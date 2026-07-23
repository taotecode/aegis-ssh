package sshclient

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/vault"
	"golang.org/x/crypto/ssh"
)

type Limits struct {
	Timeout        time.Duration
	MaxOutputBytes int64
}

const (
	maxTimeout        = 30 * time.Minute
	maxOutputBytes    = int64(4 << 20)
	maxCommandBytes   = 128 << 10
	authenticationErr = "unable to authenticate"
)

type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

type Client struct{}

func New() *Client {
	return &Client{}
}

func (c *Client) Execute(ctx context.Context, secret vault.ServerSecret, command string, limits Limits) (Result, error) {
	if !valid(ctx, secret, command, limits) {
		return Result{}, model.ErrValidation
	}

	opCtx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()

	address := net.JoinHostPort(secret.Host, strconv.FormatUint(uint64(secret.Port), 10))
	conn, err := (&net.Dialer{}).DialContext(opCtx, "tcp", address)
	if err != nil {
		return Result{}, connectionError(opCtx)
	}

	hostKeyRejected := false
	config := &ssh.ClientConfig{
		User: secret.User,
		Auth: []ssh.AuthMethod{ssh.Password(string(secret.Password))},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(actual), []byte(secret.HostFingerprint)) != 1 {
				hostKeyRejected = true
				return model.ErrHostKey
			}
			return nil
		},
	}

	sshConn, channels, requests, err := handshake(opCtx, conn, address, config)
	if err != nil {
		_ = conn.Close()
		return Result{}, handshakeError(opCtx, err, hostKeyRejected)
	}
	client := ssh.NewClient(sshConn, channels, requests)
	defer client.Close()

	stopContextWatch := make(chan struct{})
	var stopOnce sync.Once
	stopWatch := func() { stopOnce.Do(func() { close(stopContextWatch) }) }
	defer stopWatch()
	go func() {
		select {
		case <-opCtx.Done():
			_ = client.Close()
		case <-stopContextWatch:
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, connectionError(opCtx)
	}
	defer session.Close()

	budget := &outputBudget{remaining: limits.MaxOutputBytes}
	stdout := &boundedWriter{budget: budget}
	stderr := &boundedWriter{budget: budget}
	session.Stdout = stdout
	session.Stderr = stderr

	runResult := make(chan error, 1)
	go func() { runResult <- session.Run(command) }()

	select {
	case err := <-runResult:
		stopWatch()
		result := collectResult(stdout, stderr, budget)
		if err == nil {
			return result, nil
		}
		var exitError *ssh.ExitError
		if errors.As(err, &exitError) {
			result.ExitCode = exitError.ExitStatus()
			return result, nil
		}
		return result, connectionError(opCtx)
	case <-opCtx.Done():
		_ = session.Close()
		_ = client.Close()
		<-runResult
		return collectResult(stdout, stderr, budget), model.ErrTimeout
	}
}

func valid(ctx context.Context, secret vault.ServerSecret, command string, limits Limits) bool {
	return ctx != nil &&
		strings.TrimSpace(secret.Host) != "" &&
		secret.Port != 0 &&
		strings.TrimSpace(secret.User) != "" &&
		len(secret.Password) != 0 &&
		strings.TrimSpace(secret.HostFingerprint) != "" &&
		command != "" &&
		len(command) <= maxCommandBytes &&
		limits.Timeout > 0 && limits.Timeout <= maxTimeout &&
		limits.MaxOutputBytes > 0 && limits.MaxOutputBytes <= maxOutputBytes
}

func handshake(ctx context.Context, conn net.Conn, address string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	close(done)
	return sshConn, channels, requests, err
}

func handshakeError(ctx context.Context, err error, hostKeyRejected bool) error {
	if ctx.Err() != nil {
		return model.ErrTimeout
	}
	if hostKeyRejected {
		return model.ErrHostKey
	}
	if strings.Contains(err.Error(), authenticationErr) {
		return model.ErrAuthentication
	}
	return model.ErrConnection
}

func connectionError(ctx context.Context) error {
	if ctx.Err() != nil {
		return model.ErrTimeout
	}
	return model.ErrConnection
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int64
	truncated bool
}

type boundedWriter struct {
	budget *outputBudget
	buffer bytes.Buffer
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()

	accepted := min(int64(len(p)), w.budget.remaining)
	if accepted > 0 {
		_, _ = w.buffer.Write(p[:int(accepted)])
		w.budget.remaining -= accepted
	}
	if accepted < int64(len(p)) {
		w.budget.truncated = true
	}
	return len(p), nil
}

func collectResult(stdout, stderr *boundedWriter, budget *outputBudget) Result {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return Result{
		Stdout:    stdout.buffer.String(),
		Stderr:    stderr.buffer.String(),
		Truncated: budget.truncated,
	}
}
