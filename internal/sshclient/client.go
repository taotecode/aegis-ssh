package sshclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/vault"
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

type Client struct {
	connectTimeout time.Duration
	mu             sync.Mutex
	connections    map[[32]byte]cachedConnection
	generation     uint64
}

type cachedConnection struct {
	client   *ssh.Client
	lastUsed time.Time
}

const connectionIdleTimeout = 60 * time.Second

func New() *Client {
	return &Client{connections: make(map[[32]byte]cachedConnection)}
}

func NewWithConnectTimeout(timeout time.Duration) *Client {
	return &Client{connectTimeout: timeout, connections: make(map[[32]byte]cachedConnection)}
}

func (c *Client) Execute(ctx context.Context, secret vault.ServerSecret, command string, limits Limits) (Result, error) {
	if !valid(ctx, secret, command, limits) {
		return Result{}, model.ErrValidation
	}
	auth, err := authenticationMethod(secret)
	if err != nil {
		return Result{}, err
	}

	key := connectionKey(secret)
	client, err := c.getClient(ctx, secret, auth, limits.Timeout, key)
	if err != nil {
		return Result{}, err
	}
	opCtx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()

	stopContextWatch := make(chan struct{})
	var stopOnce sync.Once
	stopWatch := func() { stopOnce.Do(func() { close(stopContextWatch) }) }
	defer stopWatch()
	go func() {
		select {
		case <-opCtx.Done():
			_ = client.Close()
			c.evict(key, client)
		case <-stopContextWatch:
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		c.evict(key, client)
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
		_ = client.Close()
		c.evict(key, client)
		return result, connectionError(opCtx)
	case <-opCtx.Done():
		_ = session.Close()
		_ = client.Close()
		c.evict(key, client)
		<-runResult
		return collectResult(stdout, stderr, budget), model.ErrTimeout
	}
}

func (c *Client) getClient(ctx context.Context, secret vault.ServerSecret, auth ssh.AuthMethod, timeout time.Duration, key [32]byte) (*ssh.Client, error) {
	if c == nil {
		return nil, model.ErrValidation
	}
	now := time.Now()
	c.mu.Lock()
	generation := c.generation
	for cachedKey, item := range c.connections {
		if now.Sub(item.lastUsed) > connectionIdleTimeout {
			_ = item.client.Close()
			delete(c.connections, cachedKey)
		}
	}
	if item, ok := c.connections[key]; ok {
		item.lastUsed = now
		c.connections[key] = item
		c.mu.Unlock()
		return item.client, nil
	}
	c.mu.Unlock()
	connectTimeout := c.connectTimeout
	if connectTimeout <= 0 {
		connectTimeout = timeout
	}
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	address := net.JoinHostPort(secret.Host, strconv.FormatUint(uint64(secret.Port), 10))
	conn, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", address)
	if err != nil {
		return nil, connectionError(connectCtx)
	}
	hostKeyRejected := false
	config := &ssh.ClientConfig{User: secret.User, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(secret.HostFingerprint)) != 1 {
			hostKeyRejected = true
			return model.ErrHostKey
		}
		return nil
	}}
	sshConn, channels, requests, err := handshake(connectCtx, conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, handshakeError(connectCtx, err, hostKeyRejected)
	}
	newClient := ssh.NewClient(sshConn, channels, requests)
	c.mu.Lock()
	if generation != c.generation {
		c.mu.Unlock()
		_ = newClient.Close()
		return nil, model.ErrConnection
	}
	if item, ok := c.connections[key]; ok {
		c.mu.Unlock()
		_ = newClient.Close()
		return item.client, nil
	}
	c.connections[key] = cachedConnection{client: newClient, lastUsed: time.Now()}
	c.mu.Unlock()
	return newClient, nil
}

func (c *Client) evict(key [32]byte, client *ssh.Client) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if item, ok := c.connections[key]; ok && item.client == client {
		delete(c.connections, key)
	}
	c.mu.Unlock()
}
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	for key, item := range c.connections {
		_ = item.client.Close()
		delete(c.connections, key)
	}
}
func connectionKey(secret vault.ServerSecret) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(secret.Host))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(strconv.FormatUint(uint64(secret.Port), 10)))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(secret.User))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(secret.HostFingerprint))
	_, _ = hash.Write(secret.Password)
	_, _ = hash.Write(secret.PrivateKey)
	_, _ = hash.Write(secret.PrivateKeyPassphrase)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func valid(ctx context.Context, secret vault.ServerSecret, command string, limits Limits) bool {
	return ctx != nil &&
		strings.TrimSpace(secret.Host) != "" &&
		secret.Port != 0 &&
		strings.TrimSpace(secret.User) != "" &&
		validAuthentication(secret) &&
		strings.TrimSpace(secret.HostFingerprint) != "" &&
		command != "" &&
		len(command) <= maxCommandBytes &&
		limits.Timeout > 0 && limits.Timeout <= maxTimeout &&
		limits.MaxOutputBytes > 0 && limits.MaxOutputBytes <= maxOutputBytes
}

func validAuthentication(secret vault.ServerSecret) bool {
	switch secret.EffectiveAuthMethod() {
	case vault.AuthMethodPassword:
		return len(secret.Password) != 0 && len(secret.PrivateKey) == 0 && len(secret.PrivateKeyPassphrase) == 0
	case vault.AuthMethodPrivateKey:
		return len(secret.Password) == 0 && len(secret.PrivateKey) != 0
	default:
		return false
	}
}

func authenticationMethod(secret vault.ServerSecret) (ssh.AuthMethod, error) {
	switch secret.EffectiveAuthMethod() {
	case vault.AuthMethodPassword:
		return ssh.Password(string(secret.Password)), nil
	case vault.AuthMethodPrivateKey:
		var (
			signer ssh.Signer
			err    error
		)
		if len(secret.PrivateKeyPassphrase) == 0 {
			signer, err = ssh.ParsePrivateKey(secret.PrivateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(secret.PrivateKey, secret.PrivateKeyPassphrase)
		}
		if err != nil {
			return nil, model.ErrAuthentication
		}
		return ssh.PublicKeys(signer), nil
	default:
		return nil, model.ErrValidation
	}
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
