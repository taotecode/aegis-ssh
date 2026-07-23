package sshclient_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/sshclient"
	"github.com/chenjw/aegis-ssh/internal/testssh"
	"github.com/chenjw/aegis-ssh/internal/vault"
)

func testLimits() sshclient.Limits {
	return sshclient.Limits{Timeout: 2 * time.Second, MaxOutputBytes: 64 << 10}
}

func TestExecutePasswordAuthenticatedCommand(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-correct-password")

	result, err := sshclient.New().Execute(context.Background(), server.Secret("root", "synthetic-correct-password"), "printf ok", testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "ok" || result.Stderr != "" || result.ExitCode != 0 || result.Truncated {
		t.Fatalf("Execute() = %#v", result)
	}
}

func TestExecuteRejectsWrongPassword(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-correct-password")
	secret := server.Secret("synthetic-user", "synthetic-wrong-password")

	_, err := sshclient.New().Execute(context.Background(), secret, "printf ok", testLimits())
	assertSanitizedError(t, err, model.ErrAuthentication, secret)
}

func TestExecuteRejectsHostKeyMismatch(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	secret := server.Secret("root", "synthetic-password")
	secret.HostFingerprint = "SHA256:synthetic-mismatched-fingerprint"

	_, err := sshclient.New().Execute(context.Background(), secret, "printf ok", testLimits())
	assertSanitizedError(t, err, model.ErrHostKey, secret)
}

func TestExecuteTimeoutCancelsRemoteHandler(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	started := make(chan struct{})
	canceled := make(chan struct{})
	server.Handle("block", func(ctx context.Context) testssh.Output {
		close(started)
		<-ctx.Done()
		close(canceled)
		return testssh.Output{}
	})

	start := time.Now()
	_, err := sshclient.New().Execute(context.Background(), server.Secret("root", "synthetic-password"), "block", sshclient.Limits{
		Timeout: 100 * time.Millisecond, MaxOutputBytes: 1024,
	})
	if !errors.Is(err, model.ErrTimeout) {
		t.Fatalf("Execute() error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Execute() returned after %v, want prompt timeout", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("remote handler did not start")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remote handler did not observe context cancellation")
	}
}

func TestExecuteTimeoutInterruptsSSHHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	secret := vault.ServerSecret{Host: host, Port: uint16(port), User: "synthetic-user", Password: []byte("synthetic-password"), HostFingerprint: "SHA256:synthetic"}

	start := time.Now()
	_, executeErr := sshclient.New().Execute(context.Background(), secret, "printf ok", sshclient.Limits{Timeout: 100 * time.Millisecond, MaxOutputBytes: 1024})
	if !errors.Is(executeErr, model.ErrTimeout) {
		t.Fatalf("Execute() error = %v, want ErrTimeout", executeErr)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("handshake timeout returned after %v", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept connection")
	}
}

func TestExecuteHonorsEarlierContextCancellation(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	started := make(chan struct{})
	canceled := make(chan struct{})
	server.Handle("wait", func(ctx context.Context) testssh.Output {
		close(started)
		<-ctx.Done()
		close(canceled)
		return testssh.Output{}
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()

	_, err := sshclient.New().Execute(ctx, server.Secret("root", "synthetic-password"), "wait", sshclient.Limits{Timeout: 5 * time.Second, MaxOutputBytes: 1024})
	if !errors.Is(err, model.ErrTimeout) {
		t.Fatalf("Execute() error = %v, want ErrTimeout", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remote handler did not observe cancellation")
	}
}

func TestExecuteBoundsCombinedOutput(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	server.Handle("large-output", func(context.Context) testssh.Output {
		return testssh.Output{Stdout: strings.Repeat("o", 4096), Stderr: strings.Repeat("e", 4096)}
	})
	const maxOutput = 777

	result, err := sshclient.New().Execute(context.Background(), server.Secret("root", "synthetic-password"), "large-output", sshclient.Limits{Timeout: 2 * time.Second, MaxOutputBytes: maxOutput})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.Stdout) + len(result.Stderr); got != maxOutput {
		t.Fatalf("combined output = %d bytes, want %d", got, maxOutput)
	}
	if !result.Truncated {
		t.Fatal("Result.Truncated = false, want true")
	}
}

func TestExecuteReturnsNonZeroExitAsResult(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	server.Handle("fail", func(context.Context) testssh.Output {
		return testssh.Output{Stdout: "before failure", Stderr: "expected failure", ExitCode: 23}
	})

	result, err := sshclient.New().Execute(context.Background(), server.Secret("root", "synthetic-password"), "fail", testLimits())
	if err != nil {
		t.Fatalf("Execute() error = %v, want normal result", err)
	}
	if result.ExitCode != 23 || result.Stdout != "before failure" || result.Stderr != "expected failure" {
		t.Fatalf("Execute() = %#v", result)
	}
}

func TestExecuteValidatesInputs(t *testing.T) {
	validSecret := vault.ServerSecret{
		Host: "127.0.0.1", Port: 22, User: "root", Password: []byte("password"), HostFingerprint: "SHA256:fingerprint",
	}
	validLimits := testLimits()
	tests := []struct {
		name    string
		secret  vault.ServerSecret
		command string
		limits  sshclient.Limits
	}{
		{name: "empty host", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.Host = "" }), command: "true", limits: validLimits},
		{name: "zero port", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.Port = 0 }), command: "true", limits: validLimits},
		{name: "empty user", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.User = "" }), command: "true", limits: validLimits},
		{name: "empty password", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.Password = nil }), command: "true", limits: validLimits},
		{name: "empty fingerprint", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.HostFingerprint = "" }), command: "true", limits: validLimits},
		{name: "empty command", secret: validSecret, command: "", limits: validLimits},
		{name: "zero timeout", secret: validSecret, command: "true", limits: sshclient.Limits{MaxOutputBytes: 1}},
		{name: "negative timeout", secret: validSecret, command: "true", limits: sshclient.Limits{Timeout: -time.Second, MaxOutputBytes: 1}},
		{name: "zero output limit", secret: validSecret, command: "true", limits: sshclient.Limits{Timeout: time.Second}},
		{name: "negative output limit", secret: validSecret, command: "true", limits: sshclient.Limits{Timeout: time.Second, MaxOutputBytes: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Execute() panicked: %v", recovered)
				}
			}()
			_, err := sshclient.New().Execute(context.Background(), test.secret, test.command, test.limits)
			if !errors.Is(err, model.ErrValidation) {
				t.Fatalf("Execute() error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestExecuteDoesNotExposeConnectionDetails(t *testing.T) {
	secret := vault.ServerSecret{
		Host:            "127.0.0.1",
		Port:            1,
		User:            "synthetic-private-user",
		Password:        []byte("synthetic-private-password"),
		HostFingerprint: "SHA256:synthetic-private-fingerprint",
	}
	_, err := sshclient.New().Execute(context.Background(), secret, "synthetic-private-command", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 1024})
	assertSanitizedError(t, err, model.ErrAuthentication, secret)
}

func mutateSecret(secret vault.ServerSecret, mutate func(*vault.ServerSecret)) vault.ServerSecret {
	copy := secret
	copy.Password = append([]byte(nil), secret.Password...)
	mutate(&copy)
	return copy
}

func assertSanitizedError(t *testing.T, err error, want error, secret vault.ServerSecret) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("Execute() error = %v, want %v", err, want)
	}
	message := err.Error()
	for _, sensitive := range []string{
		secret.Host,
		strconv.FormatUint(uint64(secret.Port), 10),
		secret.User,
		string(secret.Password),
		secret.HostFingerprint,
		net.JoinHostPort(secret.Host, strconv.FormatUint(uint64(secret.Port), 10)),
	} {
		if sensitive != "" && strings.Contains(message, sensitive) {
			t.Fatalf("error %q contains sensitive value %q", message, sensitive)
		}
	}
}
