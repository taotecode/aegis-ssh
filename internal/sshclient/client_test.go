package sshclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/sshclient"
	"github.com/taotecode/aegis-ssh/internal/testssh"
	"github.com/taotecode/aegis-ssh/internal/vault"
	"golang.org/x/crypto/ssh"
)

var _ int64 = sshclient.Limits{}.MaxOutputBytes

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

func TestExecutePrivateKeyAuthenticatedCommand(t *testing.T) {
	for _, test := range []struct {
		name       string
		passphrase []byte
	}{
		{name: "unencrypted"},
		{name: "encrypted", passphrase: []byte("synthetic-key-passphrase")},
	} {
		t.Run(test.name, func(t *testing.T) {
			privateKey, publicKey := privateKeyFixture(t, test.passphrase)
			server := testssh.StartWithPublicKey(t, "deploy", publicKey)
			secret := vault.ServerSecret{
				Host: server.Host, Port: server.Port, User: "deploy",
				AuthMethod: vault.AuthMethodPrivateKey, PrivateKey: privateKey,
				PrivateKeyPassphrase: append([]byte(nil), test.passphrase...),
				HostFingerprint:      server.Fingerprint,
			}

			result, err := sshclient.New().Execute(context.Background(), secret, "printf ok", testLimits())
			if err != nil {
				t.Fatal(err)
			}
			if result.Stdout != "ok" || result.Stderr != "" || result.ExitCode != 0 || result.Truncated {
				t.Fatalf("Execute() = %#v", result)
			}
		})
	}
}

func TestExecuteRejectsInvalidOrUnauthorizedPrivateKey(t *testing.T) {
	correctKey, correctPublicKey := privateKeyFixture(t, []byte("correct-passphrase"))
	server := testssh.StartWithPublicKey(t, "deploy", correctPublicKey)

	wrongPassphrase := vault.ServerSecret{
		Host: server.Host, Port: server.Port, User: "deploy", AuthMethod: vault.AuthMethodPrivateKey,
		PrivateKey: correctKey, PrivateKeyPassphrase: []byte("wrong-passphrase"), HostFingerprint: server.Fingerprint,
	}
	_, err := sshclient.New().Execute(context.Background(), wrongPassphrase, "printf ok", testLimits())
	assertSanitizedError(t, err, model.ErrAuthentication, wrongPassphrase)

	unauthorizedKey, _ := privateKeyFixture(t, nil)
	unauthorized := vault.ServerSecret{
		Host: server.Host, Port: server.Port, User: "deploy", AuthMethod: vault.AuthMethodPrivateKey,
		PrivateKey: unauthorizedKey, HostFingerprint: server.Fingerprint,
	}
	_, err = sshclient.New().Execute(context.Background(), unauthorized, "printf ok", testLimits())
	assertSanitizedError(t, err, model.ErrAuthentication, unauthorized)
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

func TestExecuteCancellationAfterHandlerStarts(t *testing.T) {
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

func TestServerCloseCancelsAndWaitsForHandler(t *testing.T) {
	server := testssh.Start(t, "root", "synthetic-password")
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()
	handlerReturned := make(chan struct{})
	server.Handle("wait-for-cleanup", func(ctx context.Context) testssh.Output {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		close(handlerReturned)
		return testssh.Output{}
	})

	executeResult := make(chan error, 1)
	go func() {
		_, err := sshclient.New().Execute(context.Background(), server.Secret("root", "synthetic-password"), "wait-for-cleanup", testLimits())
		executeResult <- err
	}()
	waitForSignal(t, started, "handler start")

	closeResult := make(chan struct{})
	go func() {
		server.Close()
		close(closeResult)
	}()
	waitForSignal(t, canceled, "handler cancellation")
	select {
	case <-closeResult:
		t.Fatal("Server.Close() returned before handler exited")
	default:
	}
	releaseHandler()
	waitForSignal(t, handlerReturned, "handler return")
	waitForSignal(t, closeResult, "server close")
	select {
	case err := <-executeResult:
		if !errors.Is(err, model.ErrConnection) {
			t.Fatalf("Execute() error = %v, want ErrConnection", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Execute() to return")
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
		{name: "unknown auth method", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.AuthMethod = "agent" }), command: "true", limits: validLimits},
		{name: "password with private key", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.PrivateKey = []byte("key") }), command: "true", limits: validLimits},
		{name: "private key missing", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.AuthMethod = vault.AuthMethodPrivateKey; s.Password = nil }), command: "true", limits: validLimits},
		{name: "private key with password", secret: mutateSecret(validSecret, func(s *vault.ServerSecret) { s.AuthMethod = vault.AuthMethodPrivateKey; s.PrivateKey = []byte("key") }), command: "true", limits: validLimits},
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

func TestExecuteAcceptsDefensiveLimitBoundaries(t *testing.T) {
	secret := refusedConnectionSecret(t)
	const (
		maxOutputBytes  int64 = 4 << 20
		maxCommandBytes       = 128 << 10
	)
	tests := []struct {
		name    string
		command string
		limits  sshclient.Limits
	}{
		{name: "timeout", command: "true", limits: sshclient.Limits{Timeout: 30 * time.Minute, MaxOutputBytes: 1}},
		{name: "output", command: "true", limits: sshclient.Limits{Timeout: time.Second, MaxOutputBytes: maxOutputBytes}},
		{name: "command", command: strings.Repeat("x", maxCommandBytes), limits: testLimits()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := sshclient.New().Execute(context.Background(), secret, test.command, test.limits)
			if !errors.Is(err, model.ErrConnection) {
				t.Fatalf("Execute() error = %v, want accepted validation followed by ErrConnection", err)
			}
		})
	}
}

func TestExecuteRejectsLimitsAboveDefensiveBounds(t *testing.T) {
	validSecret := vault.ServerSecret{
		Host: "127.0.0.1", Port: 22, User: "root", Password: []byte("password"), HostFingerprint: "SHA256:fingerprint",
	}
	tests := []struct {
		name    string
		command string
		limits  sshclient.Limits
	}{
		{name: "timeout", command: "true", limits: sshclient.Limits{Timeout: 30*time.Minute + time.Nanosecond, MaxOutputBytes: 1}},
		{name: "output", command: "true", limits: sshclient.Limits{Timeout: time.Second, MaxOutputBytes: (4 << 20) + 1}},
		{name: "command", command: strings.Repeat("x", (128<<10)+1), limits: testLimits()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := sshclient.New().Execute(context.Background(), validSecret, test.command, test.limits)
			if !errors.Is(err, model.ErrValidation) {
				t.Fatalf("Execute() error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestExecuteClassifiesAndSanitizesConnectionRefused(t *testing.T) {
	secret := refusedConnectionSecret(t)
	_, err := sshclient.New().Execute(context.Background(), secret, "synthetic-private-command", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 1024})
	assertSanitizedError(t, err, model.ErrConnection, secret)
}

func TestExecuteClassifiesAndSanitizesInvalidSSHProtocol(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Write([]byte("synthetic-garbage-protocol\r\n"))
		_ = conn.Close()
	}()
	secret := secretForAddress(t, listener.Addr().String())

	_, executeErr := sshclient.New().Execute(context.Background(), secret, "synthetic-private-command", testLimits())
	assertSanitizedError(t, executeErr, model.ErrConnection, secret)
	if strings.Contains(executeErr.Error(), "synthetic-garbage-protocol") {
		t.Fatalf("Execute() error exposed raw protocol input: %q", executeErr)
	}
	waitForSignal(t, serverDone, "invalid protocol server exit")
}

func mutateSecret(secret vault.ServerSecret, mutate func(*vault.ServerSecret)) vault.ServerSecret {
	copy := vault.CloneServerSecret(secret)
	mutate(&copy)
	return copy
}

func refusedConnectionSecret(t *testing.T) vault.ServerSecret {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return secretForAddress(t, address)
}

func secretForAddress(t *testing.T, address string) vault.ServerSecret {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return vault.ServerSecret{
		Host:            host,
		Port:            uint16(port),
		User:            "synthetic-private-user",
		Password:        []byte("synthetic-private-password"),
		HostFingerprint: "SHA256:synthetic-private-fingerprint",
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
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
		string(secret.PrivateKey),
		string(secret.PrivateKeyPassphrase),
		secret.HostFingerprint,
		net.JoinHostPort(secret.Host, strconv.FormatUint(uint64(secret.Port), 10)),
	} {
		if sensitive != "" && strings.Contains(message, sensitive) {
			t.Fatalf("error %q contains sensitive value %q", message, sensitive)
		}
	}
}

func privateKeyFixture(t *testing.T, passphrase []byte) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(privateKey, "aegis-ssh-test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "aegis-ssh-test", passphrase)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}
