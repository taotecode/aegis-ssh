package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taotecode/aegis-ssh/internal/app"
	"github.com/taotecode/aegis-ssh/internal/broker"
	"github.com/taotecode/aegis-ssh/internal/config"
	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/paths"
	"github.com/taotecode/aegis-ssh/internal/testssh"
	"github.com/taotecode/aegis-ssh/internal/vault"
	"golang.org/x/crypto/ssh"
)

type fakeProbe struct {
	fingerprint string
}

func (probe fakeProbe) Probe(context.Context, string, uint16) (string, error) {
	return probe.fingerprint, nil
}

type unavailableBroker struct{}

func (unavailableBroker) Status(context.Context) (model.BrokerStatus, error) {
	return model.BrokerStatus{}, broker.ErrUnavailable
}
func (unavailableBroker) ListServers(context.Context) ([]model.ServerSummary, error) {
	return nil, broker.ErrUnavailable
}
func (unavailableBroker) Execute(context.Context, model.ExecuteRequest) (model.ExecuteResult, error) {
	return model.ExecuteResult{}, broker.ErrUnavailable
}
func (unavailableBroker) ExecuteApproved(context.Context, model.ApprovedRequest) (model.ExecuteResult, error) {
	return model.ExecuteResult{}, broker.ErrUnavailable
}
func (unavailableBroker) Lock(context.Context) error { return broker.ErrUnavailable }

type terminalQueue struct {
	mu        sync.Mutex
	terminals []*fakeTerminal
	opened    []*fakeTerminal
}

func (queue *terminalQueue) open() (app.Terminal, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.terminals) == 0 {
		return nil, app.ErrNoTerminal
	}
	terminal := queue.terminals[0]
	queue.terminals = queue.terminals[1:]
	queue.opened = append(queue.opened, terminal)
	return terminal, nil
}

func TestSecretArgumentsAndEnvironmentAreRejected(t *testing.T) {
	application := app.New(app.Dependencies{Root: filepath.Join(t.TempDir(), ".aegis-ssh"), Stdout: ioDiscard{}, Stderr: ioDiscard{}})
	for _, args := range [][]string{
		{"server", "add", "--password", "pw"},
		{"server", "add", "--host=secret.example"},
		{"server", "edit", "prod", "--user", "root"},
		{"server", "add", "--private-key", "/secret/key"},
	} {
		if err := application.Run(context.Background(), args); !errors.Is(err, app.ErrSecretArgument) {
			t.Fatalf("Run(%q) = %v", args, err)
		}
	}
	if err := application.Run(context.Background(), []string{"exec", "prod", "--", "tool --user remote-user"}); !errors.Is(err, app.ErrDaemonUnavailable) {
		t.Fatalf("remote command option was treated as a local secret argument: %v", err)
	}
	t.Setenv("AEGIS_SSH_PASSWORD", "fixture-password")
	if err := application.Run(context.Background(), []string{"status"}); !errors.Is(err, app.ErrSecretEnvironment) {
		t.Fatalf("Run(status) with secret environment = %v", err)
	}
}

func TestServerLifecycleDoesNotExposeConnectionValues(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis-ssh")
	var stdout, stderr bytes.Buffer
	master := "master fixture"
	privateKey := privateKeyPEM(t, nil)
	queue := &terminalQueue{terminals: []*fakeTerminal{
		{secretAnswers: [][]byte{[]byte(master), []byte(master)}},
		{
			secretAnswers: [][]byte{[]byte(master), []byte("ssh-password-one")},
			lineAnswers:   []string{"prod", "Production", "secret-host-one", "2222", "root-one", "password", "TRUST"},
		},
		{
			secretAnswers: [][]byte{[]byte(master)},
			lineAnswers:   []string{"staging", "Staging", "secret-key-host", "22", "deploy", "private-key", "TRUST", "/secret/id_ed25519"},
		},
		{
			secretAnswers: [][]byte{[]byte(master), []byte("ssh-password-two")},
			lineAnswers:   []string{"Updated", "secret-host-two", "2200", "root-two", "password", "TRUST"},
		},
		{secretAnswers: [][]byte{[]byte(master)}, lineAnswers: []string{"prod"}},
	}}
	application := app.New(app.Dependencies{
		Root: root, Stdout: &stdout, Stderr: &stderr, OpenTerminal: queue.open,
		HostKeyProbe: fakeProbe{fingerprint: "SHA256:secret-fixture-fingerprint"},
		ReadPrivateKey: func(path string) ([]byte, error) {
			if path != "/secret/id_ed25519" {
				return nil, app.ErrPrivateKey
			}
			return append([]byte(nil), privateKey...), nil
		},
		TestConnection: func(context.Context, vault.ServerSecret) error { return nil },
		BrokerClient:   func(string) app.BrokerClient { return unavailableBroker{} },
	})

	commands := [][]string{
		{"init"}, {"server", "add"}, {"server", "add"}, {"server", "list"},
		{"server", "edit", "prod"}, {"server", "list"}, {"server", "remove", "prod"}, {"server", "list"},
	}
	for _, command := range commands {
		if err := application.Run(context.Background(), command); err != nil {
			t.Fatalf("Run(%q) = %v", command, err)
		}
	}
	output := stdout.String() + stderr.String()
	if !strings.Contains(output, "prod") {
		t.Fatalf("public alias missing from output: %q", output)
	}
	for _, secret := range []string{
		"secret-host-one", "secret-host-two", "secret-key-host", "root-one", "root-two", "deploy",
		"ssh-password-one", "ssh-password-two", "/secret/id_ed25519", "SHA256:secret-fixture-fingerprint", master,
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("stdout/stderr leaked %q: %q", secret, output)
		}
	}
	for _, terminal := range queue.opened {
		if !terminal.closed {
			t.Fatal("terminal was not closed")
		}
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("root permissions = %v, %v", info, err)
	}
	data, err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Load([]byte(master))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for alias, secret := range data.Servers {
			vault.ZeroServerSecret(&secret)
			delete(data.Servers, alias)
		}
	}()
	staging, ok := data.Servers["staging"]
	if !ok || len(data.Servers) != 1 || staging.EffectiveAuthMethod() != vault.AuthMethodPrivateKey || len(staging.PrivateKey) == 0 || len(staging.Password) != 0 {
		t.Fatalf("remaining multi-server key entry = method %q aliases=%d", staging.EffectiveAuthMethod(), len(data.Servers))
	}
}

func TestAddEncryptedPrivateKeyServerPromptsForPassphrase(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis-ssh")
	master := "master fixture"
	passphrase := []byte("private-key-passphrase")
	privateKey := privateKeyPEM(t, passphrase)
	queue := &terminalQueue{terminals: []*fakeTerminal{
		{secretAnswers: [][]byte{[]byte(master), []byte(master)}},
		{
			secretAnswers: [][]byte{[]byte(master), append([]byte(nil), passphrase...)},
			lineAnswers:   []string{"key-prod", "Key server", "secret-key-host", "22", "deploy", "private-key", "TRUST", "~/.ssh/id_ed25519"},
		},
	}}
	application := app.New(app.Dependencies{
		Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}, OpenTerminal: queue.open,
		HostKeyProbe:   fakeProbe{fingerprint: "SHA256:fixture"},
		ReadPrivateKey: func(string) ([]byte, error) { return append([]byte(nil), privateKey...), nil },
		TestConnection: func(context.Context, vault.ServerSecret) error { return nil },
	})
	if err := application.Run(context.Background(), []string{"init"}); err != nil {
		t.Fatal(err)
	}
	if err := application.Run(context.Background(), []string{"server", "add"}); err != nil {
		t.Fatal(err)
	}
	data, err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Load([]byte(master))
	if err != nil {
		t.Fatal(err)
	}
	secret := data.Servers["key-prod"]
	defer vault.ZeroServerSecret(&secret)
	if secret.EffectiveAuthMethod() != vault.AuthMethodPrivateKey || string(secret.PrivateKeyPassphrase) != string(passphrase) {
		t.Fatalf("stored key credential = method %q passphrase length %d", secret.EffectiveAuthMethod(), len(secret.PrivateKeyPassphrase))
	}
}

func TestAddServerConnectionFailureIsNotSaved(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis-ssh")
	master := "master fixture"
	queue := &terminalQueue{terminals: []*fakeTerminal{
		{secretAnswers: [][]byte{[]byte(master), []byte(master)}},
		{
			secretAnswers: [][]byte{[]byte(master), []byte("ssh-password")},
			lineAnswers:   []string{"prod", "Production", "secret-host", "22", "root", "password", "TRUST"},
		},
	}}
	application := app.New(app.Dependencies{
		Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}, OpenTerminal: queue.open,
		HostKeyProbe: fakeProbe{fingerprint: "SHA256:fixture"},
		TestConnection: func(context.Context, vault.ServerSecret) error {
			return errors.New("authentication failed")
		},
		BrokerClient: func(string) app.BrokerClient { return unavailableBroker{} },
	})
	if err := application.Run(context.Background(), []string{"init"}); err != nil {
		t.Fatal(err)
	}
	if err := application.Run(context.Background(), []string{"server", "add"}); !errors.Is(err, app.ErrConnectionTest) {
		t.Fatalf("server add error = %v", err)
	}
	cfg, err := config.Load(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Servers["prod"]; ok {
		t.Fatal("server was saved after its connection test failed")
	}
}

func TestRecoveryResetsMasterPasswordAndPreservesVault(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis-ssh")
	oldMaster, newMaster := "old master", "new master"
	initTerminal := &fakeTerminal{secretAnswers: [][]byte{[]byte(oldMaster), []byte(oldMaster)}}
	enableTerminal := &fakeTerminal{secretAnswers: [][]byte{[]byte(oldMaster)}}
	queue := &terminalQueue{terminals: []*fakeTerminal{initTerminal, enableTerminal}}
	application := app.New(app.Dependencies{Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}, OpenTerminal: queue.open, BrokerClient: func(string) app.BrokerClient { return unavailableBroker{} }})
	if err := application.Run(context.Background(), []string{"init"}); err != nil {
		t.Fatal(err)
	}
	data := vault.Data{Servers: map[string]vault.ServerSecret{"prod": {AuthMethod: vault.AuthMethodPassword, Password: []byte("server password")}}}
	if err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Save([]byte(oldMaster), data); err != nil {
		t.Fatal(err)
	}
	if err := application.Run(context.Background(), []string{"recovery", "enable"}); err != nil {
		t.Fatal(err)
	}
	line := enableTerminal.visible.String()
	parts := strings.Split(strings.TrimSpace(line), "\n")
	last := parts[len(parts)-1]
	_, recoveryCode, found := strings.Cut(last, "：")
	if !found {
		_, recoveryCode, found = strings.Cut(last, ":")
	}
	if !found {
		t.Fatalf("recovery output = %q", line)
	}
	recoveryCode = strings.TrimSpace(recoveryCode)
	restoreTerminal := &fakeTerminal{secretAnswers: [][]byte{[]byte(recoveryCode), []byte(newMaster), []byte(newMaster)}}
	queue.terminals = append(queue.terminals, restoreTerminal)
	if err := application.Run(context.Background(), []string{"recovery", "restore"}); err != nil {
		t.Fatal(err)
	}
	restored, err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Load([]byte(newMaster))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for alias, secret := range restored.Servers {
			vault.ZeroServerSecret(&secret)
			delete(restored.Servers, alias)
		}
		vault.Zero(restored.RecoveryKey)
	}()
	if string(restored.Servers["prod"].Password) != "server password" {
		t.Fatal("recovery did not preserve the server password")
	}
}

func TestServerPasswordRequiresMasterAndWritesOnlyToTerminal(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis-ssh")
	master := []byte("master")
	if _, err := paths.EnsureLayout(root); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(filepath.Join(root, "config.yaml"), config.Config{Version: 2, Servers: map[string]config.ServerPublic{"prod": {AuthMethod: "password"}}}); err != nil {
		t.Fatal(err)
	}
	if err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Save(master, vault.Data{Servers: map[string]vault.ServerSecret{"prod": {AuthMethod: vault.AuthMethodPassword, Password: []byte("server password")}}}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	terminal := &fakeTerminal{secretAnswers: [][]byte{append([]byte(nil), master...)}}
	application := app.New(app.Dependencies{Root: root, Stdout: &stdout, Stderr: ioDiscard{}, OpenTerminal: func() (app.Terminal, error) { return terminal, nil }})
	if err := application.Run(context.Background(), []string{"server", "password", "prod"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "server password") || !strings.Contains(terminal.visible.String(), "server password") {
		t.Fatalf("stdout=%q terminal=%q", stdout.String(), terminal.visible.String())
	}
}

func TestHelpAndUnavailableStatus(t *testing.T) {
	t.Setenv("LC_ALL", "en_US.UTF-8")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "en_US.UTF-8")
	var output bytes.Buffer
	application := app.New(app.Dependencies{
		Root: filepath.Join(t.TempDir(), ".aegis-ssh"), Stdout: &output, Stderr: ioDiscard{},
		BrokerClient: func(string) app.BrokerClient { return unavailableBroker{} },
	})
	if err := application.Run(context.Background(), []string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if err := application.Run(context.Background(), []string{"status"}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"server add", "exec <alias>", "mcp", "daemon: unavailable"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("help/status missing %q: %q", expected, text)
		}
	}
}

func TestDaemonLockAndContextCancellation(t *testing.T) {
	root := shortTestRoot(t)
	master := "daemon master fixture"
	initQueue := &terminalQueue{terminals: []*fakeTerminal{{secretAnswers: [][]byte{[]byte(master), []byte(master)}}}}
	initializer := app.New(app.Dependencies{
		Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}, OpenTerminal: initQueue.open,
	})
	if err := initializer.Run(context.Background(), []string{"init"}); err != nil {
		t.Fatal(err)
	}

	for _, stopMode := range []string{"lock", "cancel"} {
		t.Run(stopMode, func(t *testing.T) {
			daemonTerminal := &fakeTerminal{secretAnswers: [][]byte{[]byte(master)}}
			daemon := app.New(app.Dependencies{
				Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{},
				OpenTerminal: func() (app.Terminal, error) { return daemonTerminal, nil },
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- daemon.Run(ctx, []string{"daemon"}) }()

			socket := filepath.Join(root, "run", "aegis.sock")
			client := broker.NewClient(socket)
			waitForDaemon(t, client, done)
			if stopMode == "lock" {
				controller := app.New(app.Dependencies{Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}})
				if err := controller.Run(context.Background(), []string{"lock"}); err != nil {
					t.Fatalf("lock = %v", err)
				}
				status, err := client.Status(context.Background())
				if err != nil || !status.VaultLocked {
					t.Fatalf("locked daemon status = %#v, %v", status, err)
				}
				if err := controller.Run(context.Background(), []string{"stop"}); err != nil {
					t.Fatalf("stop = %v", err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("daemon stop = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("daemon did not stop")
			}
			cancel()
			if !daemonTerminal.closed {
				t.Fatal("daemon terminal was not closed after unlock")
			}
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("socket remains after daemon stop: %v", err)
			}
		})
	}
}

func TestDaemonRejectsConfigVaultAliasMismatch(t *testing.T) {
	root := shortTestRoot(t)
	master := "mismatch master fixture"
	queue := &terminalQueue{terminals: []*fakeTerminal{{secretAnswers: [][]byte{[]byte(master), []byte(master)}}}}
	application := app.New(app.Dependencies{Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{}, OpenTerminal: queue.open})
	if err := application.Run(context.Background(), []string{"init"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Servers["stale"] = config.ServerPublic{Description: "must not start"}
	if err := config.Save(filepath.Join(root, "config.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	daemonTerminal := &fakeTerminal{secretAnswers: [][]byte{[]byte(master)}}
	daemon := app.New(app.Dependencies{
		Root: root, Stdout: ioDiscard{}, Stderr: ioDiscard{},
		OpenTerminal: func() (app.Terminal, error) { return daemonTerminal, nil },
	})
	if err := daemon.Run(context.Background(), []string{"daemon"}); !errors.Is(err, app.ErrStorage) {
		t.Fatalf("daemon with mismatched aliases = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "run", "aegis.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched daemon created socket: %v", err)
	}
	data, err := (vault.Store{Path: filepath.Join(root, "vault.enc")}).Load([]byte(master))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range data.Servers {
		vault.ZeroServerSecret(&secret)
	}
}

func TestSSHHostKeyProbeCapturesFingerprintBeforeAuthentication(t *testing.T) {
	server := testssh.Start(t, "probe-user", "password-never-supplied")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fingerprint, err := (app.SSHHostKeyProbe{}).Probe(ctx, server.Host, server.Port)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != server.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, server.Fingerprint)
	}
}

func shortTestRoot(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "aegis-app-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	return filepath.Join(parent, ".aegis-ssh")
}

func waitForDaemon(t *testing.T, client *broker.Client, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	retry := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer retry.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		status, err := client.Status(ctx)
		cancel()
		if err == nil && status.DaemonReachable {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("daemon stopped during startup: %v", err)
		case <-deadline.C:
			t.Fatalf("daemon did not become reachable: %v", err)
		case <-retry.C:
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(data []byte) (int, error) { return len(data), nil }

func privateKeyPEM(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(privateKey, "aegis-ssh-app-test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "aegis-ssh-app-test", passphrase)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}
