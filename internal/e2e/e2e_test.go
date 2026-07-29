package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/approval"
	"github.com/chenjw/aegis-ssh/internal/audit"
	"github.com/chenjw/aegis-ssh/internal/broker"
	"github.com/chenjw/aegis-ssh/internal/config"
	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/paths"
	"github.com/chenjw/aegis-ssh/internal/policy"
	"github.com/chenjw/aegis-ssh/internal/sshclient"
	"github.com/chenjw/aegis-ssh/internal/testssh"
	"github.com/chenjw/aegis-ssh/internal/vault"
)

type memorySecrets struct {
	servers map[string]vault.ServerSecret
}

func (secrets memorySecrets) Lookup(alias string) (vault.ServerSecret, bool) {
	secret, ok := secrets.servers[alias]
	secret.Password = append([]byte(nil), secret.Password...)
	return secret, ok
}

type outputRedactor struct{}

func (outputRedactor) Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult {
	return policy.NewRedactor(allowed).WithMaxBytes(maxBytes).RedactString(input)
}

func TestPasswordOnlyBrokerAcceptance(t *testing.T) {
	const (
		alias    = "prod"
		username = "fixture-user"
		password = "fixture-password"
	)
	sshServer := testssh.Start(t, username, password)
	var sensitiveExecutions atomic.Int32
	sshServer.Handle("show peer", func(context.Context) testssh.Output {
		return testssh.Output{Stdout: "peer 192.0.2.44\n"}
	})
	sshServer.Handle("ip route", func(context.Context) testssh.Output {
		sensitiveExecutions.Add(1)
		return testssh.Output{Stdout: "default via 192.0.2.1\n"}
	})

	parent, err := os.MkdirTemp("/tmp", "aegis-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	root := filepath.Join(parent, ".aegis-ssh")
	layout, err := paths.EnsureLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	master := []byte("fixture-master")
	defer vault.Zero(master)
	secret := sshServer.Secret(username, password)
	data := vault.Data{Servers: map[string]vault.ServerSecret{alias: secret}}
	sealed, err := vault.Seal(master, data, vault.KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.VaultFile, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	vault.Zero(sealed)
	if err := config.Save(layout.ConfigFile, config.Config{
		Version: 1, Servers: map[string]config.ServerPublic{alias: {Description: "Production"}},
	}); err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(layout.AuditDir, audit.Options{MaxBytes: 1 << 20, Backups: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now
	service, err := broker.NewService(broker.ServiceOptions{
		Secrets: memorySecrets{servers: data.Servers}, Analyzer: policy.NewAnalyzer(),
		Approvals: approval.NewStore(now, rand.Reader), Executor: sshclient.New(),
		Redactor: outputRedactor{}, Auditor: logger, Now: now,
		DefaultTimeout: 5 * time.Second, DefaultMaxOutput: 1 << 20,
		Servers: []model.ServerSummary{{Alias: alias, Description: "Production", Available: true}},
		Version: "test", PolicyVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- broker.NewServer(layout.SocketFile, service).Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("broker stop: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("broker did not stop")
		}
	})
	client := broker.NewClient(layout.SocketFile)
	waitForBroker(t, client, done)

	servers, err := client.ListServers(context.Background())
	if err != nil || len(servers) != 1 || servers[0].Alias != alias || servers[0].Description != "Production" {
		t.Fatalf("ListServers() = %+v, %v", servers, err)
	}
	assertNoSecrets(t, mustJSON(t, servers), sshServer, username, password)

	ordinary, err := client.Execute(context.Background(), model.ExecuteRequest{ServerAlias: alias, Command: "printf ok"})
	if err != nil || ordinary.Status != model.StatusCompleted || ordinary.Stdout != "ok" {
		t.Fatalf("ordinary Execute() = %+v, %v", ordinary, err)
	}
	redacted, err := client.Execute(context.Background(), model.ExecuteRequest{ServerAlias: alias, Command: "show peer"})
	if err != nil || redacted.Status != model.StatusCompleted || strings.Contains(redacted.Stdout, "192.0.2.44") || !redacted.Redactions.Applied {
		t.Fatalf("redacted Execute() = %+v, %v", redacted, err)
	}

	blocked, err := client.Execute(context.Background(), model.ExecuteRequest{ServerAlias: alias, Command: "ip route"})
	if err != nil || blocked.Status != model.StatusRequiresApproval || blocked.Approval == nil || sensitiveExecutions.Load() != 0 {
		t.Fatalf("sensitive Execute() = %+v, %v calls=%d", blocked, err, sensitiveExecutions.Load())
	}
	wrong, err := client.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: "ZZZZ",
	})
	if err != nil || wrong.Status != model.StatusFailed || !errors.Is(wrong.Error, model.ErrApproval) || sensitiveExecutions.Load() != 0 {
		t.Fatalf("wrong approval = %+v, %v calls=%d", wrong, err, sensitiveExecutions.Load())
	}
	approved, err := client.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})
	if err != nil || approved.Status != model.StatusCompleted || sensitiveExecutions.Load() != 1 {
		t.Fatalf("approved execution = %+v, %v calls=%d", approved, err, sensitiveExecutions.Load())
	}
	replay, err := client.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})
	if err != nil || replay.Status != model.StatusFailed || !errors.Is(replay.Error, model.ErrApproval) || sensitiveExecutions.Load() != 1 {
		t.Fatalf("approval replay = %+v, %v calls=%d", replay, err, sensitiveExecutions.Load())
	}

	results := bytes.Join([][]byte{mustJSON(t, ordinary), mustJSON(t, redacted), mustJSON(t, blocked), mustJSON(t, wrong), mustJSON(t, approved), mustJSON(t, replay)}, nil)
	assertNoSecrets(t, results, sshServer, username, password)
	auditData, err := os.ReadFile(filepath.Join(layout.AuditDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, auditData, sshServer, username, password)
}

func waitForBroker(t *testing.T, client *broker.Client, done <-chan error) {
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
			t.Fatalf("broker stopped during startup: %v", err)
		case <-deadline.C:
			t.Fatalf("broker unavailable: %v", err)
		case <-retry.C:
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoSecrets(t *testing.T, data []byte, server *testssh.Server, username, password string) {
	t.Helper()
	for _, forbidden := range []string{server.Host, username, password, server.Fingerprint} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("output contains connection secret %q: %s", forbidden, data)
		}
	}
}
