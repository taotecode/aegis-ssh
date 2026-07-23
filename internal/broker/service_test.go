package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/approval"
	"github.com/chenjw/aegis-ssh/internal/audit"
	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/policy"
	"github.com/chenjw/aegis-ssh/internal/sshclient"
	"github.com/chenjw/aegis-ssh/internal/vault"
)

type fakeExecutor struct {
	calls       int
	lastCommand string
	result      sshclient.Result
	err         error
}

func (executor *fakeExecutor) Execute(_ context.Context, _ vault.ServerSecret, command string, _ sshclient.Limits) (sshclient.Result, error) {
	executor.calls++
	executor.lastCommand = command
	return executor.result, executor.err
}

type fakeAudit struct {
	err error
}

func (auditor *fakeAudit) Write(audit.Event) error { return auditor.err }

type memorySecrets struct {
	servers map[string]vault.ServerSecret
}

func (secrets memorySecrets) Lookup(alias string) (vault.ServerSecret, bool) {
	secret, ok := secrets.servers[alias]
	secret.Password = append([]byte(nil), secret.Password...)
	return secret, ok
}

type realOutputRedactor struct{}

func (realOutputRedactor) Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult {
	return policy.NewRedactor(allowed).WithMaxBytes(maxBytes).RedactString(input)
}

func newTestService(executor *fakeExecutor) *Service {
	return newTestServiceWithAudit(executor, &fakeAudit{})
}

func newTestServiceWithAudit(executor *fakeExecutor, auditor *fakeAudit) *Service {
	return newTestServiceWithAuditMode(executor, auditor, true)
}

func newTestServiceWithAuditMode(executor *fakeExecutor, auditor *fakeAudit, auditFailClosed bool) *Service {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	service, err := NewService(ServiceOptions{
		Secrets: memorySecrets{servers: map[string]vault.ServerSecret{
			"prod": {
				Host:            "secret-host",
				Port:            22,
				User:            "root",
				Password:        []byte("password-value"),
				HostFingerprint: "SHA256:fixture",
			},
		}},
		Analyzer:         policy.NewAnalyzer(),
		Approvals:        approval.NewStore(now, rand.Reader),
		Executor:         executor,
		Redactor:         realOutputRedactor{},
		Auditor:          auditor,
		Now:              now,
		AuditFailClosed:  auditFailClosed,
		DefaultTimeout:   30 * time.Second,
		DefaultMaxOutput: 1 << 20,
	})
	if err != nil {
		panic(err)
	}
	return service
}

func TestServiceExecuteOrdinaryCommandFiltersBeforeReturn(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "peer 192.0.2.1"}}
	service := newTestService(executor)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusCompleted || strings.Contains(got.Stdout, "192.0.2.1") {
		t.Fatal(got)
	}
}

func TestServiceExecuteSensitiveCommandCreatesApprovalWithoutSSH(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestService(executor)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})

	if got.Status != model.StatusRequiresApproval || executor.calls != 0 || got.Approval == nil {
		t.Fatal(got)
	}
}

func TestServiceExecuteApprovedUsesStoredCommand(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "route 192.0.2.1"}}
	service := newTestService(executor)
	blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})

	got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})

	if got.Status != model.StatusCompleted || executor.calls != 1 || executor.lastCommand != "ip route" {
		t.Fatalf("result=%+v calls=%d command=%q", got, executor.calls, executor.lastCommand)
	}
}

func TestServiceUnknownAliasNeverRevealsVaultData(t *testing.T) {
	service := newTestService(&fakeExecutor{})

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "missing", Command: "uptime"})
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-host", "root", "password-value", "SHA256:fixture"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("result leaked %q", secret)
		}
	}
}

func TestServiceAuditFailurePreventsRemoteExecution(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestServiceWithAudit(executor, &fakeAudit{err: errors.New("disk full")})

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusFailed || got.Error == nil || got.Error.Code() != model.CodeAudit || executor.calls != 0 {
		t.Fatalf("result=%+v calls=%d", got, executor.calls)
	}
}

func TestServiceExplicitAuditFailOpenAllowsOrdinaryExecution(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "ok"}}
	service := newTestServiceWithAuditMode(executor, &fakeAudit{err: errors.New("disk full")}, false)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusCompleted || got.Stdout != "ok" || executor.calls != 1 {
		t.Fatalf("result=%+v calls=%d", got, executor.calls)
	}
}

func TestServiceRejectsOverflowingTimeoutBeforeSSH(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestService(executor)

	got := service.Execute(context.Background(), model.ExecuteRequest{
		ServerAlias: "prod", Command: "uptime", TimeoutSeconds: int(^uint(0) >> 1),
	})

	if got.Status != model.StatusFailed || got.Error == nil || got.Error.Code() != model.CodeValidation || executor.calls != 0 {
		t.Fatalf("result=%+v calls=%d", got, executor.calls)
	}
}
