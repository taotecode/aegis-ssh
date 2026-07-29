package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
	lastLimits  sshclient.Limits
	result      sshclient.Result
	err         error
}

func (executor *fakeExecutor) Execute(_ context.Context, _ vault.ServerSecret, command string, limits sshclient.Limits) (sshclient.Result, error) {
	executor.calls++
	executor.lastCommand = command
	executor.lastLimits = limits
	return executor.result, executor.err
}

type fakeAudit struct {
	mu         sync.Mutex
	err        error
	calls      int
	errOnCalls map[int]error
	events     []audit.Event
}

func (auditor *fakeAudit) Write(event audit.Event) error {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	auditor.calls++
	auditor.events = append(auditor.events, event)
	if err := auditor.errOnCalls[auditor.calls]; err != nil {
		return err
	}
	return auditor.err
}

func (auditor *fakeAudit) snapshot() []audit.Event {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	return append([]audit.Event(nil), auditor.events...)
}

type memorySecrets struct {
	servers map[string]vault.ServerSecret
}

func (secrets memorySecrets) Lookup(alias string) (vault.ServerSecret, bool) {
	secret, ok := secrets.servers[alias]
	secret.Password = append([]byte(nil), secret.Password...)
	return secret, ok
}

type sharedPasswordSecrets struct {
	secret vault.ServerSecret
}

func (secrets *sharedPasswordSecrets) Lookup(string) (vault.ServerSecret, bool) {
	return secrets.secret, true
}

type passwordObservingExecutor struct {
	seen       [][]byte
	references [][]byte
}

func (executor *passwordObservingExecutor) Execute(_ context.Context, secret vault.ServerSecret, _ string, _ sshclient.Limits) (sshclient.Result, error) {
	executor.seen = append(executor.seen, append([]byte(nil), secret.Password...))
	executor.references = append(executor.references, secret.Password)
	return sshclient.Result{Stdout: "ok"}, nil
}

type realOutputRedactor struct{}

func (realOutputRedactor) Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult {
	return policy.NewRedactor(allowed).WithMaxBytes(maxBytes).RedactString(input)
}

func newTestService(executor *fakeExecutor) *Service {
	return newTestServiceWithAudit(executor, &fakeAudit{})
}

func newTestServiceWithAudit(executor *fakeExecutor, auditor *fakeAudit) *Service {
	return newTestServiceWithAuditMode(executor, auditor, false)
}

func newTestServiceWithAuditMode(executor *fakeExecutor, auditor *fakeAudit, allowAuditFailOpen bool) *Service {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	return newTestServiceWithDependencies(executor, auditor, approval.NewStore(now, rand.Reader), allowAuditFailOpen, now)
}

func newTestServiceWithDependencies(executor SSHExecutor, auditor Auditor, approvals ApprovalStore, allowAuditFailOpen bool, now func() time.Time) *Service {
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
		Analyzer:           policy.NewAnalyzer(),
		Approvals:          approvals,
		Executor:           executor,
		Redactor:           realOutputRedactor{},
		Auditor:            auditor,
		Now:                now,
		AllowAuditFailOpen: allowAuditFailOpen,
		DefaultTimeout:     30 * time.Second,
		DefaultMaxOutput:   1 << 20,
	})
	if err != nil {
		panic(err)
	}
	return service
}

type observingApprovalStore struct {
	inner           *approval.Store
	revokeErr       error
	createdCommand  []byte
	consumedCommand []byte
}

func (store *observingApprovalStore) Create(alias string, command []byte, categories []policy.Category, limits approval.ExecutionLimits) (approval.Approval, error) {
	created, err := store.inner.Create(alias, command, categories, limits)
	store.createdCommand = created.Command
	return created, err
}

func (store *observingApprovalStore) Consume(id, code string) (approval.Approval, error) {
	consumed, err := store.inner.Consume(id, code)
	store.consumedCommand = consumed.Command
	return consumed, err
}

func (store *observingApprovalStore) Revoke(id string) error {
	if store.revokeErr != nil {
		return store.revokeErr
	}
	return store.inner.Revoke(id)
}

type statelessExecutor struct{}

func (statelessExecutor) Execute(context.Context, vault.ServerSecret, string, sshclient.Limits) (sshclient.Result, error) {
	return sshclient.Result{Stdout: "ok"}, nil
}

func TestServiceExecuteOrdinaryCommandFiltersBeforeReturn(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "peer 192.0.2.1"}}
	service := newTestService(executor)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusCompleted || strings.Contains(got.Stdout, "192.0.2.1") {
		t.Fatal(got)
	}
}

func TestServiceOwnsAndZerosOnlyItsPasswordCopy(t *testing.T) {
	password := []byte("shared-password")
	secrets := &sharedPasswordSecrets{secret: vault.ServerSecret{
		Host: "host", Port: 22, User: "root", Password: password, HostFingerprint: "SHA256:test",
	}}
	executor := &passwordObservingExecutor{}
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	service, err := NewService(ServiceOptions{
		Secrets: secrets, Analyzer: policy.NewAnalyzer(), Approvals: approval.NewStore(now, rand.Reader),
		Executor: executor, Redactor: realOutputRedactor{}, Auditor: &fakeAudit{}, Now: now,
		DefaultTimeout: 30 * time.Second, DefaultMaxOutput: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		result := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
		if result.Status != model.StatusCompleted {
			t.Fatal(result)
		}
	}

	if string(password) != "shared-password" || string(secrets.secret.Password) != "shared-password" {
		t.Fatalf("lookup-owned password was modified: input=%q stored=%q", password, secrets.secret.Password)
	}
	if len(executor.seen) != 2 || string(executor.seen[0]) != "shared-password" || string(executor.seen[1]) != "shared-password" {
		t.Fatalf("executor observations = %q", executor.seen)
	}
	for index, reference := range executor.references {
		if !bytes.Equal(reference, make([]byte, len(reference))) {
			t.Fatalf("execution password copy %d was not zeroed: %q", index, reference)
		}
	}
}

func TestServiceExecuteSensitiveCommandCreatesApprovalWithoutSSH(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestService(executor)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})

	if got.Status != model.StatusRequiresApproval || executor.calls != 0 || got.Approval == nil {
		t.Fatal(got)
	}
	wantConfirmation := "允许 " + got.Approval.Code
	if !strings.Contains(got.Approval.Message, wantConfirmation) ||
		!strings.Contains(got.Approval.Message, string(policy.NetworkIdentity)) {
		t.Fatalf("approval message = %q, want confirmation %q and risk category", got.Approval.Message, wantConfirmation)
	}
	for _, sensitive := range []string{"secret-host", "root", "password-value", "SHA256:fixture", "ip route"} {
		if strings.Contains(got.Approval.Message, sensitive) {
			t.Fatalf("approval message leaked %q: %q", sensitive, got.Approval.Message)
		}
	}
}

func TestServiceExecuteApprovedUsesStoredCommandAndExplicitLimits(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "route 192.0.2.1"}}
	service := newTestService(executor)
	blocked := service.Execute(context.Background(), model.ExecuteRequest{
		ServerAlias: "prod", Command: "ip route", TimeoutSeconds: 1, MaxOutputBytes: 4 << 10,
	})

	got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})

	wantLimits := sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 4 << 10}
	if got.Status != model.StatusCompleted || executor.calls != 1 || executor.lastCommand != "ip route" || executor.lastLimits != wantLimits {
		t.Fatalf("result=%+v calls=%d command=%q limits=%+v", got, executor.calls, executor.lastCommand, executor.lastLimits)
	}
}

func TestServiceExecuteApprovedUsesStoredNormalizedDefaultLimits(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestService(executor)
	blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
	got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})
	wantLimits := sshclient.Limits{Timeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	if got.Status != model.StatusCompleted || executor.lastLimits != wantLimits {
		t.Fatalf("result=%+v limits=%+v, want %+v", got, executor.lastLimits, wantLimits)
	}
}

func TestServiceZerosConsumedApprovalCommandOnEveryReturn(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }

	t.Run("successful execution", func(t *testing.T) {
		store := &observingApprovalStore{inner: approval.NewStore(now, rand.Reader)}
		service := newTestServiceWithDependencies(&fakeExecutor{}, &fakeAudit{}, store, false, now)
		blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
		got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
			ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
		})
		if got.Status != model.StatusCompleted {
			t.Fatal(got)
		}
		if !bytes.Equal(store.consumedCommand, make([]byte, len(store.consumedCommand))) {
			t.Fatalf("consumed command was not zeroed: %q", store.consumedCommand)
		}
	})

	t.Run("alias lookup failure", func(t *testing.T) {
		store := &observingApprovalStore{inner: approval.NewStore(now, rand.Reader)}
		created, err := store.inner.Create(
			"missing", []byte("ip route"), []policy.Category{policy.NetworkIdentity},
			approval.ExecutionLimits{Timeout: time.Second, MaxOutputBytes: 4 << 10},
		)
		if err != nil {
			t.Fatal(err)
		}
		service := newTestServiceWithDependencies(&fakeExecutor{}, &fakeAudit{}, store, false, now)
		got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
			ApprovalID: created.ID, ApprovalCode: created.Code,
		})
		if got.Status != model.StatusFailed || !errors.Is(got.Error, model.ErrValidation) {
			t.Fatal(got)
		}
		if !bytes.Equal(store.consumedCommand, make([]byte, len(store.consumedCommand))) {
			t.Fatalf("consumed command after lookup failure was not zeroed: %q", store.consumedCommand)
		}
	})
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
	service := newTestServiceWithAuditMode(executor, &fakeAudit{err: errors.New("disk full")}, true)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusCompleted || got.Stdout != "ok" || executor.calls != 1 || got.Error != nil {
		t.Fatalf("result=%+v calls=%d", got, executor.calls)
	}
	assertOnlyAuditWarning(t, got)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("disk full")) {
		t.Fatalf("result leaked audit error: %s", raw)
	}
}

func TestServiceExplicitAuditFailOpenSurfacesFinalAuditFailure(t *testing.T) {
	executor := &fakeExecutor{result: sshclient.Result{Stdout: "ok", Stderr: "warning", ExitCode: 7, Truncated: true}}
	auditor := &fakeAudit{errOnCalls: map[int]error{2: errors.New("final audit contains secret-host")}}
	service := newTestServiceWithAuditMode(executor, auditor, true)

	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if got.Status != model.StatusCompleted || got.Stdout != "ok" || got.Stderr != "warning" ||
		got.ExitCode != 7 || !got.Truncated || got.Error != nil ||
		executor.calls != 1 || auditor.calls != 2 {
		t.Fatalf("result=%+v executor_calls=%d audit_calls=%d", got, executor.calls, auditor.calls)
	}
	assertOnlyAuditWarning(t, got)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("final audit")) || bytes.Contains(raw, []byte("secret-host")) {
		t.Fatalf("result leaked audit error: %s", raw)
	}
}

func TestServiceAuditWarningsDoNotReplaceExecutionErrors(t *testing.T) {
	executionErrors := []struct {
		name string
		err  *model.CodedError
	}{
		{name: "authentication", err: model.ErrAuthentication},
		{name: "timeout", err: model.ErrTimeout},
	}
	auditFailures := []struct {
		name    string
		auditor func() *fakeAudit
	}{
		{
			name: "preflight",
			auditor: func() *fakeAudit {
				return &fakeAudit{errOnCalls: map[int]error{1: errors.New("preflight secret-host")}}
			},
		},
		{
			name: "final",
			auditor: func() *fakeAudit {
				return &fakeAudit{errOnCalls: map[int]error{2: errors.New("final password-value")}}
			},
		},
		{
			name: "both",
			auditor: func() *fakeAudit {
				return &fakeAudit{err: errors.New("both SHA256:fixture")}
			},
		},
	}
	for _, executionFailure := range executionErrors {
		for _, auditFailure := range auditFailures {
			t.Run(executionFailure.name+"/"+auditFailure.name, func(t *testing.T) {
				executor := &fakeExecutor{
					result: sshclient.Result{Stdout: "partial", Stderr: "remote failure", ExitCode: 255, Truncated: true},
					err:    executionFailure.err,
				}
				auditor := auditFailure.auditor()
				service := newTestServiceWithAuditMode(executor, auditor, true)

				got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

				if got.Status != model.StatusFailed || got.Error == nil || got.Error.Code() != executionFailure.err.Code() ||
					got.Stdout != "partial" || got.Stderr != "remote failure" || got.ExitCode != 255 || !got.Truncated ||
					executor.calls != 1 || executor.lastCommand != "uptime" || auditor.calls != 2 {
					t.Fatalf("result=%+v executor=%+v audit_calls=%d", got, executor, auditor.calls)
				}
				assertOnlyAuditWarning(t, got)
				raw, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"preflight secret-host", "final password-value", "both SHA256:fixture"} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Fatalf("result leaked audit error %q: %s", secret, raw)
					}
				}
			})
		}
	}
}

func assertOnlyAuditWarning(t *testing.T, result model.ExecuteResult) {
	t.Helper()
	if len(result.Warnings) != 1 || result.Warnings[0] == nil || result.Warnings[0].Code() != model.CodeAudit {
		t.Fatalf("warnings = %+v, want one audit warning", result.Warnings)
	}
}

func TestServiceAuditEventsReuseOneOperationCorrelationID(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) {
		auditor := &fakeAudit{}
		service := newTestServiceWithAudit(&fakeExecutor{}, auditor)
		got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
		if got.Status != model.StatusCompleted {
			t.Fatal(got)
		}
		events := auditor.snapshot()
		if len(events) != 2 || events[0].RequestID == "" || events[0].RequestID != events[1].RequestID {
			t.Fatalf("ordinary audit correlation = %+v", events)
		}
	})

	t.Run("approval lifecycle", func(t *testing.T) {
		auditor := &fakeAudit{}
		service := newTestServiceWithAudit(&fakeExecutor{}, auditor)
		blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
		got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
			ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
		})
		if got.Status != model.StatusCompleted {
			t.Fatal(got)
		}
		events := auditor.snapshot()
		wantID := "approval-" + blocked.Approval.ID
		if len(events) != 3 {
			t.Fatalf("approval audit events = %+v", events)
		}
		for _, event := range events {
			if event.RequestID != wantID {
				t.Fatalf("approval event ID = %q, want %q", event.RequestID, wantID)
			}
		}
	})
}

func TestServiceConcurrentIdenticalCommandsUseUniqueCorrelationIDs(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	auditor := &fakeAudit{}
	service := newTestServiceWithDependencies(statelessExecutor{}, auditor, approval.NewStore(now, rand.Reader), false, now)
	const operations = 32
	var wait sync.WaitGroup
	results := make(chan model.ExecuteResult, operations)
	for range operations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
		}()
	}
	wait.Wait()
	close(results)
	for result := range results {
		if result.Status != model.StatusCompleted {
			t.Fatal(result)
		}
	}
	counts := make(map[string]int)
	for _, event := range auditor.snapshot() {
		if strings.Contains(event.RequestID, "uptime") || strings.Contains(event.RequestID, "secret-host") {
			t.Fatalf("request ID contains sensitive input: %q", event.RequestID)
		}
		counts[event.RequestID]++
	}
	if len(counts) != operations {
		t.Fatalf("unique correlation IDs = %d, want %d: %+v", len(counts), operations, counts)
	}
	for requestID, count := range counts {
		if requestID == "" || count != 2 {
			t.Fatalf("correlation %q has %d events, want 2", requestID, count)
		}
	}
}

func TestServiceFinalAuditFailurePreservesRemoteOutcome(t *testing.T) {
	outcomes := []struct {
		name       string
		executeErr *model.CodedError
		wantStatus model.Status
	}{
		{name: "completed", wantStatus: model.StatusCompleted},
		{name: "authentication", executeErr: model.ErrAuthentication, wantStatus: model.StatusFailed},
		{name: "timeout", executeErr: model.ErrTimeout, wantStatus: model.StatusFailed},
	}
	for _, approved := range []bool{false, true} {
		mode := "ordinary"
		if approved {
			mode = "approved"
		}
		for _, outcome := range outcomes {
			t.Run(mode+"/"+outcome.name, func(t *testing.T) {
				var executeErr error
				if outcome.executeErr != nil {
					executeErr = outcome.executeErr
				}
				executor := &fakeExecutor{
					result: sshclient.Result{Stdout: "remote-result", Stderr: "remote-stderr", ExitCode: 23, Truncated: true},
					err:    executeErr,
				}
				finalCall := 2
				if approved {
					finalCall = 3
				}
				auditor := &fakeAudit{errOnCalls: map[int]error{finalCall: errors.New("final secret-host")}}
				service := newTestServiceWithAuditMode(executor, auditor, false)
				var got model.ExecuteResult
				if approved {
					blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
					got = service.ExecuteApproved(context.Background(), model.ApprovedRequest{
						ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
					})
				} else {
					got = service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
				}
				if got.Status != outcome.wantStatus || got.Stdout != "remote-result" || got.Stderr != "remote-stderr" ||
					got.ExitCode != 23 || !got.Truncated || executor.calls != 1 {
					t.Fatalf("result=%+v calls=%d", got, executor.calls)
				}
				if outcome.executeErr == nil {
					if got.Error != nil {
						t.Fatalf("completed result error = %v", got.Error)
					}
				} else if !errors.Is(got.Error, outcome.executeErr) {
					t.Fatalf("execution error = %v, want %v", got.Error, outcome.executeErr)
				}
				assertOnlyAuditWarning(t, got)
			})
		}
	}
}

func TestServiceApprovedPreflightAuditFailureAlwaysPreventsSSH(t *testing.T) {
	executor := &fakeExecutor{}
	auditor := &fakeAudit{errOnCalls: map[int]error{2: errors.New("preflight password-value")}}
	service := newTestServiceWithAuditMode(executor, auditor, true)
	blocked := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
	got := service.ExecuteApproved(context.Background(), model.ApprovedRequest{
		ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
	})
	if got.Status != model.StatusFailed || !errors.Is(got.Error, model.ErrAudit) || executor.calls != 0 {
		t.Fatalf("result=%+v calls=%d", got, executor.calls)
	}
}

func TestServiceRevokesApprovalWhenCreatedAuditFails(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	store := approval.NewStore(now, rand.Reader)
	auditor := &fakeAudit{err: errors.New("disk full")}
	service := newTestServiceWithDependencies(&fakeExecutor{}, auditor, store, false, now)
	for index := 0; index < 300; index++ {
		got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
		if got.Status != model.StatusFailed || !errors.Is(got.Error, model.ErrAudit) {
			t.Fatalf("failed creation %d = %+v", index, got)
		}
	}
	auditor.mu.Lock()
	auditor.err = nil
	auditor.mu.Unlock()
	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
	if got.Status != model.StatusRequiresApproval || got.Approval == nil {
		t.Fatalf("creation after audit recovery = %+v", got)
	}
}

func TestServiceCreatedAuditAndRevokeFailuresExposeOnlyAuditError(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }
	store := &observingApprovalStore{
		inner: approval.NewStore(now, rand.Reader), revokeErr: errors.New("revoke password-value"),
	}
	service := newTestServiceWithDependencies(
		&fakeExecutor{}, &fakeAudit{err: errors.New("audit secret-host")}, store, false, now,
	)
	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
	if got.Status != model.StatusFailed || !errors.Is(got.Error, model.ErrAudit) {
		t.Fatal(got)
	}
	if !bytes.Equal(store.createdCommand, make([]byte, len(store.createdCommand))) {
		t.Fatalf("service-owned created command was not zeroed: %q", store.createdCommand)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("password-value")) || bytes.Contains(raw, []byte("secret-host")) {
		t.Fatalf("result leaked dependency error: %s", raw)
	}
}

func TestServiceOmittedAuditPolicyDefaultsToFailClosed(t *testing.T) {
	executor := &fakeExecutor{}
	service := newTestServiceWithAuditMode(executor, &fakeAudit{err: errors.New("disk full")}, false)

	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := service.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
	if !status.AuditFailClosed || got.Status != model.StatusFailed || got.Error == nil || got.Error.Code() != model.CodeAudit || executor.calls != 0 {
		t.Fatalf("status=%+v result=%+v calls=%d", status, got, executor.calls)
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
