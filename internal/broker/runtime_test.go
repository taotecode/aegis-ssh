package broker

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/taotecode/aegis-ssh/internal/approval"
	"github.com/taotecode/aegis-ssh/internal/audit"
	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/policy"
	"github.com/taotecode/aegis-ssh/internal/sshclient"
	"github.com/taotecode/aegis-ssh/internal/vault"
)

type runtimeSecrets struct {
	locked bool
	secret vault.ServerSecret
}

func (s *runtimeSecrets) Lookup(string) (vault.ServerSecret, bool) {
	if s.locked {
		return vault.ServerSecret{}, false
	}
	return vault.CloneServerSecret(s.secret), true
}

func TestServiceLockAndUnlockStatePreservesPublicServerStatus(t *testing.T) {
	secrets := &runtimeSecrets{locked: false, secret: vault.ServerSecret{Host: "hidden", Port: 22, User: "hidden", Password: []byte("secret"), HostFingerprint: "SHA256:test"}}
	service, err := NewService(ServiceOptions{Secrets: secrets, Analyzer: policy.NewAnalyzer(), Approvals: approval.NewStore(time.Now, rand.Reader), Executor: statelessRuntimeExecutor{}, Redactor: runtimeRedactor{}, Auditor: runtimeAudit{}, Now: time.Now, DefaultTimeout: time.Second, DefaultMaxOutput: 1024, Servers: []model.ServerSummary{{Alias: "prod", Available: true}}})
	if err != nil {
		t.Fatal(err)
	}
	service.SetVaultState(true, []model.ServerSummary{{Alias: "prod", Available: false}})
	status, err := service.Status(context.Background())
	if err != nil || !status.VaultLocked || status.ServerCount != 1 {
		t.Fatalf("locked status=%#v err=%v", status, err)
	}
	service.SetVaultState(false, []model.ServerSummary{{Alias: "prod", Available: true}})
	status, err = service.Status(context.Background())
	if err != nil || status.VaultLocked || status.ServerCount != 1 {
		t.Fatalf("unlocked status=%#v err=%v", status, err)
	}
}

type statelessRuntimeExecutor struct{}

func (statelessRuntimeExecutor) Execute(context.Context, vault.ServerSecret, string, sshclient.Limits) (sshclient.Result, error) {
	return sshclient.Result{Stdout: "ok"}, nil
}

type runtimeRedactor struct{}

func (runtimeRedactor) Redact(input string, _ map[policy.RedactionCategory]bool, _ int) policy.RedactionResult {
	return policy.RedactionResult{Text: input}
}

type runtimeAudit struct{}

func (runtimeAudit) Write(audit.Event) error { return nil }
