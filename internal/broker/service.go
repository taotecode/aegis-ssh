package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chenjw/aegis-ssh/internal/approval"
	"github.com/chenjw/aegis-ssh/internal/audit"
	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/policy"
	"github.com/chenjw/aegis-ssh/internal/sshclient"
	"github.com/chenjw/aegis-ssh/internal/vault"
)

const (
	maxCommandBytes = 128 << 10
	maxTimeout      = 30 * time.Minute
	maxOutputBytes  = int64(4 << 20)
)

var ErrInvalidServiceOptions = errors.New("invalid broker service options")

type SecretLookup interface {
	Lookup(alias string) (vault.ServerSecret, bool)
}

type CommandAnalyzer interface {
	Analyze(command string) (policy.Analysis, error)
}

type ApprovalStore interface {
	Create(serverAlias string, command []byte, categories []policy.Category) (approval.Approval, error)
	Consume(id, code string) (approval.Approval, error)
}

type SSHExecutor interface {
	Execute(context.Context, vault.ServerSecret, string, sshclient.Limits) (sshclient.Result, error)
}

type OutputRedactor interface {
	Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult
}

type Auditor interface {
	Write(audit.Event) error
}

type ServiceOptions struct {
	Secrets            SecretLookup
	Analyzer           CommandAnalyzer
	Approvals          ApprovalStore
	Executor           SSHExecutor
	Redactor           OutputRedactor
	Auditor            Auditor
	Now                func() time.Time
	AllowAuditFailOpen bool
	DefaultTimeout     time.Duration
	DefaultMaxOutput   int64
	Servers            []model.ServerSummary
	VaultLocked        bool
	Version            string
	PolicyVersion      string
}

type Service struct {
	secrets          SecretLookup
	analyzer         CommandAnalyzer
	approvals        ApprovalStore
	executor         SSHExecutor
	redactor         OutputRedactor
	auditor          Auditor
	now              func() time.Time
	auditFailClosed  bool
	defaultTimeout   time.Duration
	defaultMaxOutput int64
	servers          []model.ServerSummary
	vaultLocked      bool
	version          string
	policyVersion    string
	requestSequence  atomic.Uint64
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Secrets == nil || options.Analyzer == nil || options.Approvals == nil ||
		options.Executor == nil || options.Redactor == nil || options.Auditor == nil || options.Now == nil ||
		options.DefaultTimeout <= 0 || options.DefaultTimeout > maxTimeout ||
		options.DefaultMaxOutput <= 0 || options.DefaultMaxOutput > maxOutputBytes {
		return nil, ErrInvalidServiceOptions
	}
	return &Service{
		secrets:          options.Secrets,
		analyzer:         options.Analyzer,
		approvals:        options.Approvals,
		executor:         options.Executor,
		redactor:         options.Redactor,
		auditor:          options.Auditor,
		now:              options.Now,
		auditFailClosed:  !options.AllowAuditFailOpen,
		defaultTimeout:   options.DefaultTimeout,
		defaultMaxOutput: options.DefaultMaxOutput,
		servers:          cloneServers(options.Servers),
		vaultLocked:      options.VaultLocked,
		version:          options.Version,
		policyVersion:    options.PolicyVersion,
	}, nil
}

func (service *Service) Status(ctx context.Context) (model.BrokerStatus, error) {
	if service == nil || ctx == nil {
		return model.BrokerStatus{}, model.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return model.BrokerStatus{}, model.ErrTimeout
	}
	return model.BrokerStatus{
		DaemonReachable: true,
		VaultLocked:     service.vaultLocked,
		Version:         service.version,
		PolicyVersion:   service.policyVersion,
		AuditFailClosed: service.auditFailClosed,
	}, nil
}

func (service *Service) ListServers(ctx context.Context) ([]model.ServerSummary, error) {
	if service == nil || ctx == nil {
		return nil, model.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, model.ErrTimeout
	}
	return cloneServers(service.servers), nil
}

func (service *Service) Execute(ctx context.Context, request model.ExecuteRequest) model.ExecuteResult {
	if service == nil || !validExecuteRequest(ctx, request) {
		return failed(model.ErrValidation)
	}
	secret, ok := service.secrets.Lookup(request.ServerAlias)
	if !ok {
		return failed(model.ErrValidation)
	}
	defer vault.Zero(secret.Password)

	analysis, err := service.analyzer.Analyze(request.Command)
	if err != nil {
		return failed(model.ErrValidation)
	}
	if len(analysis.Categories) != 0 {
		created, err := service.approvals.Create(request.ServerAlias, []byte(request.Command), analysis.Categories)
		if err != nil {
			return failed(model.ErrApproval)
		}
		event := service.auditEvent(request.ServerAlias, request.Command, analysis.Categories)
		event.Decision = string(model.StatusRequiresApproval)
		event.ApprovalState = "created"
		event.RequireSync = true
		if err := service.auditor.Write(event); err != nil {
			return failed(model.ErrAudit)
		}
		return model.ExecuteResult{
			Status: model.StatusRequiresApproval,
			Approval: &model.ApprovalInfo{
				ID:        created.ID,
				Code:      created.Code,
				Message:   fmt.Sprintf("检测到风险类别：%s。请由用户确认后回复：允许 %s", categoryList(analysis.Categories), created.Code),
				ExpiresAt: created.ExpiresAt.UTC().Format(time.RFC3339),
			},
		}
	}

	return service.executeRemote(ctx, request.ServerAlias, request.Command, requestLimits(request, service), nil, false, secret)
}

func (service *Service) ExecuteApproved(ctx context.Context, request model.ApprovedRequest) model.ExecuteResult {
	if service == nil || ctx == nil || ctx.Err() != nil || request.ApprovalID == "" || request.ApprovalCode == "" {
		return failed(model.ErrApproval)
	}
	approved, err := service.approvals.Consume(request.ApprovalID, request.ApprovalCode)
	if err != nil {
		return failed(model.ErrApproval)
	}
	secret, ok := service.secrets.Lookup(approved.ServerAlias)
	if !ok {
		return failed(model.ErrValidation)
	}
	defer vault.Zero(secret.Password)
	return service.executeRemote(
		ctx,
		approved.ServerAlias,
		string(approved.Command),
		sshclient.Limits{Timeout: service.defaultTimeout, MaxOutputBytes: service.defaultMaxOutput},
		approved.Categories,
		true,
		secret,
	)
}

func (service *Service) executeRemote(
	ctx context.Context,
	alias string,
	command string,
	limits sshclient.Limits,
	categories []policy.Category,
	approved bool,
	secret vault.ServerSecret,
) model.ExecuteResult {
	failClosed := service.auditFailClosed || approved
	preflight := service.auditEvent(alias, command, categories)
	preflight.Decision = "execute_preflight"
	if approved {
		preflight.ApprovalState = "consumed"
		preflight.RequireSync = true
	}
	auditFailed := false
	if err := service.auditor.Write(preflight); err != nil {
		if failClosed {
			return failed(model.ErrAudit)
		}
		auditFailed = true
	}

	started := service.now()
	executed, executeErr := service.executor.Execute(ctx, secret, command, limits)
	duration := service.now().Sub(started)
	allowed := approvedRedactions(categories)
	stdout := service.redactor.Redact(executed.Stdout, allowed, int(limits.MaxOutputBytes))
	stderr := service.redactor.Redact(executed.Stderr, allowed, int(limits.MaxOutputBytes))
	counts := mergeRedactionCounts(stdout.Counts, stderr.Counts)
	truncated := executed.Truncated || stdout.Truncated || stderr.Truncated

	result := model.ExecuteResult{
		Status:     model.StatusCompleted,
		Stdout:     stdout.Text,
		Stderr:     stderr.Text,
		ExitCode:   executed.ExitCode,
		DurationMS: duration.Milliseconds(),
		Truncated:  truncated,
		Redactions: model.RedactionSummary{Applied: len(counts) != 0, Counts: counts},
	}
	if executeErr != nil {
		result.Status = model.StatusFailed
		result.Error = publicError(executeErr)
	}

	finalEvent := service.auditEvent(alias, command, categories)
	finalEvent.Decision = string(result.Status)
	if approved {
		finalEvent.ApprovalState = "executed"
		finalEvent.RequireSync = true
	}
	finalEvent.DurationMS = result.DurationMS
	finalEvent.ExitCode = result.ExitCode
	finalEvent.TimedOut = result.Error != nil && result.Error.Code() == model.CodeTimeout
	finalEvent.Truncated = result.Truncated
	finalEvent.Redactions = cloneCounts(result.Redactions.Counts)
	if err := service.auditor.Write(finalEvent); err != nil {
		if failClosed {
			return failed(model.ErrAudit)
		}
		auditFailed = true
	}
	if auditFailed {
		result.Warnings = []*model.CodedError{model.ErrAudit}
	}
	return result
}

func validExecuteRequest(ctx context.Context, request model.ExecuteRequest) bool {
	return ctx != nil && ctx.Err() == nil && strings.TrimSpace(request.ServerAlias) != "" &&
		strings.TrimSpace(request.Command) != "" && len(request.Command) <= maxCommandBytes &&
		request.TimeoutSeconds >= 0 && request.TimeoutSeconds <= int(maxTimeout/time.Second) &&
		request.MaxOutputBytes >= 0 && request.MaxOutputBytes <= maxOutputBytes
}

func requestLimits(request model.ExecuteRequest, service *Service) sshclient.Limits {
	timeout := service.defaultTimeout
	if request.TimeoutSeconds != 0 {
		timeout = time.Duration(request.TimeoutSeconds) * time.Second
	}
	maxOutput := service.defaultMaxOutput
	if request.MaxOutputBytes != 0 {
		maxOutput = request.MaxOutputBytes
	}
	return sshclient.Limits{Timeout: timeout, MaxOutputBytes: maxOutput}
}

func (service *Service) auditEvent(alias, command string, categories []policy.Category) audit.Event {
	now := service.now()
	sequence := service.requestSequence.Add(1)
	return audit.Event{
		Timestamp:      now,
		RequestID:      fmt.Sprintf("broker-%d-%d", now.UnixNano(), sequence),
		Interface:      "unix",
		ServerAlias:    alias,
		Command:        command,
		RiskCategories: append([]policy.Category(nil), categories...),
	}
}

func approvedRedactions(categories []policy.Category) map[policy.RedactionCategory]bool {
	allowed := make(map[policy.RedactionCategory]bool)
	for _, category := range categories {
		for _, redaction := range categoryRedactions[category] {
			allowed[redaction] = true
		}
	}
	return allowed
}

var categoryRedactions = map[policy.Category][]policy.RedactionCategory{
	policy.SSHSecret:          {policy.PrivateKeyBlock},
	policy.CloudCredential:    {policy.BearerToken, policy.AccessKey, policy.URLCredential, policy.CredentialAssignment},
	policy.ProcessEnvironment: {policy.BearerToken, policy.AccessKey, policy.URLCredential, policy.CredentialAssignment},
	policy.DatabaseCredential: {policy.URLCredential, policy.CredentialAssignment},
	policy.KubernetesSecret:   {policy.BearerToken, policy.CredentialAssignment},
	policy.PrivateKey:         {policy.PrivateKeyBlock},
	policy.NetworkIdentity:    {policy.IPAddress},
}

func mergeRedactionCounts(left, right map[policy.RedactionCategory]int) map[string]int {
	counts := make(map[string]int, len(left)+len(right))
	for category, count := range left {
		counts[string(category)] += count
	}
	for category, count := range right {
		counts[string(category)] += count
	}
	return counts
}

func cloneCounts(counts map[string]int) map[string]int {
	cloned := make(map[string]int, len(counts))
	for category, count := range counts {
		cloned[category] = count
	}
	return cloned
}

func cloneServers(servers []model.ServerSummary) []model.ServerSummary {
	return append([]model.ServerSummary(nil), servers...)
}

func publicError(err error) *model.CodedError {
	var coded *model.CodedError
	if errors.As(err, &coded) {
		return coded
	}
	return model.ErrConnection
}

func failed(err *model.CodedError) model.ExecuteResult {
	return model.ExecuteResult{Status: model.StatusFailed, Error: err}
}

func categoryList(categories []policy.Category) string {
	values := make([]string, len(categories))
	for index, category := range categories {
		values[index] = string(category)
	}
	return strings.Join(values, ", ")
}
