package broker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/taotecode/aegis-ssh/internal/approval"
	"github.com/taotecode/aegis-ssh/internal/audit"
	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/policy"
	"github.com/taotecode/aegis-ssh/internal/sshclient"
	"github.com/taotecode/aegis-ssh/internal/vault"
)

const (
	maxCommandBytes = 128 << 10
	maxTimeout      = 30 * time.Minute
	maxOutputBytes  = int64(4 << 20)
)

var ErrInvalidServiceOptions = errors.New("invalid broker service options")

type SecretLookup interface {
	// Lookup returns a caller-owned password buffer. The service clears it
	// after each request.
	Lookup(alias string) (vault.ServerSecret, bool)
}

type CommandAnalyzer interface {
	Analyze(command string) (policy.Analysis, error)
}

type ApprovalStore interface {
	Create(serverAlias string, command []byte, categories []policy.Category, limits approval.ExecutionLimits) (approval.Approval, error)
	Consume(id, code string) (approval.Approval, error)
	Revoke(id string) error
}

type BatchApprovalStore interface {
	CreateBatch([]string, []byte, []policy.Category, approval.ExecutionLimits) (approval.Approval, error)
	List(bool) []approval.Approval
	Decide(string, bool) error
}
type WaitingApprovalStore interface {
	Wait(context.Context, string) (approval.Approval, bool, error)
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
	RiskPolicy         string
	LogLevel           string
	BatchConcurrency   int
	NotifyApproval     func()
}

type Service struct {
	mu               sync.RWMutex
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
	riskPolicy       string
	logLevel         string
	batchConcurrency int
	requestSequence  atomic.Uint64
	startedAt        time.Time
	notifyApproval   func()
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
		riskPolicy:       normalizeRiskPolicy(options.RiskPolicy),
		logLevel:         options.LogLevel,
		batchConcurrency: normalizeConcurrency(options.BatchConcurrency),
		startedAt:        options.Now(),
		notifyApproval:   options.NotifyApproval,
	}, nil
}

func (service *Service) Status(ctx context.Context) (model.BrokerStatus, error) {
	if service == nil || ctx == nil {
		return model.BrokerStatus{}, model.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return model.BrokerStatus{}, model.ErrTimeout
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return model.BrokerStatus{
		DaemonReachable: true,
		VaultLocked:     service.vaultLocked,
		Version:         service.version,
		PolicyVersion:   service.policyVersion,
		AuditFailClosed: service.auditFailClosed,
		RiskPolicy:      service.riskPolicy, LogLevel: service.logLevel,
		BatchConcurrency: service.batchConcurrency, ServerCount: len(service.servers),
		PID: os.Getpid(), StartedAt: service.startedAt.UTC().Format(time.RFC3339),
	}, nil
}

func (service *Service) ListServers(ctx context.Context) ([]model.ServerSummary, error) {
	if service == nil || ctx == nil {
		return nil, model.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, model.ErrTimeout
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return cloneServers(service.servers), nil
}

func (service *Service) SetVaultState(locked bool, servers []model.ServerSummary) {
	if service == nil {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	service.vaultLocked = locked
	service.servers = cloneServers(servers)
}

func (service *Service) UpdateSettings(riskPolicy, logLevel string, batchConcurrency int) {
	if service == nil {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	service.riskPolicy = normalizeRiskPolicy(riskPolicy)
	service.logLevel = logLevel
	service.batchConcurrency = normalizeConcurrency(batchConcurrency)
}

func (service *Service) settings() (string, int) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.riskPolicy, service.batchConcurrency
}

func (service *Service) ListApprovals(includeCommand bool) []approval.Approval {
	store, ok := service.approvals.(BatchApprovalStore)
	if !ok {
		return nil
	}
	return store.List(includeCommand)
}

func (service *Service) DecideApproval(id string, allow bool) error {
	store, ok := service.approvals.(BatchApprovalStore)
	if !ok {
		return model.ErrApproval
	}
	return store.Decide(id, allow)
}

func (service *Service) Execute(ctx context.Context, request model.ExecuteRequest) model.ExecuteResult {
	if service == nil || !validExecuteRequest(ctx, request) {
		return failed(model.ErrValidation)
	}
	secret, ok := service.secrets.Lookup(request.ServerAlias)
	if !ok {
		return failed(model.ErrValidation)
	}
	defer vault.ZeroServerSecret(&secret)

	riskPolicy, _ := service.settings()
	analysis := policy.Analysis{}
	if riskPolicy != "off" {
		var err error
		analysis, err = service.analyzer.Analyze(request.Command)
		if err != nil {
			return failed(model.ErrValidation)
		}
	}
	limits := requestLimits(request, service)
	if riskPolicy == "warn" {
		return service.executeRemote(ctx, service.nextRequestID(), request.ServerAlias, request.Command, limits, analysis.Categories, false, secret)
	}
	if len(analysis.Categories) != 0 {
		created, err := service.approvals.Create(
			request.ServerAlias,
			[]byte(request.Command),
			analysis.Categories,
			approval.ExecutionLimits{Timeout: limits.Timeout, MaxOutputBytes: limits.MaxOutputBytes},
		)
		if err != nil {
			return failed(model.ErrApproval)
		}
		defer vault.Zero(created.Command)
		event := service.auditEvent(approvalRequestID(created.ID), request.ServerAlias, request.Command, analysis.Categories)
		event.Decision = string(model.StatusRequiresApproval)
		event.ApprovalState = "created"
		event.RequireSync = true
		if err := service.auditor.Write(event); err != nil {
			_ = service.approvals.Revoke(created.ID)
			return failed(model.ErrAudit)
		}
		return model.ExecuteResult{
			Status: model.StatusRequiresApproval,
			Approval: &model.ApprovalInfo{
				ID:        created.ID,
				Code:      created.Code,
				Message:   fmt.Sprintf("local approval required for risk categories: %s", categoryList(analysis.Categories)),
				ExpiresAt: created.ExpiresAt.UTC().Format(time.RFC3339),
			},
		}
	}

	return service.executeRemote(ctx, service.nextRequestID(), request.ServerAlias, request.Command, limits, nil, false, secret)
}

func (service *Service) ExecuteBatch(ctx context.Context, request model.BatchExecuteRequest) model.BatchExecuteResult {
	if service == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(request.Command) == "" {
		return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrValidation}
	}
	aliases := append([]string(nil), request.ServerAliases...)
	if request.All {
		aliases = aliases[:0]
		for _, server := range service.servers {
			aliases = append(aliases, server.Alias)
		}
	}
	if request.All {
		sort.Strings(aliases)
	}
	if len(aliases) == 0 || len(aliases) > 256 {
		return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrValidation}
	}
	seen := make(map[string]struct{}, len(aliases))
	unique := aliases[:0]
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		unique = append(unique, alias)
	}
	aliases = unique
	analysis := policy.Analysis{}
	if service.riskPolicy != "off" {
		var err error
		analysis, err = service.analyzer.Analyze(request.Command)
		if err != nil {
			return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrValidation}
		}
	}
	riskPolicy, defaultConcurrency := service.settings()
	if riskPolicy == "enforce" && len(analysis.Categories) != 0 {
		store, ok := service.approvals.(BatchApprovalStore)
		if !ok {
			return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrApproval}
		}
		limits := requestLimits(model.ExecuteRequest{TimeoutSeconds: request.TimeoutSeconds, MaxOutputBytes: request.MaxOutputBytes}, service)
		created, err := store.CreateBatch(aliases, []byte(request.Command), analysis.Categories, approval.ExecutionLimits{Timeout: limits.Timeout, MaxOutputBytes: limits.MaxOutputBytes})
		if err != nil {
			return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrApproval}
		}
		return model.BatchExecuteResult{Status: model.StatusRequiresApproval, Approval: &model.ApprovalInfo{ID: created.ID, Message: fmt.Sprintf("local approval required for %d servers; risk categories: %s", len(aliases), categoryList(analysis.Categories)), ExpiresAt: created.ExpiresAt.UTC().Format(time.RFC3339)}}
	}
	concurrency := request.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > 32 {
		concurrency = 32
	}
	results := make([]model.ServerExecuteResult, len(aliases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for n := 0; n < concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				secret, ok := service.secrets.Lookup(aliases[index])
				if !ok {
					results[index] = model.ServerExecuteResult{ServerAlias: aliases[index], ExecuteResult: failed(model.ErrValidation)}
					continue
				}
				limits := requestLimits(model.ExecuteRequest{TimeoutSeconds: request.TimeoutSeconds, MaxOutputBytes: request.MaxOutputBytes}, service)
				one := service.executeRemote(ctx, service.nextRequestID(), aliases[index], request.Command, limits, analysis.Categories, false, secret)
				vault.ZeroServerSecret(&secret)
				results[index] = model.ServerExecuteResult{ServerAlias: aliases[index], ExecuteResult: one}
			}
		}()
	}
	for i := range aliases {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	status := model.StatusCompleted
	for _, result := range results {
		if result.Status != model.StatusCompleted {
			status = model.StatusFailed
			break
		}
	}
	return model.BatchExecuteResult{Status: status, Results: results}
}

func normalizeRiskPolicy(value string) string {
	if value == "warn" || value == "off" {
		return value
	}
	return "enforce"
}
func normalizeConcurrency(value int) int {
	if value < 1 || value > 32 {
		return 8
	}
	return value
}

func (service *Service) ExecuteApproved(ctx context.Context, request model.ApprovedRequest) model.ExecuteResult {
	if service == nil || ctx == nil || ctx.Err() != nil || request.ApprovalID == "" || request.ApprovalCode == "" {
		return failed(model.ErrApproval)
	}
	approved, err := service.approvals.Consume(request.ApprovalID, request.ApprovalCode)
	if err != nil {
		return failed(model.ErrApproval)
	}
	defer vault.Zero(approved.Command)
	secret, ok := service.secrets.Lookup(approved.ServerAlias)
	if !ok {
		return failed(model.ErrValidation)
	}
	defer vault.ZeroServerSecret(&secret)
	return service.executeRemote(
		ctx,
		approvalRequestID(approved.ID),
		approved.ServerAlias,
		string(approved.Command),
		sshclient.Limits{Timeout: approved.Limits.Timeout, MaxOutputBytes: approved.Limits.MaxOutputBytes},
		approved.Categories,
		true,
		secret,
	)
}

func (service *Service) ExecuteWait(ctx context.Context, request model.ExecuteRequest) model.ExecuteResult {
	result := service.Execute(ctx, request)
	if result.Status != model.StatusRequiresApproval || result.Approval == nil {
		return result
	}
	if service.notifyApproval != nil {
		service.notifyApproval()
	}
	store, ok := service.approvals.(WaitingApprovalStore)
	if !ok {
		return failed(model.ErrApproval)
	}
	approved, allowed, err := store.Wait(ctx, result.Approval.ID)
	if err != nil || !allowed {
		return model.ExecuteResult{Status: model.StatusDenied, Error: model.ErrApproval}
	}
	defer vault.Zero(approved.Command)
	secret, ok := service.secrets.Lookup(approved.ServerAlias)
	if !ok {
		return failed(model.ErrValidation)
	}
	defer vault.ZeroServerSecret(&secret)
	return service.executeRemote(ctx, approvalRequestID(approved.ID), approved.ServerAlias, string(approved.Command), sshclient.Limits{Timeout: approved.Limits.Timeout, MaxOutputBytes: approved.Limits.MaxOutputBytes}, approved.Categories, true, secret)
}

func (service *Service) ExecuteBatchWait(ctx context.Context, request model.BatchExecuteRequest) model.BatchExecuteResult {
	result := service.ExecuteBatch(ctx, request)
	if result.Status != model.StatusRequiresApproval || result.Approval == nil {
		return result
	}
	if service.notifyApproval != nil {
		service.notifyApproval()
	}
	store, ok := service.approvals.(WaitingApprovalStore)
	if !ok {
		return model.BatchExecuteResult{Status: model.StatusFailed, Error: model.ErrApproval}
	}
	approved, allowed, err := store.Wait(ctx, result.Approval.ID)
	if err != nil || !allowed {
		return model.BatchExecuteResult{Status: model.StatusDenied, Error: model.ErrApproval}
	}
	aliases := approved.ServerAliases
	concurrency := request.Concurrency
	if concurrency <= 0 {
		_, concurrency = service.settings()
	}
	if concurrency > 32 {
		concurrency = 32
	}
	results := make([]model.ServerExecuteResult, len(aliases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for n := 0; n < concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				secret, ok := service.secrets.Lookup(aliases[index])
				if !ok {
					results[index] = model.ServerExecuteResult{ServerAlias: aliases[index], ExecuteResult: failed(model.ErrValidation)}
					continue
				}
				one := service.executeRemote(ctx, approvalRequestID(approved.ID), aliases[index], string(approved.Command), sshclient.Limits{Timeout: approved.Limits.Timeout, MaxOutputBytes: approved.Limits.MaxOutputBytes}, approved.Categories, true, secret)
				vault.ZeroServerSecret(&secret)
				results[index] = model.ServerExecuteResult{ServerAlias: aliases[index], ExecuteResult: one}
			}
		}()
	}
	for i := range aliases {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	vault.Zero(approved.Command)
	status := model.StatusCompleted
	for _, one := range results {
		if one.Status != model.StatusCompleted {
			status = model.StatusFailed
			break
		}
	}
	return model.BatchExecuteResult{Status: status, Results: results}
}

func (service *Service) executeRemote(
	ctx context.Context,
	requestID string,
	alias string,
	command string,
	limits sshclient.Limits,
	categories []policy.Category,
	approved bool,
	secret vault.ServerSecret,
) model.ExecuteResult {
	failClosed := service.auditFailClosed || approved
	preflight := service.auditEvent(requestID, alias, command, categories)
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

	finalEvent := service.auditEvent(requestID, alias, command, categories)
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

func (service *Service) nextRequestID() string {
	now := service.now()
	sequence := service.requestSequence.Add(1)
	return fmt.Sprintf("broker-%d-%d", now.UnixNano(), sequence)
}

func approvalRequestID(id string) string {
	return "approval-" + id
}

func (service *Service) auditEvent(requestID, alias, command string, categories []policy.Category) audit.Event {
	now := service.now()
	return audit.Event{
		Timestamp:      now,
		RequestID:      requestID,
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
