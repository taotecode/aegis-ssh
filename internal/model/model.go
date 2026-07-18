package model

import "encoding/json"

type Status string

const (
	StatusReady           Status = "ready"
	StatusLocked          Status = "locked"
	StatusPendingApproval Status = "pending_approval"
	StatusApproved        Status = "approved"
	StatusDenied          Status = "denied"
	StatusSucceeded       Status = "succeeded"
	StatusFailed          Status = "failed"
)

type ErrorCode string

const (
	ErrorAuthentication    ErrorCode = "authentication_failed"
	ErrorHostKey           ErrorCode = "host_key_verification_failed"
	ErrorTimeout           ErrorCode = "timeout"
	ErrorUnavailableDaemon ErrorCode = "daemon_unavailable"
	ErrorLockedVault       ErrorCode = "vault_locked"
	ErrorValidation        ErrorCode = "validation_failed"
	ErrorApproval          ErrorCode = "approval_failed"
	ErrorAudit             ErrorCode = "audit_failed"
)

type CodedError struct {
	code    ErrorCode
	message string
}

func (e *CodedError) Error() string {
	return e.message
}

func (e *CodedError) Code() ErrorCode {
	return e.code
}

func (e *CodedError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
	}{Code: e.code, Message: e.message})
}

var (
	ErrAuthentication    = &CodedError{code: ErrorAuthentication, message: "authentication failed"}
	ErrHostKey           = &CodedError{code: ErrorHostKey, message: "host key verification failed"}
	ErrTimeout           = &CodedError{code: ErrorTimeout, message: "operation timed out"}
	ErrUnavailableDaemon = &CodedError{code: ErrorUnavailableDaemon, message: "broker daemon unavailable"}
	ErrLockedVault       = &CodedError{code: ErrorLockedVault, message: "credential vault is locked"}
	ErrValidation        = &CodedError{code: ErrorValidation, message: "request validation failed"}
	ErrApproval          = &CodedError{code: ErrorApproval, message: "request approval failed"}
	ErrAudit             = &CodedError{code: ErrorAudit, message: "audit operation failed"}
)

type ExecuteRequest struct {
	Server         string `json:"server"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty"`
}

type ApprovedRequest struct {
	Request  ExecuteRequest `json:"request"`
	Approval ApprovalInfo   `json:"approval"`
}

type ExecuteResult struct {
	Status     Status           `json:"status"`
	Stdout     string           `json:"stdout,omitempty"`
	Stderr     string           `json:"stderr,omitempty"`
	ExitCode   int              `json:"exit_code"`
	DurationMS int64            `json:"duration_ms,omitempty"`
	Error      *CodedError      `json:"error,omitempty"`
	Approval   *ApprovalInfo    `json:"approval,omitempty"`
	Redactions RedactionSummary `json:"redactions"`
}

type ApprovalInfo struct {
	ID        string `json:"id"`
	Status    Status `json:"status"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type RedactionSummary struct {
	Applied     bool `json:"applied"`
	InputCount  int  `json:"input_count,omitempty"`
	OutputCount int  `json:"output_count,omitempty"`
}

type ServerSummary struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Available   bool   `json:"available"`
}

type BrokerStatus struct {
	Status          Status          `json:"status"`
	VaultLocked     bool            `json:"vault_locked"`
	AuditFailClosed bool            `json:"audit_fail_closed"`
	Servers         []ServerSummary `json:"servers"`
}
