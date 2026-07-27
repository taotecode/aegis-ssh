package model

import (
	"encoding/json"
	"errors"
)

type Status string

const (
	StatusReady            Status = "ready"
	StatusLocked           Status = "locked"
	StatusCompleted        Status = "completed"
	StatusRequiresApproval Status = "requires_approval"
	StatusDenied           Status = "denied"
	StatusFailed           Status = "failed"
)

type ErrorCode string

const (
	CodeAuthentication    ErrorCode = "authentication_failed"
	CodeConnection        ErrorCode = "connection_failed"
	CodeHostKey           ErrorCode = "host_key_verification_failed"
	CodeTimeout           ErrorCode = "timeout"
	CodeUnavailableDaemon ErrorCode = "daemon_unavailable"
	CodeLockedVault       ErrorCode = "vault_locked"
	CodeValidation        ErrorCode = "validation_failed"
	CodeApproval          ErrorCode = "approval_failed"
	CodeAudit             ErrorCode = "audit_failed"
)

type CodedError struct {
	code    ErrorCode
	message string
}

func (e *CodedError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *CodedError) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

func (e *CodedError) Is(target error) bool {
	other, ok := target.(*CodedError)
	return ok && e != nil && other != nil &&
		codedErrorForCode(e.code) != nil && codedErrorForCode(other.code) != nil &&
		e.code == other.code
}

func (e *CodedError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
	}{Code: e.code, Message: e.message})
}

func (e *CodedError) UnmarshalJSON(data []byte) error {
	if e == nil || isCanonicalCodedError(e) {
		return errors.New("invalid coded error receiver")
	}
	var wire struct {
		Code ErrorCode `json:"code"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	canonical := codedErrorForCode(wire.Code)
	if canonical == nil {
		return errors.New("invalid coded error")
	}
	*e = *canonical
	return nil
}

func isCanonicalCodedError(candidate *CodedError) bool {
	return candidate == ErrAuthentication || candidate == ErrConnection || candidate == ErrHostKey ||
		candidate == ErrTimeout || candidate == ErrUnavailableDaemon || candidate == ErrLockedVault ||
		candidate == ErrValidation || candidate == ErrApproval || candidate == ErrAudit
}

var (
	ErrAuthentication    = &CodedError{code: CodeAuthentication, message: "authentication failed"}
	ErrConnection        = &CodedError{code: CodeConnection, message: "remote connection failed"}
	ErrHostKey           = &CodedError{code: CodeHostKey, message: "host key verification failed"}
	ErrTimeout           = &CodedError{code: CodeTimeout, message: "operation timed out"}
	ErrUnavailableDaemon = &CodedError{code: CodeUnavailableDaemon, message: "broker daemon unavailable"}
	ErrLockedVault       = &CodedError{code: CodeLockedVault, message: "credential vault is locked"}
	ErrValidation        = &CodedError{code: CodeValidation, message: "request validation failed"}
	ErrApproval          = &CodedError{code: CodeApproval, message: "request approval failed"}
	ErrAudit             = &CodedError{code: CodeAudit, message: "audit operation failed"}
)

func codedErrorForCode(code ErrorCode) *CodedError {
	switch code {
	case CodeAuthentication:
		return ErrAuthentication
	case CodeConnection:
		return ErrConnection
	case CodeHostKey:
		return ErrHostKey
	case CodeTimeout:
		return ErrTimeout
	case CodeUnavailableDaemon:
		return ErrUnavailableDaemon
	case CodeLockedVault:
		return ErrLockedVault
	case CodeValidation:
		return ErrValidation
	case CodeApproval:
		return ErrApproval
	case CodeAudit:
		return ErrAudit
	default:
		return nil
	}
}

// ErrorForCode returns the immutable canonical error for a known wire code.
func ErrorForCode(code ErrorCode) *CodedError {
	return codedErrorForCode(code)
}

type ExecuteRequest struct {
	ServerAlias    string `json:"server_alias"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty"`
}

type ApprovedRequest struct {
	ApprovalID   string `json:"approval_id"`
	ApprovalCode string `json:"approval_code"`
}

type ExecuteResult struct {
	Status     Status           `json:"status"`
	Stdout     string           `json:"stdout,omitempty"`
	Stderr     string           `json:"stderr,omitempty"`
	ExitCode   int              `json:"exit_code"`
	DurationMS int64            `json:"duration_ms,omitempty"`
	Truncated  bool             `json:"truncated"`
	Error      *CodedError      `json:"error,omitempty"`
	Warnings   []*CodedError    `json:"warnings,omitempty"`
	Approval   *ApprovalInfo    `json:"approval,omitempty"`
	Redactions RedactionSummary `json:"redactions"`
}

type ApprovalInfo struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type RedactionSummary struct {
	Applied bool           `json:"applied"`
	Counts  map[string]int `json:"counts,omitempty"`
}

type ServerSummary struct {
	Alias       string `json:"alias"`
	Description string `json:"description,omitempty"`
	Available   bool   `json:"available"`
}

type BrokerStatus struct {
	DaemonReachable bool   `json:"daemon_reachable"`
	VaultLocked     bool   `json:"vault_locked"`
	Version         string `json:"version"`
	PolicyVersion   string `json:"policy_version"`
	AuditFailClosed bool   `json:"audit_fail_closed"`
}
