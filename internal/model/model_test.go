package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chenjw/aegis-ssh/internal/model"
)

func TestStatusWireValues(t *testing.T) {
	tests := []struct {
		status model.Status
		want   string
	}{
		{model.StatusReady, "ready"},
		{model.StatusLocked, "locked"},
		{model.StatusCompleted, "completed"},
		{model.StatusRequiresApproval, "requires_approval"},
		{model.StatusDenied, "denied"},
		{model.StatusFailed, "failed"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("status = %q, want %q", tt.status, tt.want)
		}
	}
}

func TestCodedErrorsHaveStableSanitizedJSONAndRemainComparable(t *testing.T) {
	tests := []struct {
		err     *model.CodedError
		code    model.ErrorCode
		message string
	}{
		{model.ErrAuthentication, model.CodeAuthentication, "authentication failed"},
		{model.ErrHostKey, model.CodeHostKey, "host key verification failed"},
		{model.ErrTimeout, model.CodeTimeout, "operation timed out"},
		{model.ErrUnavailableDaemon, model.CodeUnavailableDaemon, "broker daemon unavailable"},
		{model.ErrLockedVault, model.CodeLockedVault, "credential vault is locked"},
		{model.ErrValidation, model.CodeValidation, "request validation failed"},
		{model.ErrApproval, model.CodeApproval, "request approval failed"},
		{model.ErrAudit, model.CodeAudit, "audit operation failed"},
	}

	for _, tt := range tests {
		if tt.err.Code() != tt.code {
			t.Errorf("Code() = %q, want %q", tt.err.Code(), tt.code)
		}
		if tt.err.Error() != tt.message {
			t.Errorf("Error() = %q, want %q", tt.err.Error(), tt.message)
		}
		if !errors.Is(errors.Join(errors.New("dependency failure"), tt.err), tt.err) {
			t.Errorf("errors.Is(wrapped, sentinel) = false for %q", tt.code)
		}
		assertJSON(t, tt.err, `{"code":"`+string(tt.code)+`","message":"`+tt.message+`"}`)
	}
}

func TestPublicModelJSONContracts(t *testing.T) {
	approval := model.ApprovalInfo{
		ID:        "approval-1",
		Code:      "M7K2",
		Message:   "Approve production command",
		ExpiresAt: "2026-07-18T16:00:00Z",
	}
	redactions := model.RedactionSummary{
		Applied: true,
		Counts:  map[string]int{"credential": 2, "token": 1},
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name: "execute request",
			value: model.ExecuteRequest{
				ServerAlias:    "prod",
				Command:        "uptime",
				TimeoutSeconds: 30,
				MaxOutputBytes: 4096,
			},
			want: `{"server_alias":"prod","command":"uptime","timeout_seconds":30,"max_output_bytes":4096}`,
		},
		{
			name:  "approved request",
			value: model.ApprovedRequest{ApprovalID: "approval-1", ApprovalCode: "M7K2"},
			want:  `{"approval_id":"approval-1","approval_code":"M7K2"}`,
		},
		{
			name: "execute result",
			value: model.ExecuteResult{
				Status:     model.StatusCompleted,
				Stdout:     "ok",
				Stderr:     "warning",
				ExitCode:   0,
				DurationMS: 25,
				Truncated:  true,
				Error:      model.ErrTimeout,
				Approval:   &approval,
				Redactions: redactions,
			},
			want: `{"status":"completed","stdout":"ok","stderr":"warning","exit_code":0,"duration_ms":25,"truncated":true,"error":{"code":"timeout","message":"operation timed out"},"approval":{"id":"approval-1","code":"M7K2","message":"Approve production command","expires_at":"2026-07-18T16:00:00Z"},"redactions":{"applied":true,"counts":{"credential":2,"token":1}}}`,
		},
		{
			name:  "approval info",
			value: approval,
			want:  `{"id":"approval-1","code":"M7K2","message":"Approve production command","expires_at":"2026-07-18T16:00:00Z"}`,
		},
		{
			name:  "redaction summary",
			value: redactions,
			want:  `{"applied":true,"counts":{"credential":2,"token":1}}`,
		},
		{
			name:  "server summary",
			value: model.ServerSummary{Alias: "prod", Description: "Production", Available: true},
			want:  `{"alias":"prod","description":"Production","available":true}`,
		},
		{
			name: "broker status",
			value: model.BrokerStatus{
				DaemonReachable: true,
				VaultLocked:     false,
				Version:         "1.0.0",
				PolicyVersion:   "policy-7",
				AuditFailClosed: true,
			},
			want: `{"daemon_reachable":true,"vault_locked":false,"version":"1.0.0","policy_version":"policy-7","audit_fail_closed":true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJSON(t, tt.value, tt.want)
		})
	}
}

func TestPublicRequestAndResultTypesExcludeConnectionDetails(t *testing.T) {
	banned := map[string]bool{
		"host": true, "port": true, "user": true, "username": true,
		"password": true, "fingerprint": true,
	}
	types := []any{
		model.ExecuteRequest{},
		model.ApprovedRequest{},
		model.ExecuteResult{},
		model.ApprovalInfo{},
		model.RedactionSummary{},
		model.ServerSummary{},
		model.BrokerStatus{},
	}

	for _, value := range types {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			field := typeOf.Field(i)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			if banned[strings.ToLower(field.Name)] || banned[strings.ToLower(jsonName)] {
				t.Errorf("%s exposes banned field %s with JSON name %q", typeOf.Name(), field.Name, jsonName)
			}
		}
	}
}

func assertJSON(t *testing.T, value any, want string) {
	t.Helper()
	got, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Marshal() = %s, want %s", got, want)
	}
}
