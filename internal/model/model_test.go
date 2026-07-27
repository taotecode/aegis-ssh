package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
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
		{model.ErrConnection, model.CodeConnection, "remote connection failed"},
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

func TestExecuteResultPreservesWarningsInJSONRoundTrip(t *testing.T) {
	raw := []byte(`{"status":"failed","exit_code":0,"truncated":false,"error":{"code":"authentication_failed","message":"password-value"},"warnings":[{"code":"audit_failed","message":"secret-host"}],"redactions":{"applied":false}}`)
	var result model.ExecuteResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(encoded)
	if !strings.Contains(wire, `"error":{"code":"authentication_failed","message":"authentication failed"}`) ||
		!strings.Contains(wire, `"warnings":[{"code":"audit_failed","message":"audit operation failed"}]`) {
		t.Fatalf("ExecuteResult JSON did not preserve canonical errors: %s", encoded)
	}
	if strings.Contains(wire, "password-value") || strings.Contains(wire, "secret-host") {
		t.Fatalf("ExecuteResult JSON leaked input messages: %s", encoded)
	}
	if !errors.Is(result.Error, model.ErrAuthentication) {
		t.Fatalf("roundtrip error %v does not match ErrAuthentication", result.Error)
	}
	if len(result.Warnings) != 1 || !errors.Is(result.Warnings[0], model.ErrAudit) {
		t.Fatalf("roundtrip warnings %+v do not match ErrAudit", result.Warnings)
	}
}

func TestCodedErrorIsMatchesOnlyKnownEqualCodes(t *testing.T) {
	if errors.Is(model.ErrAuthentication, model.ErrTimeout) {
		t.Fatal("different canonical error codes matched")
	}
	var nilCoded *model.CodedError
	if errors.Is(nilCoded, model.ErrAudit) || errors.Is(model.ErrAudit, nilCoded) {
		t.Fatal("typed nil CodedError matched a canonical error")
	}
	if errors.Is(&model.CodedError{}, &model.CodedError{}) || errors.Is(&model.CodedError{}, model.ErrAudit) {
		t.Fatal("empty CodedError matched")
	}
}

func TestCodedErrorNilReceiverIsSafe(t *testing.T) {
	var coded *model.CodedError
	if got := coded.Error(); got != "" {
		t.Fatalf("nil Error() = %q, want empty", got)
	}
	if got := coded.Code(); got != "" {
		t.Fatalf("nil Code() = %q, want empty", got)
	}
	if err := coded.UnmarshalJSON([]byte(`{"code":"audit_failed"}`)); err == nil {
		t.Fatal("nil UnmarshalJSON() succeeded")
	}
}

func TestCodedErrorCanonicalSentinelsRejectDirectJSONMutation(t *testing.T) {
	tests := []*model.CodedError{
		model.ErrAuthentication, model.ErrConnection, model.ErrHostKey, model.ErrTimeout,
		model.ErrUnavailableDaemon, model.ErrLockedVault, model.ErrValidation, model.ErrApproval, model.ErrAudit,
	}
	for _, sentinel := range tests {
		original, err := json.Marshal(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(`{"code":"timeout","message":"secret-host"}`), sentinel); err == nil {
			_ = json.Unmarshal(original, sentinel)
			t.Fatalf("canonical sentinel %s accepted direct mutation", original)
		}
		after, err := json.Marshal(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(original) {
			_ = json.Unmarshal(original, sentinel)
			t.Fatalf("canonical sentinel changed: before=%s after=%s", original, after)
		}
	}
}

func TestCodedErrorCanonicalSentinelsRejectConcurrentJSONMutation(t *testing.T) {
	sentinels := []*model.CodedError{
		model.ErrAuthentication, model.ErrConnection, model.ErrHostKey, model.ErrTimeout,
		model.ErrUnavailableDaemon, model.ErrLockedVault, model.ErrValidation, model.ErrApproval, model.ErrAudit,
	}
	original := make([][]byte, len(sentinels))
	for index, sentinel := range sentinels {
		encoded, err := json.Marshal(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		original[index] = encoded
	}
	var wait sync.WaitGroup
	errorsByAttempt := make(chan error, len(sentinels)*16)
	for _, sentinel := range sentinels {
		for range 16 {
			wait.Add(1)
			go func(target *model.CodedError) {
				defer wait.Done()
				errorsByAttempt <- json.Unmarshal([]byte(`{"code":"timeout","message":"secret-host"}`), target)
			}(sentinel)
		}
	}
	wait.Wait()
	close(errorsByAttempt)
	for err := range errorsByAttempt {
		if err == nil {
			t.Fatal("concurrent canonical mutation succeeded")
		}
	}
	for index, sentinel := range sentinels {
		encoded, err := json.Marshal(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != string(original[index]) {
			t.Fatalf("canonical sentinel changed: before=%s after=%s", original[index], encoded)
		}
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
				Warnings:   []*model.CodedError{model.ErrAudit},
				Approval:   &approval,
				Redactions: redactions,
			},
			want: `{"status":"completed","stdout":"ok","stderr":"warning","exit_code":0,"duration_ms":25,"truncated":true,"error":{"code":"timeout","message":"operation timed out"},"warnings":[{"code":"audit_failed","message":"audit operation failed"}],"approval":{"id":"approval-1","code":"M7K2","message":"Approve production command","expires_at":"2026-07-18T16:00:00Z"},"redactions":{"applied":true,"counts":{"credential":2,"token":1}}}`,
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
