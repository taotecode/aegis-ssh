package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chenjw/aegis-ssh/internal/model"
)

func TestCodedErrorsAreSanitizedAndComparable(t *testing.T) {
	tests := []struct {
		err  error
		code model.ErrorCode
	}{
		{model.ErrAuthentication, model.ErrorAuthentication},
		{model.ErrHostKey, model.ErrorHostKey},
		{model.ErrTimeout, model.ErrorTimeout},
		{model.ErrUnavailableDaemon, model.ErrorUnavailableDaemon},
		{model.ErrLockedVault, model.ErrorLockedVault},
		{model.ErrValidation, model.ErrorValidation},
		{model.ErrApproval, model.ErrorApproval},
		{model.ErrAudit, model.ErrorAudit},
	}

	for _, tt := range tests {
		coded, ok := tt.err.(*model.CodedError)
		if !ok {
			t.Fatalf("%T is not *model.CodedError", tt.err)
		}
		if coded.Code() != tt.code {
			t.Errorf("Code() = %q, want %q", coded.Code(), tt.code)
		}
		wrapped := errors.Join(errors.New("dependency detail: secret-host:2222"), coded)
		if !errors.Is(wrapped, tt.err) {
			t.Errorf("errors.Is(wrapped, sentinel) = false for %q", tt.code)
		}
		encoded, err := json.Marshal(coded)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "dependency") || strings.Contains(string(encoded), "secret-host") {
			t.Errorf("coded error JSON leaked dependency detail: %s", encoded)
		}
	}
}

func TestPublicResultTypesExcludeConnectionDetails(t *testing.T) {
	banned := map[string]bool{
		"host": true, "port": true, "user": true, "username": true,
		"password": true, "fingerprint": true,
	}
	types := []any{
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
			if banned[strings.ToLower(field.Name)] {
				t.Errorf("%s exposes banned field %s", typeOf.Name(), field.Name)
			}
		}
	}
}

func TestSharedRequestAndStatusTypesAreUsable(t *testing.T) {
	request := model.ExecuteRequest{Server: "prod", Command: "uptime"}
	approved := model.ApprovedRequest{
		Request:  request,
		Approval: model.ApprovalInfo{ID: "approval-1", Status: model.StatusApproved},
	}
	result := model.ExecuteResult{
		Status:   model.StatusSucceeded,
		ExitCode: 0,
	}
	broker := model.BrokerStatus{
		Status: model.StatusReady,
		Servers: []model.ServerSummary{
			{Name: "prod", Description: "Production"},
		},
	}

	if approved.Request != request || result.Status != model.StatusSucceeded || len(broker.Servers) != 1 {
		t.Fatal("shared model values did not round-trip in memory")
	}
}
