package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/taotecode/aegis-ssh/internal/model"
)

func TestProtocolServerRejectsTwoFramesFromOneWriteBeforeDispatch(t *testing.T) {
	service := &fakeProtocolService{}
	path, _, _ := startProtocolServer(t, service)
	first := mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: "execute-1", Method: "execute",
		Params: mustRawJSON(t, model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"}),
	})
	second := mustRequestFrame(t, Request{Version: ProtocolVersion, RequestID: "status-2", Method: "status"})

	response := rawProtocolCall(t, path, append(first, second...))

	if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != 0 {
		t.Fatalf("Execute calls = %d, want 0", len(service.executes))
	}
}

func TestProtocolServerRejectsDelayedSecondFrameBeforeDispatch(t *testing.T) {
	service := &fakeProtocolService{holdEntered: make(chan struct{}), holdRelease: make(chan struct{})}
	_, path, _, _ := startConfiguredProtocolServer(t, service, func(server *Server) {
		server.requestReadTimeout = time.Second
	})
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	first := mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: "execute-1", Method: "execute",
		Params: mustRawJSON(t, model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"}),
	})
	if _, err := connection.Write(first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.holdEntered:
	case <-time.After(30 * time.Millisecond):
	}
	second := mustRequestFrame(t, Request{Version: ProtocolVersion, RequestID: "status-2", Method: "status"})
	if _, err := connection.Write(second); err != nil {
		t.Fatal(err)
	}
	closeUnixWrite(t, connection)
	close(service.holdRelease)
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != 0 {
		t.Fatalf("Execute calls = %d, want 0", len(service.executes))
	}
}

func TestProtocolServerRequiresRequestHalfCloseBeforeDispatch(t *testing.T) {
	service := &fakeProtocolService{}
	_, path, _, _ := startConfiguredProtocolServer(t, service, func(server *Server) {
		server.requestReadTimeout = 30 * time.Millisecond
	})
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: "no-half-close", Method: "execute",
		Params: mustRawJSON(t, model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"}),
	})
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != 0 {
		t.Fatalf("Execute calls = %d, want 0", len(service.executes))
	}
}

func TestProtocolClientHalfClosesRequestBeforeReadingResponse(t *testing.T) {
	path := serveResponseAfterRequestEOF(t)
	client := NewClient(path)
	client.readTimeout = time.Second

	status, err := client.Status(context.Background())

	if err != nil || !status.DaemonReachable {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}

func TestProtocolRequestHalfCloseDoesNotCancelDispatchedContext(t *testing.T) {
	service := &fakeProtocolService{
		entered: make(chan struct{}), canceled: make(chan struct{}),
		release: make(chan struct{}), finished: make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(service.release)
		}
	}()
	path, cancel, done := startProtocolServer(t, service)
	callDone := make(chan error, 1)
	go func() {
		_, err := NewClient(path).Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "block"})
		callDone <- err
	}()
	select {
	case <-service.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("service was not called")
	}
	select {
	case <-service.canceled:
		t.Fatal("request half-close canceled the dispatched context")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-service.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("server cancellation did not reach dispatched context")
	}
	close(service.release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-callDone
}

func TestProtocolServerAcceptsFragmentedRequestAfterHalfClose(t *testing.T) {
	service := &fakeProtocolService{}
	path, _, _ := startProtocolServer(t, service)
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	command := strings.Repeat("x", 120<<10)
	frame := mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: "fragmented", Method: "execute",
		Params: mustRawJSON(t, model.ExecuteRequest{ServerAlias: "prod", Command: command}),
	})
	for len(frame) != 0 {
		chunk := min(257, len(frame))
		if err := writeAll(connection, frame[:chunk]); err != nil {
			t.Fatal(err)
		}
		frame = frame[chunk:]
	}
	closeUnixWrite(t, connection)
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil || response.RequestID != "fragmented" {
		t.Fatalf("response = %+v", response)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != 1 || service.executes[0].Command != command {
		t.Fatalf("Execute calls = %d", len(service.executes))
	}
}

func TestProtocolClientRejectsTrailingDataWhilePeerStaysOpen(t *testing.T) {
	path := serveHoldingClientResponse(t, func(requestID string) []byte {
		payload := append(validStatusResponse(t, requestID), '\n')
		return append(payload, []byte("{\"secret-host\":true}\n")...)
	})

	_, err := NewClient(path).Status(context.Background())

	if !errors.Is(err, ErrInvalidProtocol) || strings.Contains(err.Error(), "secret-host") {
		t.Fatalf("Status() error = %v", err)
	}
}

func TestProtocolFrameReaderAcceptsExactMaximumFrame(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		payload := append(bytes.Repeat([]byte{'x'}, MaxFrameBytes), '\n')
		done <- writeAll(writer, payload)
		_ = writer.Close()
	}()

	_ = reader.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := readSingleFrame(reader)

	if err != nil || len(frame) != MaxFrameBytes {
		t.Fatalf("readSingleFrame() bytes = %d, error = %v", len(frame), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProtocolClientValidatesResponseIdentityBeforeRemoteError(t *testing.T) {
	tests := []struct {
		name     string
		response func(string) Response
	}{
		{
			name: "wrong request id",
			response: func(string) Response {
				return Response{Version: ProtocolVersion, RequestID: "wrong", Error: &RPCError{Code: string(model.CodeLockedVault), Message: "wire-secret"}}
			},
		},
		{
			name: "wrong version",
			response: func(requestID string) Response {
				return Response{Version: "999", RequestID: requestID, Error: &RPCError{Code: string(model.CodeLockedVault), Message: "wire-secret"}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := serveHoldingClientResponse(t, func(requestID string) []byte {
				data, marshalErr := json.Marshal(test.response(requestID))
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return append(data, '\n')
			})

			_, err := NewClient(path).Status(context.Background())

			if !errors.Is(err, ErrInvalidProtocol) || errors.Is(err, model.ErrLockedVault) || strings.Contains(err.Error(), "wire-secret") {
				t.Fatalf("Status() error = %v", err)
			}
		})
	}
}

func TestProtocolClientRequiresExactlyOneResultOrError(t *testing.T) {
	result := mustRawJSON(t, model.BrokerStatus{DaemonReachable: true})
	tests := []struct {
		name     string
		response func(string) Response
	}{
		{
			name: "both",
			response: func(requestID string) Response {
				return Response{Version: ProtocolVersion, RequestID: requestID, Result: result, Error: &RPCError{Code: ErrorInternal, Message: "wire-secret"}}
			},
		},
		{
			name: "neither",
			response: func(requestID string) Response {
				return Response{Version: ProtocolVersion, RequestID: requestID}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := serveHoldingClientResponse(t, func(requestID string) []byte {
				data, marshalErr := json.Marshal(test.response(requestID))
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return append(data, '\n')
			})

			_, err := NewClient(path).Status(context.Background())

			if !errors.Is(err, ErrInvalidProtocol) || strings.Contains(err.Error(), "wire-secret") {
				t.Fatalf("Status() error = %v", err)
			}
		})
	}
}

func TestProtocolClientMapsKnownRemoteCodesToCanonicalErrors(t *testing.T) {
	tests := []struct {
		code ErrorCodeFixture
		want error
	}{
		{ErrorCodeFixture(model.CodeLockedVault), model.ErrLockedVault},
		{ErrorCodeFixture(model.CodeTimeout), model.ErrTimeout},
		{ErrorCodeFixture(model.CodeAuthentication), model.ErrAuthentication},
	}
	for _, test := range tests {
		t.Run(string(test.code), func(t *testing.T) {
			path := serveHoldingClientResponse(t, func(requestID string) []byte {
				data, marshalErr := json.Marshal(Response{
					Version: ProtocolVersion, RequestID: requestID,
					Error: &RPCError{Code: string(test.code), Message: "wire-secret"},
				})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return append(data, '\n')
			})

			_, err := NewClient(path).Status(context.Background())

			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "wire-secret") {
				t.Fatalf("Status() error = %v, want %v", err, test.want)
			}
		})
	}
}

type ErrorCodeFixture string

func TestProtocolClientKeepsUnknownRemoteCodeAsRPCError(t *testing.T) {
	path := serveHoldingClientResponse(t, func(requestID string) []byte {
		data, err := json.Marshal(Response{
			Version: ProtocolVersion, RequestID: requestID,
			Error: &RPCError{Code: "future_error", Message: "future message"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	})

	_, err := NewClient(path).Status(context.Background())

	var rpcError *RPCError
	if !errors.As(err, &rpcError) || rpcError.Code != "future_error" || rpcError.Message != "future message" {
		t.Fatalf("Status() error = %#v", err)
	}
}

func TestProtocolServerStrictJSONRejectsUnknownFieldsBeforeService(t *testing.T) {
	service := &fakeProtocolService{}
	path, _, _ := startProtocolServer(t, service)
	tests := []struct {
		name  string
		frame string
	}{
		{"request envelope", `{"version":"1","request_id":"strict-1","method":"execute","params":{"server_alias":"prod","command":"uptime"},"extra":true}` + "\n"},
		{"execute typo", `{"version":"1","request_id":"strict-2","method":"execute","params":{"server_alias":"prod","command":"uptime","timeout_second":5}}` + "\n"},
		{"approved extra", `{"version":"1","request_id":"strict-3","method":"execute_approved","params":{"approval_id":"approval-1","approval_code":"ABCD","extra":true}}` + "\n"},
		{"status params", `{"version":"1","request_id":"strict-4","method":"status","params":{}}` + "\n"},
		{"list params", `{"version":"1","request_id":"strict-5","method":"list_servers","params":{}}` + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := rawProtocolCall(t, path, []byte(test.frame))
			if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
				t.Fatalf("response = %+v", response)
			}
		})
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != 0 || len(service.approved) != 0 {
		t.Fatalf("service calls: execute=%d approved=%d", len(service.executes), len(service.approved))
	}
}

func TestProtocolClientStrictlyDecodesEnvelopeAndResult(t *testing.T) {
	tests := []struct {
		name    string
		payload func(string) []byte
	}{
		{
			name: "unknown envelope field",
			payload: func(requestID string) []byte {
				return []byte(`{"version":"1","request_id":"` + requestID + `","result":{"daemon_reachable":true},"extra":true}` + "\n")
			},
		},
		{
			name: "unknown result field",
			payload: func(requestID string) []byte {
				return []byte(`{"version":"1","request_id":"` + requestID + `","result":{"daemon_reachable":true,"extra":true}}` + "\n")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := serveHoldingClientResponse(t, test.payload)
			_, err := NewClient(path).Status(context.Background())
			if !errors.Is(err, ErrInvalidProtocol) {
				t.Fatalf("Status() error = %v", err)
			}
		})
	}
}

func TestProtocolFitsLargeExecuteResultWithoutReplacingOutcome(t *testing.T) {
	const secret = "BOUNDARY-SECRET-MUST-NOT-LEAK"
	stdout := strings.Repeat("\x00", 4<<20) + secret
	stderr := strings.Repeat("界", (4<<20)/len("界")) + secret
	want := model.ExecuteResult{
		Status: model.StatusFailed, Stdout: stdout, Stderr: stderr, ExitCode: 23,
		DurationMS: 77, Error: model.ErrAuthentication, Warnings: []*model.CodedError{model.ErrAudit},
		Approval:   &model.ApprovalInfo{ID: "approval-1", Code: "ABCD", Message: "review"},
		Redactions: model.RedactionSummary{Applied: true, Counts: map[string]int{"credential": 2}},
	}
	response := marshalResult("large-1", want)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxFrameBytes {
		t.Fatalf("response bytes = %d, want <= %d", len(encoded), MaxFrameBytes)
	}
	if response.Error != nil {
		t.Fatalf("response replaced outcome: %+v", response.Error)
	}
	var got model.ExecuteResult
	if err := json.Unmarshal(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != want.Status || got.ExitCode != want.ExitCode || got.DurationMS != want.DurationMS ||
		!got.Truncated || !errors.Is(got.Error, model.ErrAuthentication) || len(got.Warnings) != 1 ||
		!errors.Is(got.Warnings[0], model.ErrAudit) || got.Approval == nil || got.Approval.ID != "approval-1" ||
		!got.Redactions.Applied || got.Redactions.Counts["credential"] != 2 {
		t.Fatalf("fitted result did not preserve metadata: %+v", got)
	}
	if strings.Contains(got.Stdout, secret) || strings.Contains(got.Stderr, secret) {
		t.Fatal("fitted result leaked truncated boundary secret")
	}
	if !utf8.ValidString(got.Stdout) || !utf8.ValidString(got.Stderr) {
		t.Fatal("fitted result split UTF-8 output")
	}
	allocations := testing.AllocsPerRun(3, func() {
		if fitted := marshalResult("allocation-1", want); fitted.Error != nil {
			panic("large execute result was replaced")
		}
	})
	if allocations > 80 {
		t.Fatalf("marshalResult() allocations = %.0f, want <= 80", allocations)
	}

	service := &fakeProtocolService{executeResult: &want}
	path, _, _ := startProtocolServer(t, service)
	roundTrip, err := NewClient(path).Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "large"})
	if err != nil || roundTrip.Status != want.Status || !roundTrip.Truncated || roundTrip.ExitCode != want.ExitCode {
		t.Fatalf("Execute() = %+v, %v", roundTrip, err)
	}
}

func TestFitExecuteOutputPreservesSingleStream(t *testing.T) {
	const available = 64
	stdout, stderr := fitExecuteOutput(strings.Repeat("out", 100), "", available)
	if stdout == "" || stderr != "" {
		t.Fatalf("stdout-only fit = (%q, %q)", stdout, stderr)
	}
	stdout, stderr = fitExecuteOutput("", strings.Repeat("err", 100), available)
	if stdout != "" || stderr == "" {
		t.Fatalf("stderr-only fit = (%q, %q)", stdout, stderr)
	}
}

func TestProtocolFitsLargeBatchResult(t *testing.T) {
	result := model.BatchExecuteResult{Status: model.StatusCompleted, Results: make([]model.ServerExecuteResult, 16)}
	for index := range result.Results {
		result.Results[index] = model.ServerExecuteResult{ServerAlias: fmt.Sprintf("server-%d", index), ExecuteResult: model.ExecuteResult{Status: model.StatusCompleted, Stdout: strings.Repeat("x", 1<<20), Stderr: strings.Repeat("界", 1<<19)}}
	}
	response := marshalResult("batch-large", result)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxFrameBytes || response.Error != nil {
		t.Fatalf("batch response size=%d response=%+v", len(encoded), response.Error)
	}
	var got model.BatchExecuteResult
	if err := json.Unmarshal(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	for _, one := range got.Results {
		if !one.Truncated {
			t.Fatal("large batch result was not marked truncated")
		}
		if !utf8.ValidString(one.Stdout) || !utf8.ValidString(one.Stderr) {
			t.Fatal("invalid UTF-8")
		}
	}
}

func TestJSONEscapedContentSizeMatchesEncodingJSON(t *testing.T) {
	value := "\b\f\n\r\t\"\\<>&\u2028\u2029\x00界"
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := jsonEscapedContentSize(value, MaxFrameBytes), len(encoded)-2; got != want {
		t.Fatalf("escaped content bytes = %d, want %d (%s)", got, want, encoded)
	}
}

func TestProtocolServerRequestReadDeadlineRejectsSlowloris(t *testing.T) {
	server, path, cancel, done := startConfiguredProtocolServer(t, &fakeProtocolService{}, func(server *Server) {
		server.requestReadTimeout = 30 * time.Millisecond
	})
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(`{"version":"1"`)); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	waitForProtocolSlots(t, server, 0)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProtocolServerConnectionLimitRejectsAndReleases(t *testing.T) {
	server, path, _, _ := startConfiguredProtocolServer(t, &fakeProtocolService{}, func(server *Server) {
		server.requestReadTimeout = 5 * time.Second
	})
	connections := make([]net.Conn, 0, maxProtocolConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range maxProtocolConnections {
		connection, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	waitForProtocolSlots(t, server, maxProtocolConnections)

	overflow, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = overflow.Write([]byte("x"))
	if _, err := overflow.Read(make([]byte, 1)); err == nil {
		t.Fatal("65th connection remained open")
	}
	if got := len(server.slots); got != maxProtocolConnections {
		t.Fatalf("active slots = %d, want %d", got, maxProtocolConnections)
	}

	_ = connections[0].Close()
	waitForProtocolSlots(t, server, maxProtocolConnections-1)
	replacement, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := replacement.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write(mustRequestFrame(t, Request{Version: ProtocolVersion, RequestID: "replacement", Method: "status"})); err != nil {
		t.Fatal(err)
	}
	closeUnixWrite(t, replacement)
	line, err := bufio.NewReader(replacement).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil || response.RequestID != "replacement" {
		t.Fatalf("replacement response = %+v", response)
	}
}

func TestProtocolServerCancellationReleasesIdleConnectionSlots(t *testing.T) {
	server, path, cancel, done := startConfiguredProtocolServer(t, &fakeProtocolService{}, func(server *Server) {
		server.requestReadTimeout = time.Minute
	})
	connections := make([]net.Conn, 0, maxProtocolConnections)
	for range maxProtocolConnections {
		connection, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	waitForProtocolSlots(t, server, maxProtocolConnections)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop with idle connections")
	}
	if got := len(server.slots); got != 0 {
		t.Fatalf("active slots after cancellation = %d", got)
	}
	for _, connection := range connections {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := connection.Read(make([]byte, 1)); err == nil {
			t.Error("idle connection remained open after server cancellation")
		}
		_ = connection.Close()
	}
}

func TestProtocolClientReadDeadlineBoundsIncompleteFrames(t *testing.T) {
	tests := []struct {
		name    string
		payload func(string) []byte
		wantErr error
		timeout time.Duration
	}{
		{
			name: "missing newline",
			payload: func(requestID string) []byte {
				return validStatusResponse(t, requestID)
			},
			wantErr: ErrInvalidProtocol,
			timeout: 30 * time.Millisecond,
		},
		{
			name: "over limit without newline",
			payload: func(string) []byte {
				return []byte(strings.Repeat("sensitive-payload", MaxFrameBytes/len("sensitive-payload")+2))
			},
			wantErr: ErrFrameTooLarge,
			timeout: time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := serveUnclosedClientResponse(t, test.payload)
			client := NewClient(path)
			client.readTimeout = test.timeout
			started := time.Now()
			_, err := client.Status(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Status() error = %v, want %v", err, test.wantErr)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("Status() exceeded resource deadline: %v", elapsed)
			}
		})
	}
}

func TestProtocolClientUsesEarlierContextReadDeadline(t *testing.T) {
	path := serveUnclosedClientResponse(t, func(string) []byte { return nil })
	client := NewClient(path)
	client.readTimeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := client.Status(ctx)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status() error = %v, want context deadline", err)
	}
}

func TestProtocolClientDefaultDeadlinesCoverMaximumExecution(t *testing.T) {
	client := NewClient("unused")
	if client.writeTimeout != 5*time.Second {
		t.Fatalf("write timeout = %v, want 5s", client.writeTimeout)
	}
	if client.readTimeout < 31*time.Minute {
		t.Fatalf("read timeout = %v, want at least 31m", client.readTimeout)
	}
}

func TestProtocolClientWriteDeadlineBoundsBlockedPeer(t *testing.T) {
	path := filepath.Join(newPrivateProtocolDir(t), "blocked-write.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	client := NewClient(path)
	client.writeTimeout = 20 * time.Millisecond
	callDone := make(chan error, 1)
	go func() {
		_, callErr := client.Execute(context.Background(), model.ExecuteRequest{
			ServerAlias: "prod", Command: strings.Repeat("x", MaxFrameBytes-1024),
		})
		callDone <- callErr
	}()
	connection := <-accepted
	defer connection.Close()
	select {
	case err := <-callDone:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Execute() error = %v, want ErrUnavailable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Execute() remained blocked past write deadline")
	}
}

func TestProtocolWriteAllHandlesPartialWrites(t *testing.T) {
	writer := &chunkWriter{limit: 3}
	payload := []byte("complete-frame\n")

	if err := writeAll(writer, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.Bytes(), payload) {
		t.Fatalf("written = %q, want %q", writer.Bytes(), payload)
	}
}

func TestProtocolRequestIDLengthBoundary(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	acceptedID := strings.Repeat("r", maxRequestIDBytes)
	accepted := rawProtocolCall(t, path, mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: acceptedID, Method: "status",
	}))
	if accepted.Error != nil || accepted.RequestID != acceptedID {
		t.Fatalf("accepted response = %+v", accepted)
	}

	rejected := rawProtocolCall(t, path, mustRequestFrame(t, Request{
		Version: ProtocolVersion, RequestID: acceptedID + "r", Method: "status",
	}))
	if rejected.Error == nil || rejected.Error.Code != ErrorInvalidRequest {
		t.Fatalf("rejected response = %+v", rejected)
	}
}

func TestProtocolWriteResponseFallbackAlwaysFitsFrame(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		writeResponse(server, Response{
			Version: ProtocolVersion, RequestID: strings.Repeat("r", MaxFrameBytes),
			Result: mustRawJSON(t, strings.Repeat("\x00", MaxFrameBytes)),
		})
		_ = server.Close()
	}()
	data, err := io.ReadAll(client)
	_ = client.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || len(data)-1 > MaxFrameBytes {
		t.Fatalf("fallback frame bytes = %d", len(data))
	}
	var response Response
	if err := json.Unmarshal(data[:len(data)-1], &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("fallback response = %+v", response)
	}
}

type chunkWriter struct {
	bytes.Buffer
	limit int
}

func (writer *chunkWriter) Write(data []byte) (int, error) {
	if len(data) > writer.limit {
		data = data[:writer.limit]
	}
	return writer.Buffer.Write(data)
}

func startConfiguredProtocolServer(t *testing.T, service BrokerService, configure func(*Server)) (*Server, string, context.CancelFunc, <-chan error) {
	t.Helper()
	path := filepath.Join(newPrivateProtocolDir(t), "configured.sock")
	server := NewServer(path, service)
	configure(server)
	ctx, cancel := context.WithCancel(context.Background())
	done := serveInBackground(server, ctx)
	waitForProtocolReachable(t, ctx, path, done)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("configured Serve() did not stop")
		}
	})
	return server, path, cancel, done
}

func waitForProtocolSlots(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.slots) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active slots = %d, want %d", len(server.slots), want)
}

var _ io.Writer = (*chunkWriter)(nil)

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustRequestFrame(t *testing.T, request Request) []byte {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func serveHoldingClientResponse(t *testing.T, response func(requestID string) []byte) string {
	t.Helper()
	path := filepath.Join(newPrivateProtocolDir(t), "holding.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadBytes('\n')
		if readErr != nil {
			return
		}
		var request Request
		if json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &request) != nil {
			return
		}
		if payload := response(request.RequestID); payload != nil {
			_, _ = connection.Write(payload)
		}
		_, _ = connection.Read(make([]byte, 1))
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("holding response server did not stop")
		}
	})
	return path
}

func serveUnclosedClientResponse(t *testing.T, response func(requestID string) []byte) string {
	t.Helper()
	path := filepath.Join(newPrivateProtocolDir(t), "unclosed-response.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	release := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadBytes('\n')
		if readErr != nil {
			return
		}
		var request Request
		if json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &request) != nil {
			return
		}
		if payload := response(request.RequestID); payload != nil {
			_ = writeAll(connection, payload)
		}
		<-release
	}()
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("unclosed response server did not stop")
		}
	})
	return path
}

func serveResponseAfterRequestEOF(t *testing.T) string {
	t.Helper()
	path := filepath.Join(newPrivateProtocolDir(t), "request-eof.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		frame, readErr := io.ReadAll(connection)
		if readErr != nil || len(frame) == 0 || frame[len(frame)-1] != '\n' {
			return
		}
		var request Request
		if json.Unmarshal(frame[:len(frame)-1], &request) != nil {
			return
		}
		_, _ = connection.Write(append(validStatusResponse(t, request.RequestID), '\n'))
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("request EOF server did not stop")
		}
	})
	return path
}

func closeUnixWrite(t *testing.T, connection net.Conn) {
	t.Helper()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		t.Fatalf("connection type = %T, want *net.UnixConn", connection)
	}
	if err := unixConnection.CloseWrite(); err != nil && !errors.Is(err, syscall.ENOTCONN) {
		t.Fatal(err)
	}
}
