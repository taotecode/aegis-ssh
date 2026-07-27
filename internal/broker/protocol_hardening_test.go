package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chenjw/aegis-ssh/internal/model"
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

func TestProtocolClientReturnsAfterOneFrameWhilePeerStaysOpen(t *testing.T) {
	path := serveHoldingClientResponse(t, func(requestID string) []byte {
		return append(validStatusResponse(t, requestID), '\n')
	})
	client := NewClient(path)
	client.readTimeout = time.Second
	started := time.Now()

	status, err := client.Status(context.Background())

	if err != nil || !status.DaemonReachable {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Status() waited for peer close: %v", elapsed)
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

	frame, err := readSingleFrame(reader, time.Now().Add(time.Second))

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

	service := &fakeProtocolService{executeResult: &want}
	path, _, _ := startProtocolServer(t, service)
	roundTrip, err := NewClient(path).Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "large"})
	if err != nil || roundTrip.Status != want.Status || !roundTrip.Truncated || roundTrip.ExitCode != want.ExitCode {
		t.Fatalf("Execute() = %+v, %v", roundTrip, err)
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
			path := serveHoldingClientResponse(t, test.payload)
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
	path := serveHoldingClientResponse(t, func(string) []byte { return nil })
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
