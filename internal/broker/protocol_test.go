package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
)

type fakeProtocolService struct {
	mu            sync.Mutex
	executes      []model.ExecuteRequest
	approved      []model.ApprovedRequest
	executeResult *model.ExecuteResult
	entered       chan struct{}
	canceled      chan struct{}
	release       chan struct{}
	finished      chan struct{}
}

func (service *fakeProtocolService) Status(context.Context) (model.BrokerStatus, error) {
	return model.BrokerStatus{DaemonReachable: true, Version: "test-version", AuditFailClosed: true}, nil
}

func (service *fakeProtocolService) ListServers(context.Context) ([]model.ServerSummary, error) {
	return []model.ServerSummary{{Alias: "prod", Description: "production", Available: true}}, nil
}

func (service *fakeProtocolService) Execute(ctx context.Context, request model.ExecuteRequest) model.ExecuteResult {
	service.mu.Lock()
	service.executes = append(service.executes, request)
	configured := service.executeResult
	service.mu.Unlock()
	if service.entered != nil {
		close(service.entered)
		<-ctx.Done()
		close(service.canceled)
		<-service.release
		close(service.finished)
	}
	if configured != nil {
		return *configured
	}
	return model.ExecuteResult{Status: model.StatusCompleted, Stdout: "ran:" + request.Command}
}

func (service *fakeProtocolService) ExecuteApproved(_ context.Context, request model.ApprovedRequest) model.ExecuteResult {
	service.mu.Lock()
	service.approved = append(service.approved, request)
	service.mu.Unlock()
	return model.ExecuteResult{Status: model.StatusCompleted, Stdout: "approved:" + request.ApprovalID}
}

func startProtocolServer(t *testing.T, service BrokerService) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	directory := newPrivateProtocolDir(t)
	path := filepath.Join(directory, "broker.sock")
	server := NewServer(path, service)
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
			t.Error("Serve() did not stop after cancellation")
		}
	})
	return path, cancel, done
}

func newPrivateProtocolDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "aegis-broker-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func serveInBackground(server *Server, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
		close(done)
	}()
	return done
}

func waitForProtocolReachable(t *testing.T, ctx context.Context, path string, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	retry := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer retry.Stop()
	var status model.BrokerStatus
	var statusErr error
	for {
		attemptCtx, stopAttempt := context.WithTimeout(ctx, 100*time.Millisecond)
		status, statusErr = NewClient(path).Status(attemptCtx)
		stopAttempt()
		if statusErr == nil && status.DaemonReachable {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped during startup: %v", err)
		case <-deadline.C:
			t.Fatalf("server did not become reachable: status=%+v err=%v", status, statusErr)
		case <-retry.C:
		}
	}
}

func TestProtocolDispatchesAllMethods(t *testing.T) {
	service := &fakeProtocolService{}
	path, _, _ := startProtocolServer(t, service)
	client := NewClient(path)
	ctx := context.Background()

	status, err := client.Status(ctx)
	if err != nil || !status.DaemonReachable || status.Version != "test-version" {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	servers, err := client.ListServers(ctx)
	if err != nil || len(servers) != 1 || servers[0].Alias != "prod" {
		t.Fatalf("ListServers() = %+v, %v", servers, err)
	}
	executed, err := client.Execute(ctx, model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
	if err != nil || executed.Status != model.StatusCompleted || executed.Stdout != "ran:uptime" {
		t.Fatalf("Execute() = %+v, %v", executed, err)
	}
	approved, err := client.ExecuteApproved(ctx, model.ApprovedRequest{ApprovalID: "approval-1", ApprovalCode: "ABCD"})
	if err != nil || approved.Status != model.StatusCompleted || approved.Stdout != "approved:approval-1" {
		t.Fatalf("ExecuteApproved() = %+v, %v", approved, err)
	}
}

func TestProtocolExecuteRoundTripPreservesErrorAndWarning(t *testing.T) {
	service := &fakeProtocolService{executeResult: &model.ExecuteResult{
		Status:   model.StatusFailed,
		Error:    model.ErrAuthentication,
		Warnings: []*model.CodedError{model.ErrAudit},
	}}
	path, _, _ := startProtocolServer(t, service)

	result, err := NewClient(path).Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})

	if err != nil || result.Status != model.StatusFailed || result.Error == nil ||
		result.Error.Code() != model.CodeAuthentication || len(result.Warnings) != 1 ||
		result.Warnings[0] == nil || result.Warnings[0].Code() != model.CodeAudit {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	if !errors.Is(result.Error, model.ErrAuthentication) || !errors.Is(result.Warnings[0], model.ErrAudit) {
		t.Fatalf("roundtrip errors are not comparable: error=%v warnings=%+v", result.Error, result.Warnings)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-host")) {
		t.Fatalf("roundtrip result leaked secret: %s", raw)
	}
}

func TestProtocolRejectsMalformedJSON(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	response := rawProtocolCall(t, path, []byte("{not-json}\n"))
	if response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
}

func TestProtocolRejectsUnknownMethod(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	frame, err := json.Marshal(Request{Version: ProtocolVersion, RequestID: "unknown-1", Method: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	response := rawProtocolCall(t, path, append(frame, '\n'))
	if response.RequestID != "unknown-1" || response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %+v", response)
	}
}

func TestProtocolRejectsOversizedFrame(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	frame := append([]byte(strings.Repeat("x", MaxFrameBytes+1)), '\n')
	response := rawProtocolCall(t, path, frame)
	if response.Error == nil || response.Error.Code != ErrorFrameTooLarge {
		t.Fatalf("response = %+v", response)
	}
}

func TestProtocolSocketModeIsPrivate(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %04o, want 0600", got)
	}
}

func TestProtocolSocketPathDoesNotProveReachability(t *testing.T) {
	path := filepath.Join(newPrivateProtocolDir(t), "bound.sock")
	fileDescriptor, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fileDescriptor)
	if err := syscall.Bind(fileDescriptor, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("bound path mode = %v, want socket", info.Mode())
	}
	if _, err := NewClient(path).Status(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Status() error = %v, want ErrUnavailable before listen", err)
	}
}

func TestProtocolServerCancellationClosesAndRemovesSocket(t *testing.T) {
	path, cancel, done := startProtocolServer(t, &fakeProtocolService{})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists: %v", err)
	}
}

func TestProtocolHandlesConcurrentCalls(t *testing.T) {
	service := &fakeProtocolService{}
	path, _, _ := startProtocolServer(t, service)
	client := NewClient(path)
	const calls = 32
	errorsByCall := make(chan error, calls)
	var wait sync.WaitGroup
	for index := range calls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := client.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "echo concurrent"})
			if err == nil && result.Status != model.StatusCompleted {
				err = errors.New("unexpected execution status")
			}
			errorsByCall <- err
		}()
		_ = index
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.executes) != calls {
		t.Fatalf("execute calls = %d, want %d", len(service.executes), calls)
	}
}

func TestProtocolClientCancellationReturnsContextError(t *testing.T) {
	path, _, _ := startProtocolServer(t, &fakeProtocolService{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient(path).Status(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Status() error = %v, want context.Canceled", err)
	}
}

func TestProtocolClientRequiresOneNewlineDelimitedResponseFrame(t *testing.T) {
	tests := []struct {
		name    string
		payload func(requestID string) []byte
		wantErr error
	}{
		{
			name: "missing newline",
			payload: func(requestID string) []byte {
				return validStatusResponse(t, requestID)
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "oversized before newline",
			payload: func(string) []byte {
				return append([]byte(strings.Repeat("sensitive-payload", MaxFrameBytes/len("sensitive-payload")+2)), '\n')
			},
			wantErr: ErrFrameTooLarge,
		},
		{
			name: "trailing second frame",
			payload: func(requestID string) []byte {
				return append(append(validStatusResponse(t, requestID), '\n'), []byte("{\"secret-host\":true}\n")...)
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "nonempty trailing data",
			payload: func(requestID string) []byte {
				return append(append(validStatusResponse(t, requestID), '\n'), []byte("secret-host")...)
			},
			wantErr: ErrInvalidProtocol,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := serveRawClientResponse(t, test.payload)
			_, err := NewClient(path).Status(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Status() error = %v, want %v", err, test.wantErr)
			}
			for _, sensitive := range []string{path, "sensitive-payload", "secret-host"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("Status() error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}

func TestProtocolClientCancellationInterruptsBlockedResponseRead(t *testing.T) {
	path := serveRawClientResponse(t, func(string) []byte { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() {
		_, err := NewClient(path).Status(ctx)
		callDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-callDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Status() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Status() remained blocked reading response")
	}
}

func TestProtocolClientCancellationInterruptsBlockedWrite(t *testing.T) {
	directory := newPrivateProtocolDir(t)
	path := filepath.Join(directory, "blocked.sock")
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
	ctx, cancel := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() {
		_, err := NewClient(path).Execute(ctx, model.ExecuteRequest{
			ServerAlias: "prod", Command: strings.Repeat("x", MaxFrameBytes-1024),
		})
		callDone <- err
	}()
	connection := <-accepted
	defer connection.Close()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-callDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Execute() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Execute() remained blocked in Write after cancellation")
	}
}

func TestProtocolUnavailableClientErrorIsSanitized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")
	_, err := NewClient(path).Status(context.Background())
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), path) {
		t.Fatalf("Status() error = %v", err)
	}
}

func TestProtocolShutdownDoesNotRemoveReplacementPath(t *testing.T) {
	path, cancel, done := startProtocolServer(t, &fakeProtocolService{})
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement path was changed: data=%q err=%v", data, err)
	}
}

func TestProtocolShutdownWaitsForActiveHandler(t *testing.T) {
	service := &fakeProtocolService{
		entered: make(chan struct{}), canceled: make(chan struct{}),
		release: make(chan struct{}), finished: make(chan struct{}),
	}
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
	cancel()
	select {
	case <-service.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("active handler did not receive cancellation")
	}
	select {
	case err := <-done:
		t.Fatalf("Serve returned before handler release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(service.release)
	select {
	case <-service.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("active handler did not finish")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-callDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client call did not return")
	}
}

func TestProtocolConcurrentServerStartupHasSingleReachableWinner(t *testing.T) {
	path := filepath.Join(newPrivateProtocolDir(t), "broker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := serveInBackground(NewServer(path, &fakeProtocolService{}), ctx)
	second := serveInBackground(NewServer(path, &fakeProtocolService{}), ctx)

	var winner <-chan error
	select {
	case err := <-first:
		if !errors.Is(err, ErrSocketInUse) {
			t.Fatalf("first Serve() error = %v", err)
		}
		winner = second
	case err := <-second:
		if !errors.Is(err, ErrSocketInUse) {
			t.Fatalf("second Serve() error = %v", err)
		}
		winner = first
	case <-time.After(2 * time.Second):
		t.Fatal("neither concurrent Serve returned")
	}
	waitForProtocolReachable(t, ctx, path, winner)
	cancel()
	select {
	case err := <-winner:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("winning Serve did not stop")
	}
}

func TestProtocolRejectsUnsafeStartupLock(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			target := path + ".target"
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"broad mode", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(newPrivateProtocolDir(t), "broker.sock")
			test.setup(t, path+".lock")
			err := NewServer(path, &fakeProtocolService{}).Serve(context.Background())
			if !errors.Is(err, ErrUnsafeSocket) || strings.Contains(err.Error(), path) {
				t.Fatalf("Serve() error = %v", err)
			}
		})
	}
}

func TestProtocolServerOperationErrorsAreSanitized(t *testing.T) {
	t.Run("bind", func(t *testing.T) {
		path := filepath.Join(newPrivateProtocolDir(t), "broker.sock")
		server := NewServer(path, &fakeProtocolService{})
		server.listen = func(_, _ string) (net.Listener, error) { return nil, fmt.Errorf("bind %s", path) }
		assertSanitizedSocketError(t, path, server.Serve(context.Background()))
	})
	t.Run("remove stale", func(t *testing.T) {
		path := filepath.Join(newPrivateProtocolDir(t), "broker.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		server := NewServer(path, &fakeProtocolService{})
		server.remove = func(string) error { return fmt.Errorf("remove %s", path) }
		assertSanitizedSocketError(t, path, server.Serve(context.Background()))
	})
	t.Run("accept", func(t *testing.T) {
		path := filepath.Join(newPrivateProtocolDir(t), "broker.sock")
		server := NewServer(path, &fakeProtocolService{})
		server.accept = func(net.Listener) (net.Conn, error) { return nil, fmt.Errorf("accept %s", path) }
		assertSanitizedSocketError(t, path, server.Serve(context.Background()))
	})
	t.Run("overlong path", func(t *testing.T) {
		path := filepath.Join(newPrivateProtocolDir(t), strings.Repeat("x", 180))
		assertSanitizedSocketError(t, path, NewServer(path, &fakeProtocolService{}).Serve(context.Background()))
	})
}

func assertSanitizedSocketError(t *testing.T, path string, err error) {
	t.Helper()
	if !errors.Is(err, ErrSocketOperation) || strings.Contains(err.Error(), path) {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestProtocolConcurrentServeLeavesPermanentPrivateUmask(t *testing.T) {
	original := syscall.Umask(0o022)
	defer syscall.Umask(original)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	paths := []string{
		filepath.Join(newPrivateProtocolDir(t), "one.sock"),
		filepath.Join(newPrivateProtocolDir(t), "two.sock"),
	}
	done := []<-chan error{
		serveInBackground(NewServer(paths[0], &fakeProtocolService{}), ctx),
		serveInBackground(NewServer(paths[1], &fakeProtocolService{}), ctx),
	}
	for index, path := range paths {
		waitForProtocolReachable(t, ctx, path, done[index])
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("socket %d mode = %v err=%v", index, info.Mode().Perm(), err)
		}
	}
	observed := syscall.Umask(0o077)
	syscall.Umask(observed)
	if observed != 0o077 {
		t.Fatalf("process umask = %04o, want permanent 0077", observed)
	}
	cancel()
	for _, result := range done {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
}

func rawProtocolCall(t *testing.T, path string, frame []byte) Response {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write(frame); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func validStatusResponse(t *testing.T, requestID string) []byte {
	t.Helper()
	result, err := json.Marshal(model.BrokerStatus{DaemonReachable: true})
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(Response{Version: ProtocolVersion, RequestID: requestID, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func serveRawClientResponse(t *testing.T, response func(requestID string) []byte) string {
	t.Helper()
	path := filepath.Join(newPrivateProtocolDir(t), "raw.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			return
		}
		var request Request
		if json.Unmarshal(line[:len(line)-1], &request) != nil {
			return
		}
		payload := response(request.RequestID)
		if payload == nil {
			_, _ = connection.Read(make([]byte, 1))
			return
		}
		_, _ = connection.Write(payload)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("raw response server did not stop")
		}
	})
	return path
}
