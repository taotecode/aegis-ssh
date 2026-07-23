package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
)

type fakeProtocolService struct {
	mu       sync.Mutex
	executes []model.ExecuteRequest
	approved []model.ApprovedRequest
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	finished chan struct{}
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
	service.mu.Unlock()
	if service.entered != nil {
		close(service.entered)
		<-ctx.Done()
		close(service.canceled)
		<-service.release
		close(service.finished)
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
	directory, err := os.MkdirTemp("", "aegis-broker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "broker.sock")
	server := NewServer(path, service)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case err := <-done:
			cancel()
			parentInfo, _ := os.Lstat(filepath.Dir(path))
			t.Fatalf("server stopped during startup: %v (parent=%v mode=%v owner=%v)", err, parentInfo != nil, parentInfo.Mode(), sameOwner(parentInfo))
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for Unix socket")
		}
		time.Sleep(time.Millisecond)
	}
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
