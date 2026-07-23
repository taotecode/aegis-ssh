package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
)

type BrokerService interface {
	Status(context.Context) (model.BrokerStatus, error)
	ListServers(context.Context) ([]model.ServerSummary, error)
	Execute(context.Context, model.ExecuteRequest) model.ExecuteResult
	ExecuteApproved(context.Context, model.ApprovedRequest) model.ExecuteResult
}

type Server struct {
	path    string
	service BrokerService

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	fileInfo os.FileInfo
	handlers sync.WaitGroup
}

func NewServer(path string, service BrokerService) *Server {
	return &Server{path: path, service: service, conns: make(map[net.Conn]struct{})}
}

func (server *Server) Serve(ctx context.Context) error {
	if server == nil || ctx == nil || server.path == "" || server.service == nil {
		return ErrInvalidProtocol
	}
	if err := prepareSocketPath(server.path); err != nil {
		return err
	}
	listener, err := listenPrivateUnix(server.path)
	if err != nil {
		return err
	}
	server.mu.Lock()
	server.listener = listener
	server.fileInfo, _ = os.Lstat(server.path)
	server.mu.Unlock()
	defer server.shutdown()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-serveCtx.Done()
		server.closeActive()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		server.mu.Lock()
		server.conns[connection] = struct{}{}
		server.handlers.Add(1)
		server.mu.Unlock()
		go server.handle(serveCtx, connection)
	}
}

func (server *Server) handle(parent context.Context, connection net.Conn) {
	defer func() {
		server.mu.Lock()
		delete(server.conns, connection)
		server.mu.Unlock()
		_ = connection.Close()
		server.handlers.Done()
	}()

	request, response := readRequest(connection)
	if response.Error != nil {
		writeResponse(connection, response)
		return
	}
	requestCtx, cancel := context.WithCancel(parent)
	defer cancel()
	go watchConnection(requestCtx, cancel, connection)
	response = server.dispatch(requestCtx, request)
	writeResponse(connection, response)
}

func (server *Server) dispatch(ctx context.Context, request Request) Response {
	if request.Version != ProtocolVersion || request.RequestID == "" || request.Method == "" {
		return protocolError(request.RequestID, ErrorInvalidRequest, "invalid request")
	}
	var params []byte
	if len(request.Params) != 0 {
		params = request.Params
	}
	switch request.Method {
	case "status":
		result, err := server.service.Status(ctx)
		if err != nil {
			return protocolServiceError(request.RequestID, err)
		}
		return marshalResult(request.RequestID, result)
	case "list_servers":
		result, err := server.service.ListServers(ctx)
		if err != nil {
			return protocolServiceError(request.RequestID, err)
		}
		return marshalResult(request.RequestID, result)
	case "execute":
		var execute model.ExecuteRequest
		if json.Unmarshal(params, &execute) != nil {
			return protocolError(request.RequestID, ErrorInvalidRequest, "invalid execute params")
		}
		return marshalResult(request.RequestID, server.service.Execute(ctx, execute))
	case "execute_approved":
		var approved model.ApprovedRequest
		if json.Unmarshal(params, &approved) != nil {
			return protocolError(request.RequestID, ErrorInvalidRequest, "invalid approved params")
		}
		return marshalResult(request.RequestID, server.service.ExecuteApproved(ctx, approved))
	default:
		return protocolError(request.RequestID, ErrorMethodNotFound, "unknown method")
	}
}

func readRequest(connection net.Conn) (Request, Response) {
	line, err := bufio.NewReaderSize(connection, MaxFrameBytes+2).ReadBytes('\n')
	if len(line) > MaxFrameBytes+1 || (errors.Is(err, bufio.ErrBufferFull) && len(line) >= MaxFrameBytes) {
		return Request{}, protocolError("", ErrorFrameTooLarge, "request frame too large")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return Request{}, protocolError("", ErrorInvalidRequest, "invalid request")
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return Request{}, protocolError("", ErrorInvalidRequest, "request must end with newline")
	}
	line = line[:len(line)-1]
	var request Request
	if json.Unmarshal(line, &request) != nil {
		return Request{}, protocolError("", ErrorInvalidRequest, "invalid JSON")
	}
	return request, Response{}
}

func writeResponse(connection net.Conn, response Response) {
	data, err := json.Marshal(response)
	if err != nil || len(data) > MaxFrameBytes {
		data, _ = json.Marshal(protocolError(response.RequestID, ErrorInternal, "response unavailable"))
	}
	data = append(data, '\n')
	_, _ = connection.Write(data)
}

func marshalResult(requestID string, value any) Response {
	data, err := json.Marshal(value)
	if err != nil {
		return protocolError(requestID, ErrorInternal, "response unavailable")
	}
	return Response{Version: ProtocolVersion, RequestID: requestID, Result: data}
}

func protocolServiceError(requestID string, err error) Response {
	var coded interface{ Code() model.ErrorCode }
	if errors.As(err, &coded) {
		return protocolError(requestID, string(coded.Code()), "broker request failed")
	}
	return protocolError(requestID, ErrorUnavailable, "broker request unavailable")
}

func watchConnection(ctx context.Context, cancel context.CancelFunc, connection net.Conn) {
	buffer := make([]byte, 1)
	readResult := make(chan error, 1)
	go func() { _, err := connection.Read(buffer); readResult <- err }()
	select {
	case <-ctx.Done():
		_ = connection.Close()
	case <-readResult:
		cancel()
	}
}

func (server *Server) closeActive() {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener != nil {
		_ = server.listener.Close()
	}
	for connection := range server.conns {
		_ = connection.Close()
	}
}

func (server *Server) shutdown() {
	server.closeActive()
	server.handlers.Wait()
	server.mu.Lock()
	info := server.fileInfo
	server.mu.Unlock()
	if info != nil {
		if current, err := os.Lstat(server.path); err == nil && os.SameFile(info, current) {
			_ = os.Remove(server.path)
		}
	}
}

func prepareSocketPath(path string) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 || !sameOwner(parentInfo) {
		return ErrUnsafeSocket
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !sameOwner(info) || info.Mode().Perm() != 0o600 {
		return ErrUnsafeSocket
	}
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return ErrSocketInUse
	}
	if !isConnectionRefused(dialErr) {
		return dialErr
	}
	return os.Remove(path)
}

func listenPrivateUnix(path string) (net.Listener, error) {
	previous := syscall.Umask(0o077)
	listener, err := net.Listen("unix", path)
	syscall.Umask(previous)
	if err != nil {
		return nil, err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, ErrUnsafeSocket
	}
	unixListener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, ErrUnsafeSocket
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 || !sameOwner(info) {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, ErrUnsafeSocket
	}
	return listener, nil
}

func sameOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}

func isConnectionRefused(err error) bool {
	var operation *net.OpError
	if errors.As(err, &operation) {
		return errors.Is(operation.Err, syscall.ECONNREFUSED) || errors.Is(operation.Err, syscall.ENOENT)
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT)
}
