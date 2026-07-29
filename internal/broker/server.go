package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/taotecode/aegis-ssh/internal/model"
)

type BrokerService interface {
	Status(context.Context) (model.BrokerStatus, error)
	ListServers(context.Context) ([]model.ServerSummary, error)
	Execute(context.Context, model.ExecuteRequest) model.ExecuteResult
	ExecuteApproved(context.Context, model.ApprovedRequest) model.ExecuteResult
}

type lockService interface {
	Lock(context.Context)
}

type Server struct {
	path    string
	service BrokerService
	listen  func(string, string) (net.Listener, error)
	accept  func(net.Listener) (net.Conn, error)
	remove  func(string) error
	dial    func(string, string, time.Duration) (net.Conn, error)

	requestReadTimeout time.Duration
	slots              chan struct{}

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	fileInfo os.FileInfo
	handlers sync.WaitGroup
}

func NewServer(path string, service BrokerService) *Server {
	return &Server{
		path: path, service: service, conns: make(map[net.Conn]struct{}),
		listen:             net.Listen,
		accept:             func(listener net.Listener) (net.Conn, error) { return listener.Accept() },
		remove:             os.Remove,
		dial:               net.DialTimeout,
		requestReadTimeout: defaultRequestReadTimeout,
		slots:              make(chan struct{}, maxProtocolConnections),
	}
}

const (
	defaultRequestReadTimeout = 5 * time.Second
	maxProtocolConnections    = 64
)

var umaskMu sync.Mutex

func (server *Server) Serve(ctx context.Context) error {
	if server == nil || ctx == nil || server.path == "" || server.service == nil {
		return ErrInvalidProtocol
	}
	if err := validatePrivateSocketParent(server.path); err != nil {
		return err
	}
	setPermanentPrivateUmask()
	startupLock, err := acquireStartupLock(server.path + ".lock")
	if err != nil {
		return err
	}
	lockHeld := true
	defer func() {
		if lockHeld {
			releaseStartupLock(startupLock)
		}
	}()
	if err := server.prepareSocketPath(); err != nil {
		return err
	}
	listener, socketInfo, err := server.listenPrivateUnix()
	if err != nil {
		return err
	}
	server.mu.Lock()
	server.listener = listener
	server.fileInfo = socketInfo
	server.mu.Unlock()
	releaseStartupLock(startupLock)
	lockHeld = false
	defer server.shutdown()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-serveCtx.Done()
		server.closeActive()
	}()

	for {
		connection, err := server.accept(listener)
		if err != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return ErrSocketOperation
		}
		select {
		case server.slots <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		if serveCtx.Err() != nil {
			<-server.slots
			_ = connection.Close()
			continue
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
		<-server.slots
		server.handlers.Done()
	}()

	readDeadline := time.Now().Add(server.requestReadTimeout)
	if err := connection.SetReadDeadline(readDeadline); err != nil {
		return
	}
	request, response := readRequest(connection)
	_ = connection.SetReadDeadline(time.Time{})
	if response.Error != nil {
		writeResponse(connection, response)
		return
	}
	// EOF proves that the request contains exactly one frame. After this
	// expected half-close, another read cannot distinguish a live client from a
	// disconnected one, so execution remains bounded by the daemon context and
	// the request's SSH timeout rather than connection-read cancellation.
	response = server.dispatch(parent, request)
	writeResponse(connection, response)
	if request.Method == "lock" && response.Error == nil {
		server.service.(lockService).Lock(parent)
	}
}

func (server *Server) dispatch(ctx context.Context, request Request) Response {
	if request.Version != ProtocolVersion || request.RequestID == "" || request.Method == "" {
		return protocolError(request.RequestID, ErrorInvalidRequest, "invalid request")
	}
	if len(request.RequestID) > maxRequestIDBytes {
		return protocolError("", ErrorInvalidRequest, "invalid request")
	}
	var params []byte
	if len(request.Params) != 0 {
		params = request.Params
	}
	switch request.Method {
	case "status":
		if len(request.Params) != 0 {
			return protocolError(request.RequestID, ErrorInvalidRequest, "status params must be empty")
		}
		result, err := server.service.Status(ctx)
		if err != nil {
			return protocolServiceError(request.RequestID, err)
		}
		return marshalResult(request.RequestID, result)
	case "list_servers":
		if len(request.Params) != 0 {
			return protocolError(request.RequestID, ErrorInvalidRequest, "list params must be empty")
		}
		result, err := server.service.ListServers(ctx)
		if err != nil {
			return protocolServiceError(request.RequestID, err)
		}
		return marshalResult(request.RequestID, result)
	case "execute":
		var execute model.ExecuteRequest
		if decodeStrictJSON(params, &execute) != nil {
			return protocolError(request.RequestID, ErrorInvalidRequest, "invalid execute params")
		}
		return marshalResult(request.RequestID, server.service.Execute(ctx, execute))
	case "execute_approved":
		var approved model.ApprovedRequest
		if decodeStrictJSON(params, &approved) != nil {
			return protocolError(request.RequestID, ErrorInvalidRequest, "invalid approved params")
		}
		return marshalResult(request.RequestID, server.service.ExecuteApproved(ctx, approved))
	case "lock":
		if len(request.Params) != 0 {
			return protocolError(request.RequestID, ErrorInvalidRequest, "lock params must be empty")
		}
		if _, ok := server.service.(lockService); !ok {
			return protocolError(request.RequestID, ErrorMethodNotFound, "unknown method")
		}
		return marshalResult(request.RequestID, struct {
			Accepted bool `json:"accepted"`
		}{Accepted: true})
	default:
		return protocolError(request.RequestID, ErrorMethodNotFound, "unknown method")
	}
}

func readRequest(connection net.Conn) (Request, Response) {
	line, err := readSingleFrame(connection)
	if errors.Is(err, ErrFrameTooLarge) {
		return Request{}, protocolError("", ErrorFrameTooLarge, "request frame too large")
	}
	if err != nil {
		return Request{}, protocolError("", ErrorInvalidRequest, "invalid request")
	}
	var request Request
	if decodeStrictJSON(line, &request) != nil {
		return Request{}, protocolError("", ErrorInvalidRequest, "invalid JSON")
	}
	return request, Response{}
}

func writeResponse(connection net.Conn, response Response) {
	data, err := json.Marshal(response)
	if err != nil || len(data) > MaxFrameBytes {
		requestID := response.RequestID
		if len(requestID) > maxRequestIDBytes {
			requestID = ""
		}
		data, err = json.Marshal(protocolError(requestID, ErrorInternal, "response unavailable"))
	}
	if err != nil || len(data) > MaxFrameBytes {
		data = []byte(`{"version":"1","request_id":"","error":{"code":"internal_error","message":"response unavailable"}}`)
	}
	data = append(data, '\n')
	_ = connection.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
	_ = writeAll(connection, data)
}

func marshalResult(requestID string, value any) Response {
	switch result := value.(type) {
	case model.ExecuteResult:
		return marshalExecuteResult(requestID, result)
	case *model.ExecuteResult:
		if result == nil {
			return protocolError(requestID, ErrorInternal, "response unavailable")
		}
		return marshalExecuteResult(requestID, *result)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return protocolError(requestID, ErrorInternal, "response unavailable")
	}
	return Response{Version: ProtocolVersion, RequestID: requestID, Result: data}
}

func marshalExecuteResult(requestID string, result model.ExecuteResult) Response {
	stdout := normalizeUTF8(result.Stdout)
	stderr := normalizeUTF8(result.Stderr)
	if stdout != result.Stdout || stderr != result.Stderr {
		result.Truncated = true
	}
	result.Stdout = stdout
	result.Stderr = stderr
	if len(result.Stdout)+len(result.Stderr) <= MaxFrameBytes {
		if response, size, ok := encodedResultResponse(requestID, result); ok && size <= MaxFrameBytes {
			return response
		}
	}

	result.Truncated = true
	result.Stdout = ""
	result.Stderr = ""
	base, baseSize, ok := encodedResultResponse(requestID, result)
	if !ok {
		return protocolError(requestID, ErrorInternal, "response unavailable")
	}
	if baseSize > MaxFrameBytes {
		return protocolError(requestID, ErrorInternal, "response unavailable")
	}
	stdout, stderr = fitExecuteOutput(stdout, stderr, MaxFrameBytes-baseSize)
	if stdout == "" && stderr == "" {
		return base
	}
	result.Stdout = stdout
	result.Stderr = stderr
	data, err := json.Marshal(result)
	if err != nil {
		return protocolError(requestID, ErrorInternal, "response unavailable")
	}
	return Response{Version: ProtocolVersion, RequestID: requestID, Result: data}
}

func encodedResultResponse(requestID string, result model.ExecuteResult) (Response, int, bool) {
	data, err := json.Marshal(result)
	if err != nil {
		return Response{}, 0, false
	}
	response := Response{Version: ProtocolVersion, RequestID: requestID, Result: data}
	encoded, err := json.Marshal(response)
	if err != nil {
		return Response{}, 0, false
	}
	return response, len(encoded), true
}

func normalizeUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	return strings.ToValidUTF8(value, "\uFFFD")
}

const (
	stdoutFieldBytes = len(`,"stdout":`)
	stderrFieldBytes = len(`,"stderr":`)
	jsonStringQuotes = 2
)

// fitExecuteOutput divides the available encoded-response bytes fairly between
// stdout and stderr. The returned prefixes are valid UTF-8 and their exact JSON
// representation, including field names and quotes, never exceeds available.
func fitExecuteOutput(stdout, stderr string, available int) (string, string) {
	type output struct {
		value     string
		fieldSize int
		fullSize  int
		budget    int
		isStdout  bool
	}
	outputs := make([]output, 0, 2)
	if stdout != "" {
		outputs = append(outputs, output{value: stdout, fieldSize: stdoutFieldBytes, isStdout: true})
	}
	if stderr != "" {
		outputs = append(outputs, output{value: stderr, fieldSize: stderrFieldBytes})
	}
	if len(outputs) == 0 {
		return "", ""
	}
	fixed := 0
	for index := range outputs {
		fixed += outputs[index].fieldSize + jsonStringQuotes
	}
	contentBudget := available - fixed
	if contentBudget <= 0 {
		return "", ""
	}
	for index := range outputs {
		outputs[index].fullSize = jsonEscapedContentSize(outputs[index].value, contentBudget)
	}
	if len(outputs) == 1 {
		outputs[0].budget = min(outputs[0].fullSize, contentBudget)
	} else {
		half := contentBudget / 2
		outputs[0].budget = min(outputs[0].fullSize, half)
		outputs[1].budget = min(outputs[1].fullSize, half)
		remaining := contentBudget - outputs[0].budget - outputs[1].budget
		if outputs[0].budget < outputs[0].fullSize {
			added := min(outputs[0].fullSize-outputs[0].budget, remaining)
			outputs[0].budget += added
			remaining -= added
		}
		if outputs[1].budget < outputs[1].fullSize {
			outputs[1].budget += min(outputs[1].fullSize-outputs[1].budget, remaining)
		}
	}

	prefixes := [2]string{}
	for index := range outputs {
		prefixes[index], _ = jsonPrefix(outputs[index].value, outputs[index].budget)
	}
	if len(outputs) == 1 {
		if outputs[0].isStdout {
			return prefixes[0], ""
		}
		return "", prefixes[0]
	}
	return prefixes[0], prefixes[1]
}

// jsonEscapedContentSize mirrors encoding/json's default string escaping. It
// stops once the result is known to exceed limit, avoiding integer overflow and
// needless scanning of output that cannot fit in one protocol frame.
func jsonEscapedContentSize(value string, limit int) int {
	size := 0
	for _, character := range value {
		size += jsonRuneSize(character)
		if size > limit {
			return limit + 1
		}
	}
	return size
}

func jsonPrefix(value string, budget int) (string, int) {
	end := 0
	used := 0
	for offset, character := range value {
		cost := jsonRuneSize(character)
		if used+cost > budget {
			break
		}
		used += cost
		end = offset + utf8.RuneLen(character)
	}
	return value[:end], used
}

func jsonRuneSize(character rune) int {
	switch character {
	case '\b', '\f', '\n', '\r', '\t', '"', '\\':
		return 2
	case '<', '>', '&', '\u2028', '\u2029':
		return 6
	}
	if character < 0x20 {
		return 6
	}
	return utf8.RuneLen(character)
}

func protocolServiceError(requestID string, err error) Response {
	var coded interface{ Code() model.ErrorCode }
	if errors.As(err, &coded) {
		return protocolError(requestID, string(coded.Code()), "broker request failed")
	}
	return protocolError(requestID, ErrorUnavailable, "broker request unavailable")
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
			_ = server.remove(server.path)
		}
	}
}

func validatePrivateSocketParent(path string) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o700 || !sameOwner(parentInfo) {
		return ErrUnsafeSocket
	}
	return nil
}

func (server *Server) prepareSocketPath() error {
	path := server.path
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !sameOwner(info) || info.Mode().Perm() != 0o600 {
		return ErrUnsafeSocket
	}
	connection, dialErr := server.dial("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return ErrSocketInUse
	}
	if !isConnectionRefused(dialErr) {
		return ErrSocketOperation
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return ErrSocketInUse
	}
	if err := server.remove(path); err != nil {
		return ErrSocketOperation
	}
	return nil
}

func (server *Server) listenPrivateUnix() (net.Listener, os.FileInfo, error) {
	listener, err := server.listen("unix", server.path)
	if err != nil {
		return nil, nil, ErrSocketOperation
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		_ = server.remove(server.path)
		return nil, nil, ErrSocketOperation
	}
	unixListener.SetUnlinkOnClose(false)
	if err := os.Chmod(server.path, 0o600); err != nil {
		_ = listener.Close()
		_ = server.remove(server.path)
		return nil, nil, ErrSocketOperation
	}
	info, err := os.Lstat(server.path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 || !sameOwner(info) {
		_ = listener.Close()
		_ = server.remove(server.path)
		return nil, nil, ErrUnsafeSocket
	}
	return listener, info, nil
}

func setPermanentPrivateUmask() {
	umaskMu.Lock()
	syscall.Umask(0o077)
	umaskMu.Unlock()
}

func acquireStartupLock(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !safeLockInfo(info) {
			return nil, ErrUnsafeSocket
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrSocketOperation
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if info, inspectErr := os.Lstat(path); inspectErr == nil && !safeLockInfo(info) {
			return nil, ErrUnsafeSocket
		}
		return nil, ErrSocketOperation
	}
	info, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !safeLockInfo(info) || !safeLockInfo(pathInfo) || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, ErrUnsafeSocket
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSocketInUse
		}
		return nil, ErrSocketOperation
	}
	return file, nil
}

func releaseStartupLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func safeLockInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && sameOwner(info)
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
