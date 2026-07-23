package broker

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	ProtocolVersion = "1"
	MaxFrameBytes   = 1 << 20

	ErrorInvalidRequest = "invalid_request"
	ErrorMethodNotFound = "method_not_found"
	ErrorFrameTooLarge  = "frame_too_large"
	ErrorInternal       = "internal_error"
	ErrorUnavailable    = "unavailable"
)

var (
	ErrSocketInUse     = errors.New("broker socket already in use")
	ErrUnsafeSocket    = errors.New("unsafe broker socket path")
	ErrFrameTooLarge   = errors.New("broker request frame too large")
	ErrInvalidProtocol = errors.New("invalid broker protocol request")
)

type Request struct {
	Version   string          `json:"version"`
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version   string          `json:"version"`
	RequestID string          `json:"request_id"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (err *RPCError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

func protocolError(requestID, code, message string) Response {
	return Response{Version: ProtocolVersion, RequestID: requestID, Error: &RPCError{Code: code, Message: message}}
}
