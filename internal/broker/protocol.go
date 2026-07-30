package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion   = "2"
	MaxFrameBytes     = 1 << 20
	maxRequestIDBytes = 128

	ErrorInvalidRequest = "invalid_request"
	ErrorMethodNotFound = "method_not_found"
	ErrorFrameTooLarge  = "frame_too_large"
	ErrorInternal       = "internal_error"
	ErrorUnavailable    = "unavailable"
)

var (
	ErrSocketInUse     = errors.New("broker socket already in use")
	ErrUnsafeSocket    = errors.New("unsafe broker socket path")
	ErrSocketOperation = errors.New("broker socket operation failed")
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

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidProtocol
		}
		return err
	}
	return nil
}
