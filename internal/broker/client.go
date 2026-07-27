package broker

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"time"

	"github.com/chenjw/aegis-ssh/internal/model"
)

var ErrUnavailable = model.ErrUnavailableDaemon

type Client struct {
	path         string
	sequence     atomic.Uint64
	writeTimeout time.Duration
	readTimeout  time.Duration
}

const (
	defaultWriteTimeout = 5 * time.Second
	defaultReadTimeout  = 31 * time.Minute
)

func NewClient(path string) *Client {
	return &Client{path: path, writeTimeout: defaultWriteTimeout, readTimeout: defaultReadTimeout}
}

func (client *Client) Status(ctx context.Context) (model.BrokerStatus, error) {
	var result model.BrokerStatus
	err := client.call(ctx, "status", nil, &result)
	return result, err
}

func (client *Client) ListServers(ctx context.Context) ([]model.ServerSummary, error) {
	var result []model.ServerSummary
	err := client.call(ctx, "list_servers", nil, &result)
	return result, err
}

func (client *Client) Execute(ctx context.Context, request model.ExecuteRequest) (model.ExecuteResult, error) {
	var result model.ExecuteResult
	err := client.call(ctx, "execute", request, &result)
	return result, err
}

func (client *Client) ExecuteApproved(ctx context.Context, request model.ApprovedRequest) (model.ExecuteResult, error) {
	var result model.ExecuteResult
	err := client.call(ctx, "execute_approved", request, &result)
	return result, err
}

func (client *Client) call(ctx context.Context, method string, params any, result any) error {
	if client == nil || client.path == "" {
		return ErrInvalidProtocol
	}
	if ctx == nil {
		return model.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	requestID := client.nextID()
	paramBytes, err := json.Marshal(params)
	if params == nil {
		paramBytes = nil
	}
	if err != nil {
		return err
	}
	requestBytes, err := json.Marshal(Request{Version: ProtocolVersion, RequestID: requestID, Method: method, Params: paramBytes})
	if err != nil {
		return err
	}
	if len(requestBytes) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", client.path)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	defer connection.Close()
	stopContextWatch := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopContextWatch()
	requestBytes = append(requestBytes, '\n')
	contextDeadline, hasContextDeadline := ctx.Deadline()
	writeDeadline := phaseDeadline(contextDeadline, hasContextDeadline, client.writeTimeout)
	if err := connection.SetWriteDeadline(writeDeadline); err != nil {
		return ErrUnavailable
	}
	if err := writeAll(connection, requestBytes); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if hasContextDeadline && !time.Now().Before(contextDeadline) {
			return context.DeadlineExceeded
		}
		return ErrUnavailable
	}
	_ = connection.SetWriteDeadline(time.Time{})
	readDeadline := phaseDeadline(contextDeadline, hasContextDeadline, client.readTimeout)
	if err := connection.SetReadDeadline(readDeadline); err != nil {
		return ErrInvalidProtocol
	}
	response, err := readResponseFrame(connection, readDeadline)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if hasContextDeadline && !time.Now().Before(contextDeadline) {
			return context.DeadlineExceeded
		}
		return err
	}
	if response.RequestID != requestID || response.Version != ProtocolVersion {
		return ErrInvalidProtocol
	}
	hasResult := len(response.Result) != 0 && string(response.Result) != "null"
	hasError := response.Error != nil
	if hasResult == hasError {
		return ErrInvalidProtocol
	}
	if hasError {
		if canonical := model.ErrorForCode(model.ErrorCode(response.Error.Code)); canonical != nil {
			return canonical
		}
		return response.Error
	}
	if decodeStrictJSON(response.Result, result) != nil {
		return ErrInvalidProtocol
	}
	return nil
}

func readResponseFrame(connection net.Conn, deadline time.Time) (Response, error) {
	line, err := readSingleFrame(connection, deadline)
	if err != nil {
		return Response{}, err
	}
	var response Response
	if decodeStrictJSON(line, &response) != nil {
		return Response{}, ErrInvalidProtocol
	}
	return response, nil
}

func (client *Client) nextID() string {
	return "client-" + formatUint(client.sequence.Add(1))
}

func formatUint(value uint64) string {
	const alphabet = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value != 0 {
		index--
		buffer[index] = alphabet[value%10]
		value /= 10
	}
	return string(buffer[index:])
}
