package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync/atomic"

	"github.com/chenjw/aegis-ssh/internal/model"
)

var ErrUnavailable = model.ErrUnavailableDaemon

type Client struct {
	path     string
	sequence atomic.Uint64
}

func NewClient(path string) *Client { return &Client{path: path} }

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
	if _, err := connection.Write(requestBytes); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	readResult := make(chan struct {
		response Response
		err      error
	}, 1)
	go func() {
		response, err := readResponseFrame(connection)
		readResult <- struct {
			response Response
			err      error
		}{response, err}
	}()
	select {
	case <-ctx.Done():
		_ = connection.Close()
		return ctx.Err()
	case read := <-readResult:
		if err := ctx.Err(); err != nil {
			return err
		}
		if read.err != nil {
			return read.err
		}
		if read.response.Error != nil {
			return read.response.Error
		}
		if read.response.RequestID != requestID || read.response.Version != ProtocolVersion {
			return errors.New("invalid broker response")
		}
		return json.Unmarshal(read.response.Result, result)
	}
}

func readResponseFrame(connection net.Conn) (Response, error) {
	reader := bufio.NewReader(io.LimitReader(connection, MaxFrameBytes+2))
	line, err := reader.ReadBytes('\n')
	hasNewline := len(line) != 0 && line[len(line)-1] == '\n'
	contentBytes := len(line)
	if hasNewline {
		contentBytes--
	}
	if contentBytes > MaxFrameBytes {
		return Response{}, ErrFrameTooLarge
	}
	if err != nil || !hasNewline {
		return Response{}, ErrInvalidProtocol
	}
	if _, err := reader.ReadByte(); err == nil {
		return Response{}, ErrInvalidProtocol
	} else if !errors.Is(err, io.EOF) {
		return Response{}, ErrInvalidProtocol
	}

	var response Response
	if json.Unmarshal(line[:contentBytes], &response) != nil {
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
