package broker

import (
	"context"
	"encoding/json"
	"errors"
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
		var response Response
		decoder := json.NewDecoder(ioLimitReader(connection, MaxFrameBytes+1))
		err := decoder.Decode(&response)
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
		if read.err != nil {
			return ErrUnavailable
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

type limitedReader struct {
	reader net.Conn
	left   int64
}

func ioLimitReader(reader net.Conn, limit int64) *limitedReader {
	return &limitedReader{reader: reader, left: limit}
}

func (reader *limitedReader) Read(buffer []byte) (int, error) {
	if reader.left <= 0 {
		return 0, errors.New("response frame too large")
	}
	if int64(len(buffer)) > reader.left {
		buffer = buffer[:reader.left]
	}
	count, err := reader.reader.Read(buffer)
	reader.left -= int64(count)
	return count, err
}
