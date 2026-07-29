package broker

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"
)

const initialFrameBufferBytes = 4 << 10

func readSingleFrame(connection net.Conn) ([]byte, error) {
	reader := bufio.NewReaderSize(connection, initialFrameBufferBytes)
	var frame []byte
	for {
		if len(frame) == MaxFrameBytes {
			last, err := reader.ReadByte()
			if err != nil {
				return nil, ErrInvalidProtocol
			}
			if last != '\n' {
				return nil, ErrFrameTooLarge
			}
			frame = append(frame, last)
			break
		}
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) != 0 {
			if len(frame)+len(fragment) > MaxFrameBytes+1 {
				return nil, ErrFrameTooLarge
			}
			frame = append(frame, fragment...)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(frame) > MaxFrameBytes {
				return nil, ErrFrameTooLarge
			}
			continue
		}
		if len(frame) > MaxFrameBytes {
			return nil, ErrFrameTooLarge
		}
		return nil, ErrInvalidProtocol
	}
	if len(frame) == 0 || frame[len(frame)-1] != '\n' {
		return nil, ErrInvalidProtocol
	}
	frame = frame[:len(frame)-1]
	if len(frame) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	if reader.Buffered() != 0 {
		return nil, ErrInvalidProtocol
	}
	_, err := reader.ReadByte()
	if err == nil {
		return nil, ErrInvalidProtocol
	}
	if errors.Is(err, io.EOF) {
		return frame, nil
	}
	return nil, ErrInvalidProtocol
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func phaseDeadline(ctxDeadline time.Time, hasContextDeadline bool, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if hasContextDeadline && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}
