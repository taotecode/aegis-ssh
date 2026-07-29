package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

var (
	ErrEmptySecret = errors.New("secret must not be empty")
	ErrNoTerminal  = errors.New("interactive terminal unavailable")
)

// Terminal keeps visible input and hidden password input on the controlling
// terminal instead of process stdin, which may be owned by an MCP client.
type Terminal interface {
	io.Writer
	ReadPassword() ([]byte, error)
	ReadLine() (string, error)
	Close() error
}

type ttyTerminal struct {
	file   *os.File
	reader *bufio.Reader
}

func OpenTerminal() (Terminal, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTerminal
	}
	return &ttyTerminal{file: file, reader: bufio.NewReader(file)}, nil
}

func (terminal *ttyTerminal) Write(data []byte) (int, error) {
	return terminal.file.Write(data)
}

func (terminal *ttyTerminal) ReadPassword() ([]byte, error) {
	return term.ReadPassword(int(terminal.file.Fd()))
}

func (terminal *ttyTerminal) ReadLine() (string, error) {
	return terminal.reader.ReadString('\n')
}

func (terminal *ttyTerminal) Close() error {
	return terminal.file.Close()
}

func ReadSecret(terminal Terminal, prompt string) ([]byte, error) {
	if terminal == nil {
		return nil, ErrNoTerminal
	}
	if _, err := io.WriteString(terminal, prompt); err != nil {
		return nil, fmt.Errorf("write prompt: %w", err)
	}
	secret, err := terminal.ReadPassword()
	_, newlineErr := io.WriteString(terminal, "\n")
	if err != nil {
		Zero(secret)
		return nil, fmt.Errorf("read secret: %w", err)
	}
	if newlineErr != nil {
		Zero(secret)
		return nil, fmt.Errorf("write prompt: %w", newlineErr)
	}
	secret = trimLineEnding(secret)
	if len(secret) == 0 {
		Zero(secret)
		return nil, ErrEmptySecret
	}
	return secret, nil
}

func ReadText(terminal Terminal, prompt string) (string, error) {
	if terminal == nil {
		return "", ErrNoTerminal
	}
	if _, err := io.WriteString(terminal, prompt); err != nil {
		return "", fmt.Errorf("write prompt: %w", err)
	}
	value, err := terminal.ReadLine()
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func ConfirmExact(terminal Terminal, prompt, expected string) (bool, error) {
	value, err := ReadText(terminal, prompt)
	if err != nil {
		return false, err
	}
	return value == expected, nil
}

func Zero(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

func trimLineEnding(data []byte) []byte {
	for len(data) > 0 {
		last := data[len(data)-1]
		if last != '\r' && last != '\n' {
			break
		}
		data = data[:len(data)-1]
	}
	return data
}
