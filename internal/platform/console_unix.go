//go:build darwin || linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

type ttyConsole struct {
	file   *os.File
	reader *bufio.Reader
}

func openConsole() (Console, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty: %w", ErrNoConsole)
	}
	return &ttyConsole{file: file, reader: bufio.NewReader(file)}, nil
}

func (c *ttyConsole) Write(data []byte) (int, error) {
	return c.file.Write(data)
}

func (c *ttyConsole) ReadPassword() ([]byte, error) {
	value, err := term.ReadPassword(int(c.file.Fd()))
	if errors.Is(err, os.ErrInvalid) {
		return nil, ErrNoConsole
	}
	return value, err
}

func (c *ttyConsole) ReadLine() (string, error) {
	return c.reader.ReadString('\n')
}

func (c *ttyConsole) Close() error {
	return c.file.Close()
}
