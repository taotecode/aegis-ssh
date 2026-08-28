//go:build windows

package platform

import (
	"fmt"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

type winConsole struct {
	in   windows.Handle
	out  windows.Handle
	orig uint32
}

func openConsole() (Console, error) {
	in, err := windows.CreateFile(
		windows.StringToUTF16Ptr("CONIN$"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open CONIN$: %w", ErrNoConsole)
	}
	out, err := windows.CreateFile(
		windows.StringToUTF16Ptr("CONOUT$"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		_ = windows.CloseHandle(in)
		return nil, fmt.Errorf("open CONOUT$: %w", ErrNoConsole)
	}
	var mode uint32
	if err := windows.GetConsoleMode(in, &mode); err != nil {
		_ = windows.CloseHandle(in)
		_ = windows.CloseHandle(out)
		return nil, fmt.Errorf("read console mode: %w", ErrNoConsole)
	}
	c := &winConsole{in: in, out: out, orig: mode}
	// Disable ENABLE_ECHO_INPUT so typed passwords are not echoed; keep line
	// input so ReadConsole blocks until Enter is pressed.
	if err := windows.SetConsoleMode(in, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("set console mode: %w", ErrNoConsole)
	}
	return c, nil
}

func (c *winConsole) Write(data []byte) (int, error) {
	text := string(data)
	written := 0
	for len(text) > 0 {
		chunk := text
		if len(chunk) > 512 {
			chunk = chunk[:512]
		}
		units := utf16.Encode([]rune(chunk))
		var n uint32
		if err := windows.WriteConsole(c.out, &units[0], uint32(len(units)), &n, nil); err != nil {
			return written, err
		}
		written += len([]byte(chunk))
		text = text[len(chunk):]
	}
	return written, nil
}

func (c *winConsole) ReadPassword() ([]byte, error) {
	return c.readLine()
}

func (c *winConsole) ReadLine() (string, error) {
	line, err := c.readLine()
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func (c *winConsole) readLine() ([]byte, error) {
	var units []uint16
	var one [1]uint16
	for {
		var n uint32
		if err := windows.ReadConsole(c.in, &one[0], 1, &n, nil); err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		r := rune(one[0])
		if r == '\r' || r == '\n' {
			break
		}
		if r == 0x8 || r == 0x7f { // backspace
			if len(units) > 0 {
				units = units[:len(units)-1]
			}
			continue
		}
		units = append(units, one[0])
	}
	return []byte(string(utf16.Decode(units))), nil
}

func (c *winConsole) Close() error {
	if c.in != 0 {
		_ = windows.SetConsoleMode(c.in, c.orig)
		_ = windows.CloseHandle(c.in)
	}
	if c.out != 0 {
		_ = windows.CloseHandle(c.out)
	}
	c.in, c.out = 0, 0
	return nil
}
