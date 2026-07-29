package app_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/taotecode/aegis-ssh/internal/app"
)

type fakeTerminal struct {
	visible       bytes.Buffer
	secretAnswers [][]byte
	lineAnswers   []string
	secretReads   int
	visibleReads  int
	closed        bool
}

func newFakeTerminal(secret string) *fakeTerminal {
	return &fakeTerminal{secretAnswers: [][]byte{[]byte(secret)}}
}

func (terminal *fakeTerminal) Write(data []byte) (int, error) {
	return terminal.visible.Write(data)
}

func (terminal *fakeTerminal) ReadPassword() ([]byte, error) {
	terminal.secretReads++
	if len(terminal.secretAnswers) == 0 {
		return nil, io.EOF
	}
	answer := append([]byte(nil), terminal.secretAnswers[0]...)
	terminal.secretAnswers = terminal.secretAnswers[1:]
	return answer, nil
}

func (terminal *fakeTerminal) ReadLine() (string, error) {
	terminal.visibleReads++
	if len(terminal.lineAnswers) == 0 {
		return "", io.EOF
	}
	answer := terminal.lineAnswers[0]
	terminal.lineAnswers = terminal.lineAnswers[1:]
	return answer, nil
}

func (terminal *fakeTerminal) Close() error {
	terminal.closed = true
	return nil
}

func TestSecretPromptUsesHiddenReadAndNeverEchoesAnswer(t *testing.T) {
	terminal := newFakeTerminal("master secret\r\n")
	got, err := app.ReadSecret(terminal, "Master password: ")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Zero(got)
	if string(got) != "master secret" {
		t.Fatalf("ReadSecret() = %q", got)
	}
	if terminal.secretReads != 1 || terminal.visibleReads != 0 {
		t.Fatalf("reads: hidden=%d visible=%d", terminal.secretReads, terminal.visibleReads)
	}
	visible := terminal.visible.String()
	if !strings.Contains(visible, "Master password: ") || strings.Contains(visible, "master secret") {
		t.Fatalf("visible terminal output = %q", visible)
	}
}

func TestSecretPromptRejectsEmptyInput(t *testing.T) {
	terminal := newFakeTerminal("\n")
	got, err := app.ReadSecret(terminal, "Password: ")
	if !errors.Is(err, app.ErrEmptySecret) || got != nil {
		t.Fatalf("ReadSecret() = %q, %v", got, err)
	}
}

func TestVisiblePromptDoesNotUseHiddenReader(t *testing.T) {
	terminal := &fakeTerminal{lineAnswers: []string{"  prod  \n"}}
	got, err := app.ReadText(terminal, "Alias: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "prod" || terminal.visibleReads != 1 || terminal.secretReads != 0 {
		t.Fatalf("ReadText() = %q, reads hidden=%d visible=%d", got, terminal.secretReads, terminal.visibleReads)
	}
}

func TestConfirmationRequiresExactExpectedText(t *testing.T) {
	terminal := &fakeTerminal{lineAnswers: []string{"yes\n", "CONFIRM\n"}}
	confirmed, err := app.ConfirmExact(terminal, "Type CONFIRM: ", "CONFIRM")
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("non-matching confirmation was accepted")
	}
	confirmed, err = app.ConfirmExact(terminal, "Type CONFIRM: ", "CONFIRM")
	if err != nil || !confirmed {
		t.Fatalf("matching confirmation = %v, %v", confirmed, err)
	}
}
