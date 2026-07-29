package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/taotecode/aegis-ssh/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := app.New(app.Dependencies{}).Run(ctx, os.Args[1:])
	if err == nil {
		return
	}
	if errors.Is(err, app.ErrUsage) {
		fmt.Fprintln(os.Stderr, "invalid command; run aegis-ssh --help")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, sanitizedError(err))
	os.Exit(1)
}

func sanitizedError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, app.ErrStorage):
		return "secure local storage operation failed"
	case errors.Is(err, app.ErrDaemonUnavailable):
		return "broker daemon unavailable"
	case errors.Is(err, app.ErrSecretArgument), errors.Is(err, app.ErrSecretEnvironment):
		return "connection secrets must be entered interactively on the controlling terminal"
	default:
		return err.Error()
	}
}
