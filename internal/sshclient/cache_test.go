package sshclient

import (
	"context"
	"testing"
	"time"

	"github.com/taotecode/aegis-ssh/internal/testssh"
)

func TestClientCachesAndClosesConnection(t *testing.T) {
	server := testssh.Start(t, "root", "password")
	client := New()
	limits := Limits{Timeout: time.Second, MaxOutputBytes: 1024}
	for range 2 {
		if _, err := client.Execute(context.Background(), server.Secret("root", "password"), "printf ok", limits); err != nil {
			t.Fatal(err)
		}
	}
	client.mu.Lock()
	cached := len(client.connections)
	client.mu.Unlock()
	if cached != 1 {
		t.Fatalf("cached connections=%d", cached)
	}
	client.Close()
	client.mu.Lock()
	cached = len(client.connections)
	client.mu.Unlock()
	if cached != 0 {
		t.Fatalf("cached connections after close=%d", cached)
	}
}
