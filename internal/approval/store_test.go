package approval

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

const testApprovalCodeCharacters = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func deterministicReader() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func newTestStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	return NewStore(func() time.Time { return *now }, deterministicReader())
}

func TestApprovalIsBoundAndSingleUse(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	command := []byte("sudo systemctl restart api")
	categories := []policy.Category{policy.CloudCredential, policy.SSHSecret, policy.CloudCredential}
	created, err := store.Create("prod", command, categories)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.ID) != 32 || len(created.Code) != 4 {
		t.Fatalf("unexpected id/code lengths: %d/%d", len(created.ID), len(created.Code))
	}
	if !created.CreatedAt.Equal(now) || !created.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("unexpected approval lifetime: %v to %v", created.CreatedAt, created.ExpiresAt)
	}
	for _, r := range created.Code {
		if !strings.ContainsRune(testApprovalCodeCharacters, r) {
			t.Fatalf("code contains ambiguous character %q", r)
		}
	}
	if strings.ContainsAny(created.Code, "ILO01") {
		t.Fatalf("code contains explicitly forbidden ambiguous character: %q", created.Code)
	}
	command[0] = 'X'
	categories[0] = policy.PrivateKey
	created.Command[0] = 'Z'
	created.Categories[0] = policy.PrivateKey
	consumed, err := store.Consume(created.ID, created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ServerAlias != "prod" || string(consumed.Command) != "sudo systemctl restart api" {
		t.Fatalf("approval was not bound: %#v", consumed)
	}
	if len(consumed.Categories) != 2 || consumed.Categories[0] != policy.CloudCredential || consumed.Categories[1] != policy.SSHSecret {
		t.Fatalf("categories were not sorted/deduplicated: %#v", consumed.Categories)
	}
	consumed.Command[0] = 'Y'
	consumed.Categories[0] = policy.PrivateKey
	again, err := store.Consume(created.ID, created.Code)
	if !errors.Is(err, ErrUsed) || again.ID != "" {
		t.Fatalf("second consume = %#v, %v; want ErrUsed", again, err)
	}
}

func TestApprovalExpires(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("echo ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrExpired) {
		t.Fatalf("consume after ttl = %v; want ErrExpired", err)
	}
}

func TestExpiredApprovalTakesPriorityAndIsRemoved(t *testing.T) {
	t.Run("wrong code", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("prod", []byte("echo ok"), nil)
		if err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		if _, err := store.Consume(created.ID, "AAAA"); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired approval with wrong code = %v; want ErrExpired", err)
		}
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrNotFound) {
			t.Fatalf("consume after expiry cleanup = %v; want ErrNotFound", err)
		}
	})

	t.Run("already used", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("prod", []byte("echo ok"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Consume(created.ID, created.Code); err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired used approval = %v; want ErrExpired", err)
		}
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrNotFound) {
			t.Fatalf("consume after expiry cleanup = %v; want ErrNotFound", err)
		}
	})
}

func TestWrongCodeDoesNotConsumeApproval(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("echo ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(created.ID, "AAAA"); !errors.Is(err, ErrCode) {
		t.Fatalf("wrong code = %v; want ErrCode", err)
	}
	if _, err := store.Consume(created.ID, created.Code+"X"); !errors.Is(err, ErrCode) {
		t.Fatalf("wrong-length code = %v; want ErrCode", err)
	}
	if _, err := store.Consume(created.ID, created.Code); err != nil {
		t.Fatalf("correct code after wrong code = %v", err)
	}
}

func TestDuplicateRandomIDDoesNotOverwrite(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("first", []byte("echo first"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("second", []byte("echo second"), nil); !errors.Is(err, ErrRandom) {
		t.Fatalf("duplicate id = %v; want ErrRandom", err)
	}
	consumed, err := store.Consume(created.ID, created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ServerAlias != "first" || string(consumed.Command) != "echo first" {
		t.Fatalf("duplicate random id overwrote approval: %#v", consumed)
	}
}

func TestCreateCleansExpiredApprovalsBeforeEarlyReturn(t *testing.T) {
	t.Run("random failure", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("first", []byte("echo first"), nil)
		if err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		store.random = bytes.NewReader(nil)
		if _, err := store.Create("second", []byte("echo second"), nil); !errors.Is(err, ErrRandom) {
			t.Fatalf("create with failed random source = %v; want ErrRandom", err)
		}
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired approval after failed create = %v; want ErrNotFound", err)
		}
	})

	t.Run("expired id collision", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("first", []byte("echo first"), nil)
		if err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		store.random = deterministicReader()
		replacement, err := store.Create("second", []byte("echo second"), nil)
		if err != nil {
			t.Fatalf("reuse id after expiry = %v", err)
		}
		if replacement.ID != created.ID {
			t.Fatalf("replacement id = %q; want collision id %q", replacement.ID, created.ID)
		}
		consumed, err := store.Consume(replacement.ID, replacement.Code)
		if err != nil {
			t.Fatal(err)
		}
		if consumed.ServerAlias != "second" || string(consumed.Command) != "echo second" {
			t.Fatalf("consume replacement = %#v", consumed)
		}
	})
}

func TestApprovalConcurrentConsumeOnlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("echo ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume(created.ID, created.Code); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful consumes = %d; want 1", successes)
	}
}

func TestApprovalInputValidationAndRandomFailure(t *testing.T) {
	if _, err := NewStore(nil, deterministicReader()).Create("prod", []byte("echo ok"), nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil clock = %v; want ErrInvalidInput", err)
	}
	if _, err := NewStore(time.Now, nil).Create("prod", []byte("echo ok"), nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil random = %v; want ErrInvalidInput", err)
	}
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	for _, tc := range []struct {
		alias string
		cmd   []byte
	}{
		{"", []byte("echo ok")},
		{"prod", nil},
		{"prod", []byte{}},
	} {
		if _, err := store.Create(tc.alias, tc.cmd, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Create(%q, %q) = %v; want ErrInvalidInput", tc.alias, tc.cmd, err)
		}
	}
	broken := NewStore(fixedClock(now), bytes.NewReader(nil))
	if _, err := broken.Create("prod", []byte("echo ok"), nil); !errors.Is(err, ErrRandom) {
		t.Fatalf("random failure = %v; want ErrRandom", err)
	}
}
