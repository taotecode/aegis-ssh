package approval

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

const testApprovalCodeCharacters = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	testApprovalCapacity = 256
	testMaxCommandBytes  = 128 << 10
)

var testExecutionLimits = ExecutionLimits{Timeout: 30 * time.Second, MaxOutputBytes: 1 << 20}

func deterministicReader() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
}

func uniqueApprovalReader(count int) io.Reader {
	data := make([]byte, 0, count*20)
	for i := 0; i < count; i++ {
		id := make([]byte, 16)
		binary.BigEndian.PutUint64(id[8:], uint64(i+1))
		data = append(data, id...)
		data = append(data, 2, 3, 4, 5)
	}
	return bytes.NewReader(data)
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
	created, err := store.Create("prod", command, categories, testExecutionLimits)
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
	created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrExpired) {
		t.Fatalf("consume after ttl = %v; want ErrExpired", err)
	}
}

func TestExpiredApprovalRemovalZerosCommandBacking(t *testing.T) {
	t.Run("direct consume", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("prod", []byte("cat /root/.ssh/id_rsa"), nil, testExecutionLimits)
		if err != nil {
			t.Fatal(err)
		}
		commandBacking := store.items[created.ID].Command
		now = created.ExpiresAt
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrExpired) {
			t.Fatalf("Consume() = %v, want ErrExpired", err)
		}
		if !bytes.Equal(commandBacking, make([]byte, len(commandBacking))) {
			t.Fatalf("expired command backing was not zeroed: %q", commandBacking)
		}
	})

	t.Run("opportunistic cleanup", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("prod", []byte("cat /root/.ssh/id_rsa"), nil, testExecutionLimits)
		if err != nil {
			t.Fatal(err)
		}
		commandBacking := store.items[created.ID].Command
		now = created.ExpiresAt
		if _, err := store.Create("other", []byte("uptime"), nil, testExecutionLimits); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(commandBacking, make([]byte, len(commandBacking))) {
			t.Fatalf("cleaned command backing was not zeroed: %q", commandBacking)
		}
	})
}

func TestExpiredApprovalTakesPriorityAndIsRemoved(t *testing.T) {
	t.Run("wrong code", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
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
		created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
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
	created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
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
	created, err := store.Create("first", []byte("echo first"), nil, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("second", []byte("echo second"), nil, testExecutionLimits); !errors.Is(err, ErrRandom) {
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
		created, err := store.Create("first", []byte("echo first"), nil, testExecutionLimits)
		if err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		store.random = bytes.NewReader(nil)
		if _, err := store.Create("second", []byte("echo second"), nil, testExecutionLimits); !errors.Is(err, ErrRandom) {
			t.Fatalf("create with failed random source = %v; want ErrRandom", err)
		}
		if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired approval after failed create = %v; want ErrNotFound", err)
		}
	})

	t.Run("expired id collision", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		store := newTestStore(t, &now)
		created, err := store.Create("first", []byte("echo first"), nil, testExecutionLimits)
		if err != nil {
			t.Fatal(err)
		}
		now = created.ExpiresAt
		store.random = deterministicReader()
		replacement, err := store.Create("second", []byte("echo second"), nil, testExecutionLimits)
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

func TestApprovalStoreCapacityIncludesUsedTombstonesAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now }, uniqueApprovalReader(testApprovalCapacity+1))
	var first Approval
	for i := 0; i < testApprovalCapacity; i++ {
		created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
		if err != nil {
			t.Fatalf("create approval %d: %v", i, err)
		}
		if i == 0 {
			first = created
		}
	}
	if _, err := store.Consume(first.ID, first.Code); err != nil {
		t.Fatalf("consume first approval: %v", err)
	}
	if _, err := store.Create("overflow", []byte("echo overflow"), nil, testExecutionLimits); !errors.Is(err, ErrCapacity) {
		t.Fatalf("create beyond capacity = %v; want ErrCapacity", err)
	}
	if len(store.items) != testApprovalCapacity {
		t.Fatalf("store size after rejected create = %d; want %d", len(store.items), testApprovalCapacity)
	}
	if _, err := store.Consume(first.ID, first.Code); !errors.Is(err, ErrUsed) {
		t.Fatalf("used approval after rejected create = %v; want ErrUsed", err)
	}

	now = first.ExpiresAt
	created, err := store.Create("after-expiry", []byte("echo ready"), nil, testExecutionLimits)
	if err != nil {
		t.Fatalf("create after expiry cleanup: %v", err)
	}
	if len(store.items) != 1 || created.ServerAlias != "after-expiry" {
		t.Fatalf("store after expiry cleanup = %d items, approval %#v", len(store.items), created)
	}
}

func TestApprovalCommandSizeLimit(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	if _, err := store.Create("prod", bytes.Repeat([]byte{'x'}, testMaxCommandBytes+1), nil, testExecutionLimits); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized command = %v; want ErrInvalidInput", err)
	}
	store = newTestStore(t, &now)
	if _, err := store.Create("prod", bytes.Repeat([]byte{'x'}, testMaxCommandBytes), nil, testExecutionLimits); err != nil {
		t.Fatalf("command at size limit = %v", err)
	}
}

func TestConsumeCompactsStoredApproval(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("sudo cat /root/.ssh/id_rsa"), []policy.Category{policy.PrivateKey, policy.SSHSecret}, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := store.Consume(created.ID, created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ServerAlias != "prod" || string(consumed.Command) != "sudo cat /root/.ssh/id_rsa" || len(consumed.Categories) != 2 || consumed.Code != created.Code {
		t.Fatalf("consume returned incomplete approval: %#v", consumed)
	}
	stored := store.items[created.ID]
	if !stored.used || stored.ID != created.ID || !stored.ExpiresAt.Equal(created.ExpiresAt) {
		t.Fatalf("invalid used tombstone: %#v", stored)
	}
	if stored.Code != "" || stored.ServerAlias != "" || stored.Command != nil || stored.Categories != nil || !stored.CreatedAt.IsZero() {
		t.Fatalf("used tombstone retained approval payload: %#v", stored)
	}
}

func TestApprovalCodeUsesRejectionSampling(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	id := bytes.Repeat([]byte{0x42}, 16)
	random := bytes.NewReader(append(append([]byte(nil), id...), 248, 255, 0, 1, 2, 3))
	store := NewStore(fixedClock(now), random)
	created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	if created.Code != "ABCD" {
		t.Fatalf("code after rejected high bytes = %q; want ABCD", created.Code)
	}

	random = bytes.NewReader(append(append([]byte(nil), id...), 248, 249, 250, 255))
	store = NewStore(fixedClock(now), random)
	if _, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits); !errors.Is(err, ErrRandom) {
		t.Fatalf("exhausted rejection source = %v; want ErrRandom", err)
	}
}

func TestApprovalConcurrentConsumeOnlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
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
	if _, err := NewStore(nil, deterministicReader()).Create("prod", []byte("echo ok"), nil, testExecutionLimits); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil clock = %v; want ErrInvalidInput", err)
	}
	if _, err := NewStore(time.Now, nil).Create("prod", []byte("echo ok"), nil, testExecutionLimits); !errors.Is(err, ErrInvalidInput) {
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
		if _, err := store.Create(tc.alias, tc.cmd, nil, testExecutionLimits); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Create(%q, %q) = %v; want ErrInvalidInput", tc.alias, tc.cmd, err)
		}
	}
	broken := NewStore(fixedClock(now), bytes.NewReader(nil))
	if _, err := broken.Create("prod", []byte("echo ok"), nil, testExecutionLimits); !errors.Is(err, ErrRandom) {
		t.Fatalf("random failure = %v; want ErrRandom", err)
	}
}

func TestApprovalBindsExecutionLimitsAndCompactsThemAfterConsume(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	limits := ExecutionLimits{Timeout: time.Second, MaxOutputBytes: 4 << 10}
	created, err := store.Create("prod", []byte("ip route"), []policy.Category{policy.NetworkIdentity}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if created.Limits != limits {
		t.Fatalf("created limits = %+v, want %+v", created.Limits, limits)
	}
	consumed, err := store.Consume(created.ID, created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Limits != limits {
		t.Fatalf("consumed limits = %+v, want %+v", consumed.Limits, limits)
	}
	stored := store.items[created.ID]
	if stored.Limits != (ExecutionLimits{}) {
		t.Fatalf("used tombstone retained limits: %+v", stored.Limits)
	}
}

func TestApprovalRejectsUnsafeExecutionLimits(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	for _, limits := range []ExecutionLimits{
		{},
		{Timeout: -time.Second, MaxOutputBytes: 1},
		{Timeout: 30*time.Minute + time.Nanosecond, MaxOutputBytes: 1},
		{Timeout: time.Second, MaxOutputBytes: -1},
		{Timeout: time.Second, MaxOutputBytes: (4 << 20) + 1},
	} {
		store := newTestStore(t, &now)
		if _, err := store.Create("prod", []byte("echo ok"), nil, limits); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Create(limits=%+v) = %v, want ErrInvalidInput", limits, err)
		}
	}
}

func TestApprovalRevokeZerosPayloadAndIsConservativelyIdempotent(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("cat /root/.ssh/id_rsa"), []policy.Category{policy.PrivateKey}, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	commandBacking := store.items[created.ID].Command
	if err := store.Revoke(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, exists := store.items[created.ID]; exists {
		t.Fatal("revoked approval remains stored")
	}
	if !bytes.Equal(commandBacking, make([]byte, len(commandBacking))) {
		t.Fatalf("revoked command backing was not zeroed: %q", commandBacking)
	}
	if err := store.Revoke(created.ID); err != nil {
		t.Fatalf("second Revoke() = %v, want idempotent success", err)
	}
	if err := store.Revoke(""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Revoke(empty) = %v, want ErrInvalidInput", err)
	}
}

func TestApprovalRevokeRefusesUsedTombstone(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now)
	created, err := store.Create("prod", []byte("echo ok"), nil, testExecutionLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(created.ID, created.Code); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(created.ID); !errors.Is(err, ErrUsed) {
		t.Fatalf("Revoke(used) = %v, want ErrUsed", err)
	}
	if _, err := store.Consume(created.ID, created.Code); !errors.Is(err, ErrUsed) {
		t.Fatalf("used tombstone changed after revoke: %v", err)
	}
}
