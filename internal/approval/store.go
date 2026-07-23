package approval

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

const defaultTTL = 5 * time.Minute

var (
	ErrInvalidInput = errors.New("invalid approval input")
	ErrRandom       = errors.New("approval random source failure")
	ErrNotFound     = errors.New("approval not found")
	ErrCode         = errors.New("invalid approval code")
	ErrUsed         = errors.New("approval already used")
	ErrExpired      = errors.New("approval expired")
)

// Approval is a snapshot of an approval request. Command and Categories are
// copied on input and output, so callers cannot mutate store-owned state.
type Approval struct {
	ID          string
	Code        string
	ServerAlias string
	Command     []byte
	Categories  []policy.Category
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Used        bool
}

type storedApproval struct {
	Approval
	used bool
}

type Store struct {
	mu     sync.Mutex
	now    func() time.Time
	random io.Reader
	items  map[string]storedApproval
}

// NewStore creates an in-memory approval store. Both dependencies are
// required so construction and use never panic due to nil callbacks.
func NewStore(now func() time.Time, random io.Reader) *Store {
	return &Store{now: now, random: random, items: make(map[string]storedApproval)}
}

// Create records a single-use approval with the default five-minute TTL.
func (s *Store) Create(serverAlias string, command []byte, categories []policy.Category) (Approval, error) {
	if s == nil || s.now == nil || s.random == nil || serverAlias == "" || len(command) == 0 {
		return Approval{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked("")

	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.random, idBytes); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	codeBytes := make([]byte, 4)
	if _, err := io.ReadFull(s.random, codeBytes); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	id := hex.EncodeToString(idBytes)
	code := makeCode(codeBytes)
	if _, exists := s.items[id]; exists {
		return Approval{}, fmt.Errorf("%w: duplicate approval id", ErrRandom)
	}
	createdAt := s.now()
	approval := Approval{
		ID:          id,
		Code:        code,
		ServerAlias: serverAlias,
		Command:     append([]byte(nil), command...),
		Categories:  normalizeCategories(categories),
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt.Add(defaultTTL),
	}
	s.items[id] = storedApproval{Approval: cloneApproval(approval)}
	return cloneApproval(approval), nil
}

// Consume validates and atomically marks an approval as used.
func (s *Store) Consume(id, code string) (Approval, error) {
	if s == nil || s.now == nil || s.random == nil || id == "" || code == "" {
		return Approval{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep the requested entry until it is inspected, so the first consume at
	// its expiry reports ErrExpired instead of looking like an unknown ID.
	s.cleanupLocked(id)
	item, ok := s.items[id]
	if !ok {
		return Approval{}, ErrNotFound
	}
	if item.used {
		return Approval{}, ErrUsed
	}
	var supplied [4]byte
	copy(supplied[:], code)
	codeMatch := subtle.ConstantTimeCompare([]byte(item.Code), supplied[:])
	lengthMatch := subtle.ConstantTimeEq(int32(len(code)), int32(len(item.Code)))
	if codeMatch != 1 || lengthMatch != 1 {
		return Approval{}, ErrCode
	}
	if !s.now().Before(item.ExpiresAt) {
		delete(s.items, id)
		return Approval{}, ErrExpired
	}
	item.used = true
	item.Approval.Used = true
	s.items[id] = item
	return cloneApproval(item.Approval), nil
}

func (s *Store) cleanupLocked(except string) {
	now := s.now()
	for id, item := range s.items {
		if id != except && !now.Before(item.ExpiresAt) {
			delete(s.items, id)
		}
	}
}

const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func makeCode(raw []byte) string {
	code := make([]byte, len(raw))
	for i, value := range raw {
		code[i] = codeAlphabet[int(value)%len(codeAlphabet)]
	}
	return string(code)
}

func normalizeCategories(categories []policy.Category) []policy.Category {
	if len(categories) == 0 {
		return nil
	}
	result := append([]policy.Category(nil), categories...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	unique := result[:0]
	for _, category := range result {
		if len(unique) == 0 || unique[len(unique)-1] != category {
			unique = append(unique, category)
		}
	}
	return append([]policy.Category(nil), unique...)
}

func cloneApproval(approval Approval) Approval {
	approval.Command = append([]byte(nil), approval.Command...)
	approval.Categories = append([]policy.Category(nil), approval.Categories...)
	return approval
}
