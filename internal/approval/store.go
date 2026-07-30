package approval

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/taotecode/aegis-ssh/internal/policy"
)

const (
	defaultTTL       = 5 * time.Minute
	maxStoreEntries  = 256
	maxCommandBytes  = 128 << 10
	maxTimeout       = 30 * time.Minute
	maxOutputBytes   = int64(4 << 20)
	approvalCodeSize = 4
)

var (
	ErrInvalidInput = errors.New("invalid approval input")
	ErrCapacity     = errors.New("approval store capacity reached")
	ErrRandom       = errors.New("approval random source failure")
	ErrNotFound     = errors.New("approval not found")
	ErrCode         = errors.New("invalid approval code")
	ErrUsed         = errors.New("approval already used")
	ErrExpired      = errors.New("approval expired")
)

type ExecutionLimits struct {
	Timeout        time.Duration
	MaxOutputBytes int64
}

// Approval is a snapshot of an approval request. Command and Categories are
// copied on input and output, so callers cannot mutate store-owned state.
type Approval struct {
	ID            string
	Code          string
	ServerAlias   string
	ServerAliases []string
	Command       []byte
	Categories    []policy.Category
	Limits        ExecutionLimits
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Used          bool
}

type storedApproval struct {
	Approval
	used     bool
	decision string
	done     chan struct{}
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
func (s *Store) Create(serverAlias string, command []byte, categories []policy.Category, limits ExecutionLimits) (Approval, error) {
	return s.CreateBatch([]string{serverAlias}, command, categories, limits)
}

func (s *Store) CreateBatch(serverAliases []string, command []byte, categories []policy.Category, limits ExecutionLimits) (Approval, error) {
	serverAliases = normalizeAliases(serverAliases)
	if s == nil || s.now == nil || s.random == nil || len(serverAliases) == 0 || len(command) == 0 || len(command) > maxCommandBytes ||
		limits.Timeout <= 0 || limits.Timeout > maxTimeout || limits.MaxOutputBytes <= 0 || limits.MaxOutputBytes > maxOutputBytes {
		return Approval{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cleanupAt := s.now()
	s.cleanupLocked(cleanupAt, "")
	if len(s.items) >= maxStoreEntries {
		return Approval{}, ErrCapacity
	}

	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.random, idBytes); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	id := hex.EncodeToString(idBytes)
	if _, exists := s.items[id]; exists {
		return Approval{}, fmt.Errorf("%w: duplicate approval id", ErrRandom)
	}
	code, err := generateCode(s.random)
	if err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	createdAt := s.now()
	approval := Approval{
		ID:            id,
		Code:          code,
		ServerAlias:   serverAliases[0],
		ServerAliases: append([]string(nil), serverAliases...),
		Command:       append([]byte(nil), command...),
		Categories:    normalizeCategories(categories),
		Limits:        limits,
		CreatedAt:     createdAt,
		ExpiresAt:     createdAt.Add(defaultTTL),
	}
	s.items[id] = storedApproval{Approval: cloneApproval(approval), done: make(chan struct{})}
	return cloneApproval(approval), nil
}

func (s *Store) List(includeCommand bool) []Approval {
	if s == nil || s.now == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(s.now(), "")
	result := make([]Approval, 0, len(s.items))
	for _, item := range s.items {
		if item.used {
			continue
		}
		copy := cloneApproval(item.Approval)
		if !includeCommand {
			zeroBytes(copy.Command)
			copy.Command = nil
		}
		copy.Used = item.decision != ""
		result = append(result, copy)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func (s *Store) Get(id string) (Approval, string, error) {
	if s == nil || id == "" {
		return Approval{}, "", ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Approval{}, "", ErrNotFound
	}
	return cloneApproval(item.Approval), item.decision, nil
}

func (s *Store) Decide(id string, allow bool) error {
	if s == nil || id == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return ErrNotFound
	}
	if !s.now().Before(item.ExpiresAt) {
		zeroBytes(item.Command)
		delete(s.items, id)
		return ErrExpired
	}
	if item.decision != "" || item.used {
		return ErrUsed
	}
	if allow {
		item.decision = "approved"
	} else {
		item.decision = "denied"
	}
	close(item.done)
	s.items[id] = item
	return nil
}

func (s *Store) Wait(ctx context.Context, id string) (Approval, bool, error) {
	s.mu.Lock()
	item, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return Approval{}, false, ErrNotFound
	}
	done := item.done
	expiresAt := item.ExpiresAt
	s.mu.Unlock()
	timer := time.NewTimer(time.Until(expiresAt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return Approval{}, false, ctx.Err()
	case <-done:
	case <-timer.C:
		s.mu.Lock()
		if expired, exists := s.items[id]; exists {
			zeroBytes(expired.Command)
			delete(s.items, id)
		}
		s.mu.Unlock()
		return Approval{}, false, ErrExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok = s.items[id]
	if !ok {
		return Approval{}, false, ErrNotFound
	}
	if item.decision == "denied" {
		zeroBytes(item.Command)
		delete(s.items, id)
		return Approval{}, false, nil
	}
	if item.decision != "approved" {
		return Approval{}, false, ErrNotFound
	}
	approved := cloneApproval(item.Approval)
	approved.Used = true
	zeroBytes(item.Command)
	delete(s.items, id)
	return approved, true, nil
}

// Consume validates and atomically marks an approval as used.
func (s *Store) Consume(id, code string) (Approval, error) {
	if s == nil || s.now == nil || s.random == nil || id == "" {
		return Approval{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	now := s.now()
	// Expiration wins over every other validation result and removes the
	// record, making this the only call that reports ErrExpired.
	if ok && !now.Before(item.ExpiresAt) {
		zeroBytes(item.Command)
		delete(s.items, id)
		return Approval{}, ErrExpired
	}
	s.cleanupLocked(now, id)
	if !ok {
		return Approval{}, ErrNotFound
	}
	if item.used {
		return Approval{}, ErrUsed
	}
	var supplied [approvalCodeSize]byte
	copy(supplied[:], code)
	codeMatch := subtle.ConstantTimeCompare([]byte(item.Code), supplied[:])
	lengthMatch := subtle.ConstantTimeEq(int32(len(code)), int32(len(item.Code)))
	if codeMatch != 1 || lengthMatch != 1 {
		return Approval{}, ErrCode
	}
	consumed := cloneApproval(item.Approval)
	consumed.Used = true
	zeroBytes(item.Command)
	s.items[id] = storedApproval{
		Approval: Approval{
			ID:        item.ID,
			ExpiresAt: item.ExpiresAt,
			Used:      true,
		},
		used: true,
	}
	return consumed, nil
}

// Revoke removes an unused approval. Missing IDs are treated as already
// revoked, while used tombstones are retained so replay remains distinguishable.
func (s *Store) Revoke(id string) error {
	if s == nil || s.now == nil || id == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return nil
	}
	if item.used {
		return ErrUsed
	}
	zeroBytes(item.Command)
	delete(s.items, id)
	return nil
}

func (s *Store) cleanupLocked(now time.Time, except string) {
	for id, item := range s.items {
		if id != except && !now.Before(item.ExpiresAt) {
			zeroBytes(item.Command)
			delete(s.items, id)
		}
	}
}

const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func generateCode(random io.Reader) (string, error) {
	const unbiasedLimit = 256 - 256%len(codeAlphabet)
	code := make([]byte, 0, approvalCodeSize)
	var raw [1]byte
	for len(code) < approvalCodeSize {
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return "", err
		}
		if int(raw[0]) >= unbiasedLimit {
			continue
		}
		code = append(code, codeAlphabet[int(raw[0])%len(codeAlphabet)])
	}
	return string(code), nil
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
	approval.ServerAliases = append([]string(nil), approval.ServerAliases...)
	return approval
}

func normalizeAliases(aliases []string) []string {
	seen := make(map[string]struct{}, len(aliases))
	result := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		result = append(result, alias)
	}
	return result
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
