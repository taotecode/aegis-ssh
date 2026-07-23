package policy

import (
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const defaultRedactionMaxBytes = 4 << 20

type RedactionCategory string

const (
	IPAddress            RedactionCategory = "ip_address"
	PrivateKeyBlock      RedactionCategory = "private_key_block"
	BearerToken          RedactionCategory = "bearer_token"
	AccessKey            RedactionCategory = "access_key"
	URLCredential        RedactionCategory = "url_credential"
	CredentialAssignment RedactionCategory = "credential_assignment"
)

type RedactionResult struct {
	Text      string
	Counts    map[RedactionCategory]int
	Truncated bool
}

type Redactor struct {
	allowed  map[RedactionCategory]bool
	maxBytes int
}

var (
	privateKeyBlockRE  = regexp.MustCompile(`(?ms)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	incompletePEMRE    = regexp.MustCompile(`(?ms)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*\z`)
	urlCredentialRE    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,31}://)([^/@\s:]+):([^/@\s]+)@`)
	incompleteURLRE    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,31}://)([^/@\s:]+):([^/@\s]*)\z`)
	bearerTokenRE      = regexp.MustCompile(`(?i)(\bbearer[ \t]+)([a-z0-9._~+/=-]+)`)
	accessKeyRE        = regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|glpat-[A-Za-z0-9_-]{20,})\b`)
	incompleteAccessRE = regexp.MustCompile(`(?:\b(?:AKIA|ASIA)[A-Z0-9]{0,15}|\bgh[pousr]_[A-Za-z0-9]{0,35}|\bgithub_pat_[A-Za-z0-9_]{0,81}|\bglpat-[A-Za-z0-9_-]{0,19})\z`)
	assignmentRE       = regexp.MustCompile(`(?i)(["']?\b(?:[a-z][a-z0-9_.-]*[_.-])?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)\b["']?[ \t]*(?:=|:)[ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
	bracketedIPv6RE    = regexp.MustCompile(`\[[0-9A-Fa-f:.]+(?:%[0-9A-Za-z_.-]+)?\]`)
	bareIPv6RE         = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+(?:%[0-9A-Za-z_.-]+)?`)
	ipv4RE             = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
)

var ErrStreamRedactorClosed = errors.New("stream redactor is closed")

func NewRedactor(allowed map[RedactionCategory]bool) *Redactor {
	return &Redactor{
		allowed:  cloneAllowedCategories(allowed),
		maxBytes: defaultRedactionMaxBytes,
	}
}

func (r *Redactor) WithMaxBytes(maxBytes int) *Redactor {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if r == nil {
		return &Redactor{allowed: make(map[RedactionCategory]bool), maxBytes: maxBytes}
	}
	return &Redactor{allowed: cloneAllowedCategories(r.allowed), maxBytes: maxBytes}
}

func (r *Redactor) RedactString(input string) RedactionResult {
	if r == nil {
		r = NewRedactor(nil)
	}
	maxBytes := r.maxBytes
	if maxBytes < 0 {
		maxBytes = 0
	}
	truncated := len(input) > maxBytes
	if truncated {
		input = input[:maxBytes]
	}
	return r.redactBounded(input, truncated)
}

func (r *Redactor) redactBounded(input string, truncated bool) RedactionResult {
	input = strings.ToValidUTF8(input, "\uFFFD")
	state := newRedactionState(input)

	if !r.allowed[PrivateKeyBlock] {
		state.protect(privateKeyBlockRE, PrivateKeyBlock, replaceWholeMatch)
		if truncated {
			state.protect(incompletePEMRE, PrivateKeyBlock, replaceWholeMatch)
		}
	}
	if !r.allowed[URLCredential] {
		state.protect(urlCredentialRE, URLCredential, replaceURLUserInfo)
		if truncated {
			state.protect(incompleteURLRE, URLCredential, replaceIncompleteURLUserInfo)
		}
	}
	if !r.allowed[BearerToken] {
		state.protect(bearerTokenRE, BearerToken, preserveFirstCapture)
	}
	if !r.allowed[AccessKey] {
		state.protect(accessKeyRE, AccessKey, replaceWholeMatch)
		if truncated {
			state.protect(incompleteAccessRE, AccessKey, replaceWholeMatch)
		}
	}
	if !r.allowed[CredentialAssignment] {
		state.protect(assignmentRE, CredentialAssignment, preserveFirstCapture)
	}
	if !r.allowed[IPAddress] {
		state.protectIPAddresses()
	}

	text := state.render()
	maxBytes := r.maxBytes
	if maxBytes < 0 {
		maxBytes = 0
	}
	if len(text) > maxBytes {
		text = truncateValidUTF8(text, maxBytes)
		truncated = true
	}
	return RedactionResult{Text: text, Counts: cloneRedactionCounts(state.counts), Truncated: truncated}
}

func redactionMarker(category RedactionCategory) string {
	return "[REDACTED:" + strings.ToUpper(string(category)) + "]"
}

func cloneAllowedCategories(allowed map[RedactionCategory]bool) map[RedactionCategory]bool {
	cloned := make(map[RedactionCategory]bool, len(allowed))
	for category, permitted := range allowed {
		cloned[category] = permitted
	}
	return cloned
}

func cloneRedactionCounts(counts map[RedactionCategory]int) map[RedactionCategory]int {
	cloned := make(map[RedactionCategory]int, len(counts))
	for category, count := range counts {
		cloned[category] = count
	}
	return cloned
}

func truncateValidUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

type protectedReplacement struct {
	placeholder string
	marker      string
}

type redactionState struct {
	text         string
	prefix       string
	replacements []protectedReplacement
	counts       map[RedactionCategory]int
}

func newRedactionState(text string) *redactionState {
	prefix := "\x00AEGIS_REDACTION\x00"
	for strings.Contains(text, prefix) {
		prefix += "\x00"
	}
	return &redactionState{text: text, prefix: prefix, counts: make(map[RedactionCategory]int)}
}

type protectedFormatter func(*regexp.Regexp, string, string) string

func (s *redactionState) protect(pattern *regexp.Regexp, category RedactionCategory, format protectedFormatter) {
	s.text = pattern.ReplaceAllStringFunc(s.text, func(match string) string {
		if strings.Contains(match, s.prefix) {
			return match
		}
		placeholder := s.newPlaceholder(category)
		return format(pattern, match, placeholder)
	})
}

func (s *redactionState) newPlaceholder(category RedactionCategory) string {
	placeholder := s.prefix + strconv.Itoa(len(s.replacements)) + "\x00"
	s.replacements = append(s.replacements, protectedReplacement{
		placeholder: placeholder,
		marker:      redactionMarker(category),
	})
	s.counts[category]++
	return placeholder
}

func (s *redactionState) render() string {
	text := s.text
	for _, replacement := range s.replacements {
		text = strings.ReplaceAll(text, replacement.placeholder, replacement.marker)
	}
	return text
}

func replaceWholeMatch(_ *regexp.Regexp, _ string, placeholder string) string {
	return placeholder
}

func preserveFirstCapture(pattern *regexp.Regexp, match, placeholder string) string {
	parts := pattern.FindStringSubmatch(match)
	if len(parts) < 2 {
		return placeholder
	}
	return parts[1] + placeholder
}

func replaceURLUserInfo(pattern *regexp.Regexp, match, placeholder string) string {
	parts := pattern.FindStringSubmatch(match)
	if len(parts) < 2 {
		return placeholder
	}
	return parts[1] + placeholder + "@"
}

func replaceIncompleteURLUserInfo(pattern *regexp.Regexp, match, placeholder string) string {
	parts := pattern.FindStringSubmatch(match)
	if len(parts) < 2 {
		return placeholder
	}
	return parts[1] + placeholder
}

func (s *redactionState) protectIPAddresses() {
	s.replaceValidated(bracketedIPv6RE, func(candidate string) (int, int, bool) {
		address, err := netip.ParseAddr(candidate[1 : len(candidate)-1])
		return 0, len(candidate), err == nil && address.Is6()
	})
	s.replaceValidated(bareIPv6RE, func(candidate string) (int, int, bool) {
		start, end := trimIPv6Candidate(candidate)
		if start >= end {
			return 0, 0, false
		}
		address, err := netip.ParseAddr(candidate[start:end])
		return start, end, err == nil && address.Is6()
	})
	s.replaceValidated(ipv4RE, func(candidate string) (int, int, bool) {
		address, err := netip.ParseAddr(candidate)
		return 0, len(candidate), err == nil && address.Is4()
	})
}

func (s *redactionState) replaceValidated(pattern *regexp.Regexp, validate func(string) (int, int, bool)) {
	text := s.text
	indices := pattern.FindAllStringIndex(text, -1)
	if len(indices) == 0 {
		return
	}
	var output strings.Builder
	last := 0
	for _, index := range indices {
		candidate := text[index[0]:index[1]]
		start, end, ok := validate(candidate)
		absoluteStart := index[0] + start
		absoluteEnd := index[0] + end
		if !ok || strings.Contains(candidate, s.prefix) || !validIPAddressBoundary(text, absoluteStart, absoluteEnd) {
			continue
		}
		output.WriteString(text[last:absoluteStart])
		output.WriteString(s.newPlaceholder(IPAddress))
		last = absoluteEnd
	}
	if last == 0 {
		return
	}
	output.WriteString(text[last:])
	s.text = output.String()
}

func trimIPv6Candidate(candidate string) (int, int) {
	start, end := 0, len(candidate)
	for start < end && candidate[start] == '.' {
		start++
	}
	for start < end && candidate[start] == ':' && (start+1 == end || candidate[start+1] != ':') {
		start++
	}
	for start < end && candidate[end-1] == '.' {
		end--
	}
	for start < end && candidate[end-1] == ':' && (end-start == 1 || candidate[end-2] != ':') {
		end--
	}
	return start, end
}

func validIPAddressBoundary(text string, start, end int) bool {
	if start > 0 && isIPAddressAdjacent(text[start-1]) {
		return false
	}
	if end < len(text) && isIPAddressAdjacent(text[end]) {
		return false
	}
	return true
}

func isIPAddressAdjacent(char byte) bool {
	return char == '_' || char == '%' || char == '.' ||
		char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

type StreamRedactor struct {
	mu        sync.Mutex
	dst       io.Writer
	redactor  *Redactor
	buffer    []byte
	truncated bool
	closed    bool
	closeErr  error
	result    RedactionResult
}

func NewStreamRedactor(dst io.Writer, allowed map[RedactionCategory]bool) *StreamRedactor {
	if dst == nil {
		dst = io.Discard
	}
	return &StreamRedactor{dst: dst, redactor: NewRedactor(allowed)}
}

func (s *StreamRedactor) WithMaxBytes(maxBytes int) *StreamRedactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxBytes < 0 {
		maxBytes = 0
	}
	s.redactor = s.redactor.WithMaxBytes(maxBytes)
	if len(s.buffer) > maxBytes {
		s.buffer = append([]byte(nil), s.buffer[:maxBytes]...)
		s.truncated = true
	}
	if cap(s.buffer) > maxBytes {
		shrunk := make([]byte, len(s.buffer), maxBytes)
		copy(shrunk, s.buffer)
		s.buffer = shrunk
	}
	return s
}

func (s *StreamRedactor) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStreamRedactorClosed
	}
	written := len(p)
	remaining := s.redactor.maxBytes - len(s.buffer)
	if remaining < 0 {
		remaining = 0
	}
	if len(p) > remaining {
		p = p[:remaining]
		s.truncated = true
	}
	s.growBuffer(len(p))
	s.buffer = append(s.buffer, p...)
	return written, nil
}

func (s *StreamRedactor) growBuffer(additional int) {
	required := len(s.buffer) + additional
	if required <= cap(s.buffer) {
		return
	}
	capacity := cap(s.buffer) * 2
	if capacity < required {
		capacity = required
	}
	if capacity > s.redactor.maxBytes {
		capacity = s.redactor.maxBytes
	}
	next := make([]byte, len(s.buffer), capacity)
	copy(next, s.buffer)
	s.buffer = next
}

func (s *StreamRedactor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.result = s.redactor.redactBounded(string(s.buffer), s.truncated)
	s.buffer = nil
	written, err := io.WriteString(s.dst, s.result.Text)
	if err == nil && written != len(s.result.Text) {
		err = io.ErrShortWrite
	}
	s.closeErr = err
	return err
}

func (s *StreamRedactor) Result() RedactionResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.result
	result.Counts = cloneRedactionCounts(result.Counts)
	return result
}
