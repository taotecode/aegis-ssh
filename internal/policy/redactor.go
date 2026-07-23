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

const (
	defaultRedactionMaxBytes  = 4 << 20
	redactionLookaheadBytes   = 256
	redactionBasePrefix       = "\x00AEGIS_REDACTION\x00"
	privateKeyPEMLabelPattern = `(?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|OPENSSH PRIVATE KEY|ENCRYPTED PRIVATE KEY)`
)

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
	privateKeyBlockRE  = regexp.MustCompile(`(?ms)-----BEGIN ` + privateKeyPEMLabelPattern + `-----.*?-----END ` + privateKeyPEMLabelPattern + `-----`)
	incompletePEMRE    = regexp.MustCompile(`(?ms)-----BEGIN ` + privateKeyPEMLabelPattern + `-----.*\z`)
	urlSchemeRE        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,31}://`)
	urlCredentialRE    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,31}://)([^/@\s:]+):([^/@\s]+)@`)
	incompleteURLRE    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,31}://)([^/@\s:]+):([^/@\s]*)\z`)
	bearerTokenRE      = regexp.MustCompile(`(?i)(\bbearer[ \t]+)([a-z0-9._~+/=-]+)`)
	accessKeyRE        = regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)
	gitLabAccessKeyRE  = regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)
	incompleteAccessRE = regexp.MustCompile(`(?:\b(?:AKIA|ASIA)[A-Z0-9]{0,15}|\bgh[pousr]_[A-Za-z0-9]{0,35}|\bgithub_pat_[A-Za-z0-9_]{0,81}|\bglpat-[A-Za-z0-9_-]{0,19})\z`)
	assignmentRE       = regexp.MustCompile(`(?i)(["']?\b(?:[a-z][a-z0-9_.-]*[_.-])?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)\b["']?[ \t]*(?:=|:)[ \t]*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s]+)`)
	bracketedIPv6RE    = regexp.MustCompile(`\[[^\]\s]+\]`)
	bareIPv6RE         = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+(?:%[^\s\[\]]+)?`)
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
	urlCredentialAcrossBoundary := urlCredentialAfterBoundary(input, maxBytes)
	inspectionLimit := redactionInspectionLimit(maxBytes)
	if len(input) > inspectionLimit {
		input = input[:inspectionLimit]
	}
	return r.redactInspected(input, truncated, urlCredentialAcrossBoundary)
}

func (r *Redactor) redactBounded(input string, truncated bool) RedactionResult {
	return r.redactBoundedWithBoundary(input, truncated, redactionBoundary{})
}

type redactionBoundary struct {
	rightContext                string
	crossingIPPrefix            string
	crossingURLCredentialPrefix string
}

func (r *Redactor) redactInspected(inspection string, truncated bool, urlCredentialAcrossBoundary bool) RedactionResult {
	publicBytes := len(inspection)
	if publicBytes > r.maxBytes {
		publicBytes = r.maxBytes
	}
	boundary := redactionBoundary{rightContext: inspection[publicBytes:]}
	boundary.crossingIPPrefix = crossingIPAddressPrefix(inspection, publicBytes)
	boundary.crossingURLCredentialPrefix = crossingURLCredentialPrefix(inspection, publicBytes)
	if truncated && urlCredentialAcrossBoundary && boundary.crossingURLCredentialPrefix == "" {
		if start, ok := urlAuthorityAtBoundary(inspection, publicBytes); ok {
			boundary.crossingURLCredentialPrefix = inspection[start:publicBytes]
		}
	}
	return r.redactBoundedWithBoundary(inspection[:publicBytes], truncated, boundary)
}

func (r *Redactor) redactBoundedWithBoundary(input string, truncated bool, boundary redactionBoundary) RedactionResult {
	input = strings.ToValidUTF8(input, "\uFFFD")
	state := newRedactionState(input)

	if !r.allowed[PrivateKeyBlock] {
		state.protect(privateKeyBlockRE, PrivateKeyBlock, replaceWholeMatch)
		state.protect(incompletePEMRE, PrivateKeyBlock, replaceWholeMatch)
	}
	if !r.allowed[URLCredential] {
		state.protect(urlCredentialRE, URLCredential, replaceURLUserInfo)
		if truncated {
			state.protect(incompleteURLRE, URLCredential, replaceIncompleteURLUserInfo)
		}
		state.protectTrailingCredentialPrefix(boundary.crossingURLCredentialPrefix, URLCredential)
	}
	if !r.allowed[BearerToken] {
		state.protect(bearerTokenRE, BearerToken, preserveFirstCapture)
	}
	if !r.allowed[AccessKey] {
		state.protect(accessKeyRE, AccessKey, replaceWholeMatch)
		state.protect(gitLabAccessKeyRE, AccessKey, replaceWholeMatch)
		if truncated {
			state.protect(incompleteAccessRE, AccessKey, replaceWholeMatch)
		}
	}
	if !r.allowed[CredentialAssignment] {
		state.protect(assignmentRE, CredentialAssignment, preserveFirstCapture)
	}
	if !r.allowed[IPAddress] {
		state.protectTrailingIPAddress(boundary.crossingIPPrefix)
		state.protectIPAddresses(boundary.rightContext)
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

func redactionInspectionLimit(maxBytes int) int {
	maxInt := int(^uint(0) >> 1)
	if maxBytes > maxInt-redactionLookaheadBytes {
		return maxBytes
	}
	return maxBytes + redactionLookaheadBytes
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
	category    RedactionCategory
	active      bool
}

type redactionState struct {
	text         string
	prefix       string
	replacements []protectedReplacement
	counts       map[RedactionCategory]int
}

func newRedactionState(text string) *redactionState {
	return &redactionState{text: text, prefix: collisionSafeRedactionPrefix(text), counts: make(map[RedactionCategory]int)}
}

func collisionSafeRedactionPrefix(text string) string {
	maxNULRun := -1
	searchFrom := 0
	for searchFrom < len(text) {
		relative := strings.Index(text[searchFrom:], redactionBasePrefix)
		if relative < 0 {
			break
		}
		afterPrefix := searchFrom + relative + len(redactionBasePrefix)
		runEnd := afterPrefix
		for runEnd < len(text) && text[runEnd] == 0 {
			runEnd++
		}
		if runEnd-afterPrefix > maxNULRun {
			maxNULRun = runEnd - afterPrefix
		}
		searchFrom = runEnd
	}
	if maxNULRun < 0 {
		return redactionBasePrefix
	}
	return redactionBasePrefix + strings.Repeat("\x00", maxNULRun+1)
}

type protectedFormatter func(*regexp.Regexp, string, string) string

func (s *redactionState) protect(pattern *regexp.Regexp, category RedactionCategory, format protectedFormatter) {
	s.text = pattern.ReplaceAllStringFunc(s.text, func(match string) string {
		if strings.Contains(match, s.prefix) {
			s.consumePlaceholders(match)
		}
		placeholder := s.newPlaceholder(category)
		return format(pattern, match, placeholder)
	})
}

func (s *redactionState) consumePlaceholders(text string) {
	position := 0
	for position < len(text) {
		relative := strings.Index(text[position:], s.prefix)
		if relative < 0 {
			return
		}
		start := position + relative
		end := start + len(s.prefix)
		for end < len(text) && text[end] >= '0' && text[end] <= '9' {
			end++
		}
		if end < len(text) && text[end] == 0 {
			index, err := strconv.Atoi(text[start+len(s.prefix) : end])
			if err == nil && index >= 0 && index < len(s.replacements) && s.replacements[index].placeholder == text[start:end+1] {
				if s.replacements[index].active {
					s.replacements[index].active = false
					if s.counts[s.replacements[index].category] <= 1 {
						delete(s.counts, s.replacements[index].category)
					} else {
						s.counts[s.replacements[index].category]--
					}
				}
				position = end + 1
				continue
			}
		}
		position = start + len(s.prefix)
	}
}

func (s *redactionState) newPlaceholder(category RedactionCategory) string {
	placeholder := s.prefix + strconv.Itoa(len(s.replacements)) + "\x00"
	s.replacements = append(s.replacements, protectedReplacement{
		placeholder: placeholder,
		marker:      redactionMarker(category),
		category:    category,
		active:      true,
	})
	s.counts[category]++
	return placeholder
}

func (s *redactionState) render() string {
	var rendered strings.Builder
	rendered.Grow(len(s.text))
	position := 0
	for position < len(s.text) {
		relative := strings.Index(s.text[position:], s.prefix)
		if relative < 0 {
			rendered.WriteString(s.text[position:])
			break
		}
		start := position + relative
		rendered.WriteString(s.text[position:start])
		end := start + len(s.prefix)
		for end < len(s.text) && s.text[end] >= '0' && s.text[end] <= '9' {
			end++
		}
		if end < len(s.text) && s.text[end] == 0 {
			index, err := strconv.Atoi(s.text[start+len(s.prefix) : end])
			if err == nil && index >= 0 && index < len(s.replacements) && s.replacements[index].placeholder == s.text[start:end+1] {
				if s.replacements[index].active {
					rendered.WriteString(s.replacements[index].marker)
				}
				position = end + 1
				continue
			}
		}
		rendered.WriteString(s.prefix)
		position = start + len(s.prefix)
	}
	return rendered.String()
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

type ipCandidateValidator func(string) (int, int, bool)

func (s *redactionState) protectTrailingIPAddress(prefix string) {
	if prefix == "" || !strings.HasSuffix(s.text, prefix) {
		return
	}
	s.text = strings.TrimSuffix(s.text, prefix) + s.newPlaceholder(IPAddress)
}

func (s *redactionState) protectTrailingCredentialPrefix(prefix string, category RedactionCategory) {
	if prefix == "" || !strings.HasSuffix(s.text, prefix) {
		return
	}
	s.text = strings.TrimSuffix(s.text, prefix) + s.newPlaceholder(category)
}

func (s *redactionState) protectIPAddresses(rightContext string) {
	s.replaceValidated(bracketedIPv6RE, validateBracketedIPv6, rightContext)
	s.replaceValidated(bareIPv6RE, validateBareIPv6, rightContext)
	s.replaceValidated(ipv4RE, validateIPv4, rightContext)
}

func (s *redactionState) replaceValidated(pattern *regexp.Regexp, validate ipCandidateValidator, rightContext string) {
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
		if !ok || strings.Contains(candidate, s.prefix) || !validIPAddressBoundary(text, absoluteStart, absoluteEnd, rightContext) {
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

func validateBracketedIPv6(candidate string) (int, int, bool) {
	address, err := netip.ParseAddr(candidate[1 : len(candidate)-1])
	return 0, len(candidate), err == nil && address.Is6()
}

func validateBareIPv6(candidate string) (int, int, bool) {
	start, end := trimIPv6Candidate(candidate)
	if start >= end {
		return 0, 0, false
	}
	address, err := netip.ParseAddr(candidate[start:end])
	return start, end, err == nil && address.Is6()
}

func validateIPv4(candidate string) (int, int, bool) {
	address, err := netip.ParseAddr(candidate)
	return 0, len(candidate), err == nil && address.Is4()
}

func crossingIPAddressPrefix(inspection string, publicBytes int) string {
	if publicBytes <= 0 || publicBytes >= len(inspection) {
		return ""
	}
	rules := []struct {
		pattern  *regexp.Regexp
		validate ipCandidateValidator
	}{
		{bracketedIPv6RE, validateBracketedIPv6},
		{bareIPv6RE, validateBareIPv6},
		{ipv4RE, validateIPv4},
	}
	for _, rule := range rules {
		for _, index := range rule.pattern.FindAllStringIndex(inspection, -1) {
			start, end, ok := rule.validate(inspection[index[0]:index[1]])
			absoluteStart := index[0] + start
			absoluteEnd := index[0] + end
			if ok && absoluteStart < publicBytes && absoluteEnd > publicBytes &&
				validIPAddressBoundary(inspection, absoluteStart, absoluteEnd, "") {
				return inspection[absoluteStart:publicBytes]
			}
		}
	}
	return ""
}

func crossingURLCredentialPrefix(inspection string, publicBytes int) string {
	if publicBytes <= 0 || publicBytes >= len(inspection) {
		return ""
	}
	for _, index := range urlCredentialRE.FindAllStringIndex(inspection, -1) {
		if index[0] >= publicBytes || index[1] <= publicBytes {
			continue
		}
		match := inspection[index[0]:index[1]]
		parts := urlCredentialRE.FindStringSubmatchIndex(match)
		if len(parts) < 4 || parts[2] < 0 {
			continue
		}
		credentialStart := index[0] + parts[2]
		if credentialStart < publicBytes {
			return inspection[credentialStart:publicBytes]
		}
	}
	return ""
}

func urlAuthorityAtBoundary(input string, publicBytes int) (int, bool) {
	if publicBytes <= 0 || publicBytes > len(input) {
		return 0, false
	}
	searchFrom := 0
	for searchFrom < publicBytes {
		match := urlSchemeRE.FindStringIndex(input[searchFrom:publicBytes])
		if match == nil {
			return 0, false
		}
		authorityStart := searchFrom + match[1]
		if authorityStart < publicBytes {
			terminated := false
			for i := authorityStart; i < publicBytes; i++ {
				if isURLAuthorityTerminator(input[i]) {
					terminated = true
					break
				}
			}
			if !terminated {
				return authorityStart, true
			}
		}
		searchFrom += match[1]
	}
	return 0, false
}

func urlAuthorityAtBoundaryBytes(input []byte, publicBytes int) (int, bool) {
	if publicBytes <= 0 || publicBytes > len(input) {
		return 0, false
	}
	for start := 0; start < publicBytes; start++ {
		if !isASCIIAlpha(input[start]) || start > 0 && isASCIIWord(input[start-1]) {
			continue
		}
		end := start + 1
		for end < publicBytes && end-start < 32 && isURLSchemeChar(input[end]) {
			end++
		}
		if end-start < 2 || end+2 >= len(input) || input[end] != ':' || input[end+1] != '/' || input[end+2] != '/' {
			continue
		}
		authorityStart := end + 3
		if authorityStart >= publicBytes {
			continue
		}
		terminated := false
		for i := authorityStart; i < publicBytes; i++ {
			if isURLAuthorityTerminator(input[i]) {
				terminated = true
				break
			}
		}
		if !terminated {
			return authorityStart, true
		}
	}
	return 0, false
}

func isASCIIAlpha(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

func isASCIIWord(char byte) bool {
	return isASCIIAlpha(char) || char >= '0' && char <= '9' || char == '_'
}

func isURLSchemeChar(char byte) bool {
	return isASCIIAlpha(char) || char >= '0' && char <= '9' || char == '+' || char == '.' || char == '-'
}

func urlCredentialAfterBoundary(input string, publicBytes int) bool {
	start, ok := urlAuthorityAtBoundary(input, publicBytes)
	if !ok || publicBytes >= len(input) {
		return false
	}
	colonSeen := false
	for i := start; i < len(input); i++ {
		char := input[i]
		if isURLAuthorityTerminator(char) {
			return false
		}
		switch char {
		case ':':
			colonSeen = true
		case '@':
			if colonSeen {
				return i >= publicBytes
			}
			return false
		}
	}
	return false
}

func isURLAuthorityTerminator(char byte) bool {
	return char == '/' || char == '?' || char == '#' || char == ' ' || char == '\t' || char == '\r' || char == '\n'
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

func validIPAddressBoundary(text string, start, end int, rightContext string) bool {
	if start > 0 && isIPAddressAdjacent(text[start-1]) {
		return false
	}
	if end < len(text) {
		return validIPAddressRightBoundary(text[end:])
	}
	return validIPAddressRightBoundary(rightContext)
}

func validIPAddressRightBoundary(context string) bool {
	if context == "" {
		return true
	}
	if context[0] == '.' {
		return len(context) == 1 || !isIPAddressAdjacent(context[1])
	}
	return !isIPAddressAdjacent(context[0])
}

func isIPAddressAdjacent(char byte) bool {
	return char == '_' || char == '%' || char == '.' ||
		char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

type urlAuthorityTailState struct {
	initialized bool
	active      bool
	colonSeen   bool
	credentials bool
	resolved    bool
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
	urlTail   urlAuthorityTailState
	maxFrozen bool
}

func NewStreamRedactor(dst io.Writer, allowed map[RedactionCategory]bool) *StreamRedactor {
	if dst == nil {
		dst = io.Discard
	}
	return &StreamRedactor{dst: dst, redactor: NewRedactor(allowed)}
}

// WithMaxBytes applies only before the first Write or Close; later calls are no-ops.
func (s *StreamRedactor) WithMaxBytes(maxBytes int) *StreamRedactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxFrozen || s.closed {
		return s
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	s.redactor = s.redactor.WithMaxBytes(maxBytes)
	inspectionLimit := redactionInspectionLimit(maxBytes)
	if len(s.buffer) > inspectionLimit {
		s.buffer = append([]byte(nil), s.buffer[:inspectionLimit]...)
		s.truncated = true
	}
	if len(s.buffer) > maxBytes {
		s.truncated = true
	}
	if cap(s.buffer) > inspectionLimit {
		shrunk := make([]byte, len(s.buffer), inspectionLimit)
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
	s.maxFrozen = true
	written := len(p)
	if len(s.buffer)+len(p) > s.redactor.maxBytes {
		s.truncated = true
	}
	bufferedBefore := len(s.buffer)
	remaining := redactionInspectionLimit(s.redactor.maxBytes) - len(s.buffer)
	if remaining < 0 {
		remaining = 0
	}
	kept := p
	var dropped []byte
	if len(kept) > remaining {
		kept, dropped = kept[:remaining], kept[remaining:]
		s.truncated = true
	}
	s.growBuffer(len(kept))
	s.buffer = append(s.buffer, kept...)
	if len(dropped) > 0 {
		s.observeDroppedURLBytes(dropped, bufferedBefore+len(kept))
	}
	return written, nil
}

func (s *StreamRedactor) observeDroppedURLBytes(dropped []byte, absoluteStart int) {
	if !s.urlTail.initialized {
		s.urlTail.initialized = true
		start, ok := urlAuthorityAtBoundaryBytes(s.buffer, s.redactor.maxBytes)
		if !ok {
			return
		}
		s.urlTail.active = true
		for i := start; i < len(s.buffer); i++ {
			s.observeURLAuthorityByte(s.buffer[i], i)
			if s.urlTail.resolved {
				return
			}
		}
	}
	if !s.urlTail.active || s.urlTail.resolved {
		return
	}
	for i, char := range dropped {
		s.observeURLAuthorityByte(char, absoluteStart+i)
		if s.urlTail.resolved {
			return
		}
	}
}

func (s *StreamRedactor) observeURLAuthorityByte(char byte, absolutePosition int) {
	if isURLAuthorityTerminator(char) {
		s.urlTail.resolved = true
		s.urlTail.active = false
		return
	}
	switch char {
	case ':':
		s.urlTail.colonSeen = true
	case '@':
		if s.urlTail.colonSeen && absolutePosition >= s.redactor.maxBytes {
			s.urlTail.credentials = true
		}
		s.urlTail.resolved = true
		s.urlTail.active = false
	}
}

func (s *StreamRedactor) growBuffer(additional int) {
	required := len(s.buffer) + additional
	if required <= cap(s.buffer) {
		return
	}
	limit := redactionInspectionLimit(s.redactor.maxBytes)
	capacity := required
	if cap(s.buffer) > 0 && cap(s.buffer) <= limit/2 && cap(s.buffer)*2 > capacity {
		capacity = cap(s.buffer) * 2
	}
	if capacity > limit {
		capacity = limit
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
	s.maxFrozen = true
	urlCredentialAcrossBoundary := urlCredentialAfterBoundary(string(s.buffer), s.redactor.maxBytes)
	if s.urlTail.credentials {
		urlCredentialAcrossBoundary = true
	}
	s.result = s.redactor.redactInspected(string(s.buffer), s.truncated, urlCredentialAcrossBoundary)
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
