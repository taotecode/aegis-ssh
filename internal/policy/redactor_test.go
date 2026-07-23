package policy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRedactorCategoryValuesAndMarkersAreStable(t *testing.T) {
	want := map[RedactionCategory]string{
		IPAddress:            "ip_address",
		PrivateKeyBlock:      "private_key_block",
		BearerToken:          "bearer_token",
		AccessKey:            "access_key",
		URLCredential:        "url_credential",
		CredentialAssignment: "credential_assignment",
	}
	for category, wireValue := range want {
		if string(category) != wireValue {
			t.Errorf("category %q wire value = %q, want %q", category, category, wireValue)
		}
		marker := redactionMarker(category)
		if marker != "[REDACTED:"+strings.ToUpper(wireValue)+"]" {
			t.Errorf("redactionMarker(%q) = %q", category, marker)
		}
	}
}

func TestRedactorStateRenderUsesLinearMemory(t *testing.T) {
	state := newRedactionState("")
	var text strings.Builder
	for range 512 {
		text.WriteString(state.newPlaceholder(CredentialAssignment))
	}
	state.text = text.String()

	result := testing.Benchmark(func(b *testing.B) {
		for range b.N {
			if rendered := state.render(); rendered == "" {
				b.Fatal("render() returned empty output")
			}
		}
	})
	maxBytesPerOp := int64(len(state.text) * 32)
	if result.AllocedBytesPerOp() > maxBytesPerOp {
		t.Fatalf("render() allocated %d bytes/op for %d input bytes; want <= %d", result.AllocedBytesPerOp(), len(state.text), maxBytesPerOp)
	}
}

func TestRedactorRedactsSensitiveOutputAndCountsReplacements(t *testing.T) {
	awsKey := "AKIA" + strings.Repeat("S", 16)
	githubToken := "ghp_" + strings.Repeat("g", 36)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-PEM-PAYLOAD\n-----END OPENSSH PRIVATE KEY-----"
	input := strings.Join([]string{
		"ipv4=192.0.2.10 ipv6=2001:db8::1 endpoint=[2001:db8::2]:443 zone=fe80::1%eth0",
		pem,
		"Authorization: bEaReR synthetic.header.signature",
		"aws=" + awsKey + " github=" + githubToken,
		"fetch https://demo-user:synthetic-pass@example.test/path?q=1",
		`password="synthetic quoted value" api_key: synthetic-api-value`,
	}, "\n")

	result := NewRedactor(nil).RedactString(input)

	for _, secret := range []string{
		"192.0.2.10", "2001:db8::1", "2001:db8::2", "fe80::1%eth0",
		"SYNTHETIC-PEM-PAYLOAD", "synthetic.header.signature", awsKey, githubToken,
		"demo-user", "synthetic-pass", "synthetic quoted value", "synthetic-api-value",
	} {
		if strings.Contains(result.Text, secret) {
			t.Errorf("RedactString() leaked synthetic secret %q in %q", secret, result.Text)
		}
	}
	for _, marker := range []string{
		"[REDACTED:IP_ADDRESS]",
		"[REDACTED:PRIVATE_KEY_BLOCK]",
		"[REDACTED:BEARER_TOKEN]",
		"[REDACTED:ACCESS_KEY]",
		"[REDACTED:URL_CREDENTIAL]",
		"[REDACTED:CREDENTIAL_ASSIGNMENT]",
	} {
		if !strings.Contains(result.Text, marker) {
			t.Errorf("RedactString() output missing marker %q: %q", marker, result.Text)
		}
	}
	if !strings.Contains(result.Text, "https://[REDACTED:URL_CREDENTIAL]@example.test/path?q=1") {
		t.Errorf("URL scheme and host were not preserved: %q", result.Text)
	}
	wantCounts := map[RedactionCategory]int{
		IPAddress:            4,
		PrivateKeyBlock:      1,
		BearerToken:          1,
		AccessKey:            2,
		URLCredential:        1,
		CredentialAssignment: 2,
	}
	for category, want := range wantCounts {
		if got := result.Counts[category]; got != want {
			t.Errorf("Counts[%q] = %d, want %d; output=%q", category, got, want, result.Text)
		}
	}
	if result.Truncated {
		t.Fatal("RedactString() unexpectedly reported truncation")
	}
}

func TestRedactorHandlesPEMVariantsAndPreventsPartialLowerPriorityMatches(t *testing.T) {
	for _, pemType := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		t.Run(pemType, func(t *testing.T) {
			input := "before\n-----BEGIN " + pemType + "-----\nSYNTHETIC-192.0.2.33-PAYLOAD\n-----END " + pemType + "-----\nafter"
			result := NewRedactor(nil).RedactString(input)
			if result.Text != "before\n[REDACTED:PRIVATE_KEY_BLOCK]\nafter" {
				t.Fatalf("RedactString() = %q", result.Text)
			}
			if result.Counts[PrivateKeyBlock] != 1 || result.Counts[IPAddress] != 0 {
				t.Fatalf("RedactString() counts = %#v, want only one private key block", result.Counts)
			}
		})
	}

	compactPEM := "-----BEGIN EC PRIVATE KEY-----SYNTHETIC-COMPACT-PEM-----END EC PRIVATE KEY-----"
	compactResult := NewRedactor(nil).RedactString(compactPEM)
	if compactResult.Text != "[REDACTED:PRIVATE_KEY_BLOCK]" || compactResult.Counts[PrivateKeyBlock] != 1 {
		t.Fatalf("RedactString(compact PEM) = %#v", compactResult)
	}

	result := NewRedactor(nil).RedactString("password=192.0.2.44")
	if result.Text != "password=[REDACTED:CREDENTIAL_ASSIGNMENT]" {
		t.Fatalf("RedactString() = %q", result.Text)
	}
	if result.Counts[CredentialAssignment] != 1 || result.Counts[IPAddress] != 0 {
		t.Fatalf("RedactString() counts = %#v, want only credential assignment", result.Counts)
	}
}

func TestRedactorProtectsPrivateKeyBlockAtNaturalEOF(t *testing.T) {
	input := "before\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC-EOF-PEM-PAYLOAD"
	result := NewRedactor(nil).RedactString(input)
	if result.Text != "before\n[REDACTED:PRIVATE_KEY_BLOCK]" || result.Counts[PrivateKeyBlock] != 1 {
		t.Fatalf("RedactString() = %#v", result)
	}
}

func TestRedactorAvoidsIPAddressAndAccessKeyFalsePositives(t *testing.T) {
	input := "version 1.2.3 invalid 999.1.1.1 hash deadbeef0123456789abcdef0123456789 abc2001:db8::1def glpat-short"
	result := NewRedactor(nil).RedactString(input)
	if result.Text != input {
		t.Fatalf("RedactString() = %q, want unchanged %q", result.Text, input)
	}
	if len(result.Counts) != 0 {
		t.Fatalf("RedactString() counts = %#v, want none", result.Counts)
	}
}

func TestRedactorRedactsGitLabPATEndingInHyphen(t *testing.T) {
	token := "glpat-" + strings.Repeat("g", 20) + "-"
	result := NewRedactor(nil).RedactString(token)
	if result.Text != "[REDACTED:ACCESS_KEY]" || result.Counts[AccessKey] != 1 {
		t.Fatalf("RedactString() = %#v", result)
	}
}

func TestRedactorRedactsIPAddressBeforeSentencePeriod(t *testing.T) {
	for _, input := range []string{"peer=192.0.2.10.", "peer=2001:db8::1."} {
		result := NewRedactor(nil).RedactString(input)
		if result.Text != "peer=[REDACTED:IP_ADDRESS]." {
			t.Errorf("RedactString(%q) = %q", input, result.Text)
		}
		if result.Counts[IPAddress] != 1 {
			t.Errorf("RedactString(%q) counts = %#v", input, result.Counts)
		}
	}
}

func TestRedactorAcceptsLongNetipIPv6Zones(t *testing.T) {
	zone := strings.Repeat("z", 65)
	for _, input := range []string{"fe80::1%" + zone, "[fe80::1%" + zone + "]:443"} {
		result := NewRedactor(nil).RedactString(input)
		if !strings.Contains(result.Text, "[REDACTED:IP_ADDRESS]") || result.Counts[IPAddress] != 1 {
			t.Errorf("RedactString(%q) = %#v", input, result)
		}
	}
}

func TestRedactorAllowedCategoryDoesNotDisableOtherCategoriesAndCopiesMap(t *testing.T) {
	allowed := map[RedactionCategory]bool{URLCredential: true}
	redactor := NewRedactor(allowed)
	allowed[IPAddress] = true

	input := "https://demo-user:synthetic-pass@192.0.2.55/path"
	result := redactor.RedactString(input)
	if result.Text != "https://demo-user:synthetic-pass@[REDACTED:IP_ADDRESS]/path" {
		t.Fatalf("RedactString() = %q", result.Text)
	}
	if result.Counts[URLCredential] != 0 || result.Counts[IPAddress] != 1 {
		t.Fatalf("RedactString() counts = %#v", result.Counts)
	}
}

func TestRedactorNormalizesInvalidUTF8AndHandlesEmptyInput(t *testing.T) {
	invalid := string([]byte{'o', 'k', 0xff, ' ', 'p', 'w', 'd', '=', 'x', 0xfe})
	result := NewRedactor(nil).RedactString(invalid)
	if !utf8.ValidString(result.Text) {
		t.Fatalf("RedactString() returned invalid UTF-8: %x", []byte(result.Text))
	}
	if strings.Contains(result.Text, "pwd=x") || result.Counts[CredentialAssignment] != 1 {
		t.Fatalf("RedactString() did not redact assignment around invalid UTF-8: %#v", result)
	}

	empty := NewRedactor(nil).RedactString("")
	if empty.Text != "" || len(empty.Counts) != 0 || empty.Truncated {
		t.Fatalf("RedactString(empty) = %#v", empty)
	}
}

func TestRedactorRedactsQuotedAndPrefixedCredentialAssignments(t *testing.T) {
	input := `{"db_password":"synthetic-json-value","AWS_SECRET_ACCESS_KEY": synthetic-cloud-value}`
	result := NewRedactor(nil).RedactString(input)
	for _, secret := range []string{"synthetic-json-value", "synthetic-cloud-value"} {
		if strings.Contains(result.Text, secret) {
			t.Fatalf("RedactString() leaked %q in %q", secret, result.Text)
		}
	}
	if result.Counts[CredentialAssignment] != 2 {
		t.Fatalf("RedactString() counts = %#v, output = %q", result.Counts, result.Text)
	}
}

func TestRedactorRedactsEntireEscapedQuotedCredentialValue(t *testing.T) {
	input := `{"password":"synthetic-prefix\"LEAKED-SUFFIX"}`
	result := NewRedactor(nil).RedactString(input)
	if result.Text != `{"password":[REDACTED:CREDENTIAL_ASSIGNMENT]}` {
		t.Fatalf("RedactString() = %q", result.Text)
	}
	if result.Counts[CredentialAssignment] != 1 {
		t.Fatalf("RedactString() counts = %#v", result.Counts)
	}
}

func TestRedactorRedactsUnquotedCredentialValueThroughPunctuation(t *testing.T) {
	input := "password=synthetic,leaked;still-secret"
	result := NewRedactor(nil).RedactString(input)
	if result.Text != "password=[REDACTED:CREDENTIAL_ASSIGNMENT]" || result.Counts[CredentialAssignment] != 1 {
		t.Fatalf("RedactString() = %#v", result)
	}
}

func TestRedactorOuterCredentialStructuresConsumeNestedSecrets(t *testing.T) {
	accessKey := "AKIA" + strings.Repeat("N", 16)
	tests := []struct {
		name         string
		input        string
		want         string
		wantCategory RedactionCategory
	}{
		{
			name:         "assignment",
			input:        "password=prefix-" + accessKey + "-suffix",
			want:         "password=[REDACTED:CREDENTIAL_ASSIGNMENT]",
			wantCategory: CredentialAssignment,
		},
		{
			name:         "url userinfo",
			input:        "https://demo:prefix-" + accessKey + "-suffix@example.test/path",
			want:         "https://[REDACTED:URL_CREDENTIAL]@example.test/path",
			wantCategory: URLCredential,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewRedactor(nil).RedactString(tt.input)
			if result.Text != tt.want {
				t.Fatalf("RedactString() = %q, want %q", result.Text, tt.want)
			}
			if result.Counts[tt.wantCategory] != 1 || result.Counts[AccessKey] != 0 {
				t.Fatalf("RedactString() counts = %#v", result.Counts)
			}
		})
	}
}

func TestRedactorLimitBoundsInputAndExpandedOutput(t *testing.T) {
	const maxBytes = 29
	input := "prefix password=synthetic-value suffix " + strings.Repeat("界", 64)
	result := NewRedactor(nil).WithMaxBytes(maxBytes).RedactString(input)
	if !result.Truncated {
		t.Fatal("RedactString() Truncated = false, want true")
	}
	if len(result.Text) > maxBytes {
		t.Fatalf("RedactString() returned %d bytes, max %d: %q", len(result.Text), maxBytes, result.Text)
	}
	if !utf8.ValidString(result.Text) {
		t.Fatalf("RedactString() truncated invalid UTF-8: %x", []byte(result.Text))
	}
	if strings.Contains(result.Text, "synthetic-value") {
		t.Fatalf("RedactString() leaked truncated input: %q", result.Text)
	}
}

func TestRedactorDoesNotExposeIPAddressPrefixAtStringLimit(t *testing.T) {
	const exposedPrefix = "peer=192.0.2."
	input := "peer=192.0.2.123 suffix"
	result := NewRedactor(nil).WithMaxBytes(len(exposedPrefix)).RedactString(input)
	if !result.Truncated || len(result.Text) > len(exposedPrefix) {
		t.Fatalf("RedactString() = %#v", result)
	}
	if strings.Contains(result.Text, "192.0.2.") {
		t.Fatalf("RedactString() exposed IP prefix at limit: %q", result.Text)
	}
	if result.Counts[IPAddress] != 1 {
		t.Fatalf("RedactString() counts = %#v", result.Counts)
	}
}

func TestRedactorLookaheadDoesNotRedactTruncatedVersion(t *testing.T) {
	const publicPrefix = "version=1.2."
	result := NewRedactor(nil).WithMaxBytes(len(publicPrefix)).RedactString("version=1.2.3 suffix")
	if result.Text != publicPrefix || result.Counts[IPAddress] != 0 || !result.Truncated {
		t.Fatalf("RedactString() = %#v", result)
	}
}

func TestRedactorDoesNotExposeURLCredentialAtStringLimit(t *testing.T) {
	const publicPrefix = "https://demo-user"
	result := NewRedactor(nil).WithMaxBytes(len(publicPrefix)).RedactString(publicPrefix + ":synthetic-pass@example.test/path")
	if !result.Truncated || strings.Contains(result.Text, "demo-user") || result.Counts[URLCredential] != 1 {
		t.Fatalf("RedactString() = %#v", result)
	}
}

func TestRedactorProtectsAmbiguousLongURLAuthorityAtLimit(t *testing.T) {
	const maxBytes = 50
	input := "https://" + strings.Repeat("u", 300) + ":synthetic-pass@example.test/path"
	result := NewRedactor(nil).WithMaxBytes(maxBytes).RedactString(input)
	if !result.Truncated || result.Counts[URLCredential] != 1 {
		t.Fatalf("RedactString() = %#v", result)
	}
	if strings.Contains(result.Text, strings.Repeat("u", 30)) {
		t.Fatalf("RedactString() leaked ambiguous URL authority prefix: %q", result.Text)
	}
}

func TestRedactorDoesNotOverRedactResolvedURLAuthorityAtLimit(t *testing.T) {
	ordinaryHost := "https://" + strings.Repeat("h", 80) + "/path"
	ordinary := NewRedactor(nil).WithMaxBytes(50).RedactString(ordinaryHost)
	if ordinary.Counts[URLCredential] != 0 || ordinary.Text != ordinaryHost[:50] {
		t.Fatalf("ordinary truncated host = %#v", ordinary)
	}

	pathInput := "https://example.test/path/" + strings.Repeat("p", 80)
	pathLimit := len("https://example.test/path")
	pathResult := NewRedactor(nil).WithMaxBytes(pathLimit).RedactString(pathInput)
	if pathResult.Counts[URLCredential] != 0 || pathResult.Text != pathInput[:pathLimit] {
		t.Fatalf("URL truncated at path = %#v", pathResult)
	}
}

func TestStreamRedactorBuffersUntilCloseAcrossEveryChunkBoundary(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-STREAM-PEM\n-----END PRIVATE KEY-----"
	input := "Bearer synthetic-stream-token\nIP=2001:db8::9\n" + pem
	want := NewRedactor(nil).RedactString(input)

	for split := 0; split <= len(input); split++ {
		var dst bytes.Buffer
		stream := NewStreamRedactor(&dst, nil)
		for _, chunk := range []string{input[:split], input[split:]} {
			if _, err := stream.Write([]byte(chunk)); err != nil {
				t.Fatalf("split %d Write() error = %v", split, err)
			}
			if dst.Len() != 0 {
				t.Fatalf("split %d released %q before Close", split, dst.String())
			}
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("split %d Close() error = %v", split, err)
		}
		if dst.String() != want.Text {
			t.Fatalf("split %d output = %q, want %q", split, dst.String(), want.Text)
		}
		if got := stream.Result(); got.Text != want.Text || !equalRedactionCounts(got.Counts, want.Counts) || got.Truncated != want.Truncated {
			t.Fatalf("split %d Result() = %#v, want %#v", split, got, want)
		}
	}

	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil)
	for i := range len(input) {
		if _, err := stream.Write([]byte{input[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if dst.Len() != 0 {
		t.Fatalf("byte-wise writes released %q before Close", dst.String())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if dst.String() != want.Text {
		t.Fatalf("byte-wise output = %q, want %q", dst.String(), want.Text)
	}
}

func TestStreamRedactorBoundsMemoryAndOutputAndReportsTruncation(t *testing.T) {
	const maxBytes = 64
	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil).WithMaxBytes(maxBytes)
	input := []byte("password=synthetic-stream-value " + strings.Repeat("x", 4096))
	if n, err := stream.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(input))
	}
	if dst.Len() != 0 {
		t.Fatalf("Write() released output before Close: %q", dst.String())
	}
	if len(stream.buffer) > maxBytes+redactionLookaheadBytes || cap(stream.buffer) > maxBytes+redactionLookaheadBytes {
		t.Fatalf("stream buffer exceeds bounded lookahead: len=%d cap=%d", len(stream.buffer), cap(stream.buffer))
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	result := stream.Result()
	if !result.Truncated || len(result.Text) > maxBytes || dst.String() != result.Text {
		t.Fatalf("Result() = %#v, dst=%q", result, dst.String())
	}
	if !utf8.ValidString(result.Text) || strings.Contains(result.Text, "synthetic-stream-value") {
		t.Fatalf("bounded output is unsafe: %q", result.Text)
	}
}

func TestStreamRedactorDoesNotExposeIPAddressPrefixAtLimit(t *testing.T) {
	const exposedPrefix = "peer=192.0.2."
	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil).WithMaxBytes(len(exposedPrefix))
	for _, chunk := range []string{exposedPrefix, "123 suffix"} {
		if n, err := stream.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(chunk))
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	result := stream.Result()
	if !result.Truncated || len(result.Text) > len(exposedPrefix) {
		t.Fatalf("Result() = %#v", result)
	}
	if strings.Contains(result.Text, "192.0.2.") || strings.Contains(dst.String(), "192.0.2.") {
		t.Fatalf("stream exposed IP prefix at limit: result=%q dst=%q", result.Text, dst.String())
	}
	if result.Counts[IPAddress] != 1 {
		t.Fatalf("Result() counts = %#v", result.Counts)
	}
}

func TestStreamRedactorDoesNotExposeURLCredentialAtLimit(t *testing.T) {
	const publicPrefix = "https://demo-user"
	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil).WithMaxBytes(len(publicPrefix))
	input := publicPrefix + ":synthetic-pass@example.test/path"
	if _, err := stream.Write([]byte(input[:len(publicPrefix)])); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte(input[len(publicPrefix):])); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	result := stream.Result()
	if !result.Truncated || strings.Contains(result.Text, "demo-user") || strings.Contains(dst.String(), "demo-user") || result.Counts[URLCredential] != 1 {
		t.Fatalf("stream result=%#v dst=%q", result, dst.String())
	}
}

func TestStreamRedactorProtectsAmbiguousLongURLAuthorityAtLimit(t *testing.T) {
	const maxBytes = 50
	input := "https://" + strings.Repeat("u", 300) + ":synthetic-pass@example.test/path"
	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil).WithMaxBytes(maxBytes)
	if _, err := stream.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	result := stream.Result()
	if !result.Truncated || result.Counts[URLCredential] != 1 || strings.Contains(result.Text, strings.Repeat("u", 30)) || strings.Contains(dst.String(), strings.Repeat("u", 30)) {
		t.Fatalf("stream result=%#v dst=%q", result, dst.String())
	}
}

func TestStreamRedactorCloseAndWriterErrorSemantics(t *testing.T) {
	var dst bytes.Buffer
	stream := NewStreamRedactor(&dst, nil)
	if err := stream.Close(); err != nil {
		t.Fatalf("Close(empty) error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close(empty) error = %v", err)
	}
	if _, err := stream.Write([]byte("later")); !errors.Is(err, ErrStreamRedactorClosed) {
		t.Fatalf("Write(after Close) error = %v, want ErrStreamRedactorClosed", err)
	}
	if _, err := stream.Write(nil); !errors.Is(err, ErrStreamRedactorClosed) {
		t.Fatalf("empty Write(after Close) error = %v, want ErrStreamRedactorClosed", err)
	}

	wantErr := errors.New("synthetic destination failure")
	failing := &errorWriter{err: wantErr}
	failedStream := NewStreamRedactor(failing, nil)
	secret := "synthetic-writer-secret"
	if _, err := failedStream.Write([]byte("password=" + secret)); err != nil {
		t.Fatal(err)
	}
	if err := failedStream.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
	if err := failedStream.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("second Close() error = %v, want stable %v", err, wantErr)
	}
	result := failedStream.Result()
	if strings.Contains(result.Text, secret) || result.Counts[CredentialAssignment] != 1 {
		t.Fatalf("Result() after writer failure leaked secret: %#v", result)
	}
}

func FuzzRedactor(f *testing.F) {
	const (
		adjacentIPv6Seed = "2001:db8::1,2001:db8::2"
		assignmentSeed   = "password=FUZZ-SYNTHETIC"
		pemSeed          = "-----BEGIN EC PRIVATE KEY-----\nFUZZ-PEM-PAYLOAD\n-----END EC PRIVATE KEY-----"
	)
	f.Add([]byte("ordinary output"), 3)
	f.Add([]byte{}, 0)
	f.Add([]byte{0xff, 0xfe, 'x'}, 1)
	f.Add([]byte(strings.Repeat("long", 1024)), 31)
	f.Add([]byte(adjacentIPv6Seed), 7)
	f.Add([]byte(pemSeed), 5)
	f.Add([]byte(assignmentSeed), 2)

	f.Fuzz(func(t *testing.T, input []byte, chunkSize int) {
		const maxBytes = 512
		redactor := NewRedactor(nil).WithMaxBytes(maxBytes)
		want := redactor.RedactString(string(input))
		if len(want.Text) > maxBytes || !utf8.ValidString(want.Text) {
			t.Fatalf("RedactString() returned invalid bounded output: %#v", want)
		}
		if len(input) > maxBytes && !want.Truncated {
			t.Fatalf("RedactString() did not report truncation for %d bytes", len(input))
		}
		inputText := string(input)
		switch inputText {
		case adjacentIPv6Seed:
			if strings.Contains(want.Text, "2001:db8::1") || strings.Contains(want.Text, "2001:db8::2") || want.Counts[IPAddress] != 2 {
				t.Fatalf("RedactString() did not safely redact adjacent IPv6 seed: %#v", want)
			}
		case pemSeed:
			if strings.Contains(want.Text, "FUZZ-PEM-PAYLOAD") || want.Counts[PrivateKeyBlock] != 1 {
				t.Fatalf("RedactString() leaked seeded PEM payload: %#v", want)
			}
		case assignmentSeed:
			if strings.Contains(want.Text, "FUZZ-SYNTHETIC") || want.Counts[CredentialAssignment] != 1 {
				t.Fatalf("RedactString() leaked seeded credential assignment: %#v", want)
			}
		}

		var dst bytes.Buffer
		stream := NewStreamRedactor(&dst, nil).WithMaxBytes(maxBytes)
		if len(input) == 0 {
			if n, err := stream.Write(nil); err != nil || n != 0 {
				t.Fatalf("empty Write() = (%d, %v), want (0, nil)", n, err)
			}
		}
		chunkSize = int(uint(chunkSize)%31) + 1
		for offset := 0; offset < len(input); {
			end := offset + chunkSize
			if end > len(input) {
				end = len(input)
			}
			if n, err := stream.Write(input[offset:end]); err != nil || n != end-offset {
				t.Fatalf("Write() = (%d, %v)", n, err)
			}
			if dst.Len() != 0 {
				t.Fatalf("stream released output before Close: %q", dst.String())
			}
			offset = end
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		got := stream.Result()
		if got.Text != want.Text || got.Truncated != want.Truncated || !equalRedactionCounts(got.Counts, want.Counts) {
			t.Fatalf("stream Result() = %#v, want %#v", got, want)
		}
	})
}

type errorWriter struct {
	err error
}

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }

func equalRedactionCounts(left, right map[RedactionCategory]int) bool {
	if len(left) != len(right) {
		return false
	}
	for category, count := range left {
		if right[category] != count {
			return false
		}
	}
	return true
}

var _ io.WriteCloser = (*StreamRedactor)(nil)
