package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var testKDFParams = KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

type testEnvelope struct {
	Version    int       `json:"version"`
	KDF        KDFParams `json:"kdf"`
	Salt       string    `json:"salt"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

func TestSealOpenRoundTrip(t *testing.T) {
	want := Data{Servers: map[string]ServerSecret{
		"prod": {
			Host:            "prod.internal.example",
			Port:            2222,
			User:            "deploy",
			Password:        []byte("correct horse battery staple"),
			HostFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz",
		},
	}}

	sealed, err := Seal([]byte("master password"), want, testKDFParams)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	got, err := Open([]byte("master password"), sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Open() = %#v, want %#v", got, want)
	}
}

func TestOpenWrongMasterReturnsInvalidPasswordWithoutSecrets(t *testing.T) {
	data := Data{Servers: map[string]ServerSecret{
		"prod": {Host: "secret-host.internal", Password: []byte("server-password")},
	}}
	sealed, err := Seal([]byte("right-master"), data, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open([]byte("wrong-master"), sealed)
	assertSanitizedError(t, err, ErrInvalidPassword, "secret-host.internal", "server-password", string(sealed))
}

func TestOpenRejectsAuthenticatedEnvelopeTampering(t *testing.T) {
	sealed, err := Seal([]byte("master"), Data{Servers: map[string]ServerSecret{
		"prod": {Host: "prod.internal", Password: []byte("secret-password")},
	}}, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*testEnvelope)
	}{
		{
			name: "ciphertext",
			mutate: func(envelope *testEnvelope) {
				envelope.Ciphertext = mutateBase64(t, envelope.Ciphertext)
			},
		},
		{
			name: "nonce",
			mutate: func(envelope *testEnvelope) {
				envelope.Nonce = mutateBase64(t, envelope.Nonce)
			},
		},
		{
			name: "salt",
			mutate: func(envelope *testEnvelope) {
				envelope.Salt = mutateBase64(t, envelope.Salt)
			},
		},
		{
			name: "kdf metadata included in aad",
			mutate: func(envelope *testEnvelope) {
				envelope.KDF.Parallelism = 2
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := decodeTestEnvelope(t, sealed)
			tt.mutate(&envelope)
			tampered, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}

			_, err = Open([]byte("master"), tampered)
			assertSanitizedError(t, err, ErrInvalidPassword, "prod.internal", "secret-password", string(tampered))
		})
	}
}

func TestSealUsesRandomSaltAndNonce(t *testing.T) {
	data := Data{Servers: map[string]ServerSecret{"prod": {Host: "example.com"}}}
	first, err := Seal([]byte("master"), data, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal([]byte("master"), data, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	firstEnvelope := decodeTestEnvelope(t, first)
	secondEnvelope := decodeTestEnvelope(t, second)
	if firstEnvelope.Salt == secondEnvelope.Salt {
		t.Fatal("Seal() reused salt")
	}
	if firstEnvelope.Nonce == secondEnvelope.Nonce {
		t.Fatal("Seal() reused nonce")
	}
	if string(first) == string(second) {
		t.Fatal("Seal() produced identical envelopes for identical inputs")
	}
}

func TestDefaultKDFParams(t *testing.T) {
	want := KDFParams{MemoryKiB: 65536, Iterations: 3, Parallelism: 2}
	if got := DefaultKDFParams(); got != want {
		t.Fatalf("DefaultKDFParams() = %#v, want %#v", got, want)
	}
}

func TestSealRejectsEmptyMasterAndInvalidKDFParams(t *testing.T) {
	if _, err := Seal(nil, Data{}, testKDFParams); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Seal(empty master) error = %v, want ErrInvalidPassword", err)
	}

	tests := []struct {
		name   string
		params KDFParams
	}{
		{"memory zero", KDFParams{MemoryKiB: 0, Iterations: 1, Parallelism: 1}},
		{"memory below minimum", KDFParams{MemoryKiB: 7, Iterations: 1, Parallelism: 1}},
		{"memory above maximum", KDFParams{MemoryKiB: 262145, Iterations: 1, Parallelism: 1}},
		{"iterations zero", KDFParams{MemoryKiB: 64, Iterations: 0, Parallelism: 1}},
		{"iterations above maximum", KDFParams{MemoryKiB: 64, Iterations: 11, Parallelism: 1}},
		{"parallelism zero", KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 0}},
		{"parallelism above maximum", KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 17}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Seal([]byte("master"), Data{}, tt.params)
			assertSanitizedError(t, err, ErrInvalidEnvelope)
		})
	}
}

func TestOpenRejectsMalformedUnknownAndHostileEnvelopes(t *testing.T) {
	valid, err := Seal([]byte("master"), Data{}, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}

	badVersion := decodeTestEnvelope(t, valid)
	badVersion.Version = 2
	badVersionJSON, err := json.Marshal(badVersion)
	if err != nil {
		t.Fatal(err)
	}

	hostileKDF := decodeTestEnvelope(t, valid)
	hostileKDF.KDF.MemoryKiB = 262145
	hostileKDFJSON, err := json.Marshal(hostileKDF)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		envelope []byte
	}{
		{"malformed json", []byte(`{"version":`)},
		{"unknown field", append(valid[:len(valid)-1], []byte(`,"unexpected":true}`)...)},
		{"trailing document", append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{"unknown version", badVersionJSON},
		{"hostile kdf", hostileKDFJSON},
		{"invalid salt base64", replaceEnvelopeField(t, valid, "salt", "not-base64")},
		{"wrong salt size", replaceEnvelopeField(t, valid, "salt", base64.StdEncoding.EncodeToString(make([]byte, 15)))},
		{"wrong nonce size", replaceEnvelopeField(t, valid, "nonce", base64.StdEncoding.EncodeToString(make([]byte, 23)))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open([]byte("master"), tt.envelope)
			assertSanitizedError(t, err, ErrInvalidEnvelope, string(tt.envelope))
		})
	}

	if _, err := Open(nil, valid); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Open(empty master) error = %v, want ErrInvalidPassword", err)
	}
}

func TestZeroOverwritesByteSlice(t *testing.T) {
	secret := []byte("sensitive bytes")
	Zero(secret)
	for i, value := range secret {
		if value != 0 {
			t.Fatalf("secret[%d] = %d, want 0", i, value)
		}
	}
}

func decodeTestEnvelope(t *testing.T, data []byte) testEnvelope {
	t.Helper()
	var envelope testEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func mutateBase64(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0] ^= 0xff
	return base64.StdEncoding.EncodeToString(decoded)
}

func replaceEnvelopeField(t *testing.T, data []byte, field, value string) []byte {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope[field] = value
	result, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSanitizedError(t *testing.T, err, want error, forbidden ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err.Error() != want.Error() {
		t.Fatalf("error text = %q, want stable sanitized %q", err, want)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("error %q leaked %q", err, value)
		}
	}
}
