package vault

import (
	"bytes"
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
		"key-prod": {
			Host: "key.internal.example", Port: 22, User: "deploy",
			AuthMethod: AuthMethodPrivateKey, PrivateKey: []byte("private-key"),
			PrivateKeyPassphrase: []byte("key-passphrase"), HostFingerprint: "SHA256:key-fingerprint",
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

func TestServerSecretLegacyAuthCloneAndZero(t *testing.T) {
	legacy := ServerSecret{Password: []byte("legacy-password")}
	if legacy.EffectiveAuthMethod() != AuthMethodPassword {
		t.Fatalf("legacy method = %q", legacy.EffectiveAuthMethod())
	}
	original := ServerSecret{
		AuthMethod: AuthMethodPrivateKey, PrivateKey: []byte("private-key"), PrivateKeyPassphrase: []byte("passphrase"),
	}
	cloned := CloneServerSecret(original)
	if !reflect.DeepEqual(cloned, original) || &cloned.PrivateKey[0] == &original.PrivateKey[0] || &cloned.PrivateKeyPassphrase[0] == &original.PrivateKeyPassphrase[0] {
		t.Fatal("CloneServerSecret did not make independent credential copies")
	}
	keyReference := cloned.PrivateKey
	passphraseReference := cloned.PrivateKeyPassphrase
	ZeroServerSecret(&cloned)
	if cloned.PrivateKey != nil || cloned.PrivateKeyPassphrase != nil || !bytes.Equal(keyReference, make([]byte, len(keyReference))) || !bytes.Equal(passphraseReference, make([]byte, len(passphraseReference))) {
		t.Fatal("ZeroServerSecret did not clear private-key credentials")
	}
}

func TestSealRejectsOversizedEnvelope(t *testing.T) {
	data := dataWithPasswordSize(13 << 20)

	sealed, err := Seal([]byte("master"), data, testKDFParams)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Seal() error = %v, want ErrInvalidEnvelope", err)
	}
	if len(sealed) != 0 {
		t.Fatalf("Seal() returned %d bytes for oversized envelope", len(sealed))
	}
}

func TestSealOpenNearEnvelopeLimit(t *testing.T) {
	want := dataWithPasswordSize(8 << 20)

	sealed, err := Seal([]byte("master"), want, testKDFParams)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if len(sealed) >= MaxEnvelopeBytes {
		t.Fatalf("Seal() length = %d, want below %d", len(sealed), MaxEnvelopeBytes)
	}
	if len(sealed) < MaxEnvelopeBytes*3/4 {
		t.Fatalf("Seal() length = %d, want a near-limit envelope", len(sealed))
	}
	got, err := Open([]byte("master"), sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("Open() data differs from near-limit input")
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

func TestOpenRejectsEmptyAndOversizedEnvelopesBeforeCrypto(t *testing.T) {
	if _, err := Open([]byte("master"), nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Open(empty) error = %v, want ErrInvalidEnvelope", err)
	}

	validShape := []byte(`{"version":2,"kdf":{"memory_kib":64,"iterations":1,"parallelism":1},"salt":"","nonce":"","ciphertext":""}`)
	if len(validShape) >= MaxEnvelopeBytes {
		t.Fatal("test envelope unexpectedly exceeds MaxEnvelopeBytes")
	}
	exactMax := append(append([]byte(nil), validShape...), bytes.Repeat([]byte{' '}, MaxEnvelopeBytes-len(validShape))...)
	if len(exactMax) != MaxEnvelopeBytes {
		t.Fatalf("exact envelope length = %d, want %d", len(exactMax), MaxEnvelopeBytes)
	}
	if _, err := Open([]byte("master"), exactMax); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Open(exact max invalid shape) error = %v, want ErrInvalidEnvelope", err)
	}

	overMax := append(append([]byte(nil), exactMax...), ' ')
	if len(overMax) != MaxEnvelopeBytes+1 {
		t.Fatalf("oversized envelope length = %d, want %d", len(overMax), MaxEnvelopeBytes+1)
	}
	if _, err := Open([]byte("master"), overMax); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Open(over max) error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestOpenRejectsDuplicateEnvelopeFields(t *testing.T) {
	valid, err := Seal([]byte("master"), Data{}, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeTestEnvelope(t, valid)

	rootFields := []struct {
		name  string
		value string
	}{
		{"version", jsonValue(t, decoded.Version)},
		{"kdf", jsonValue(t, decoded.KDF)},
		{"salt", jsonValue(t, decoded.Salt)},
		{"nonce", jsonValue(t, decoded.Nonce)},
		{"ciphertext", jsonValue(t, decoded.Ciphertext)},
	}
	for _, field := range rootFields {
		t.Run("root "+field.name, func(t *testing.T) {
			duplicated := appendObjectField(t, valid, field.name, field.value)
			_, err := Open([]byte("master"), duplicated)
			assertSanitizedError(t, err, ErrInvalidEnvelope, string(duplicated))
		})
	}

	kdfFields := []struct {
		name  string
		value string
	}{
		{"memory_kib", jsonValue(t, decoded.KDF.MemoryKiB)},
		{"iterations", jsonValue(t, decoded.KDF.Iterations)},
		{"parallelism", jsonValue(t, decoded.KDF.Parallelism)},
	}
	for _, field := range kdfFields {
		t.Run("kdf "+field.name, func(t *testing.T) {
			duplicated := appendKDFField(t, valid, field.name, field.value)
			_, err := Open([]byte("master"), duplicated)
			assertSanitizedError(t, err, ErrInvalidEnvelope, string(duplicated))
		})
	}
}

func TestOpenRejectsCaseVariantEnvelopeFields(t *testing.T) {
	valid, err := Seal([]byte("master"), Data{}, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeTestEnvelope(t, valid)

	rootFields := []struct {
		name    string
		variant string
		value   string
	}{
		{"version", "Version", jsonValue(t, decoded.Version)},
		{"kdf", "KDF", jsonValue(t, decoded.KDF)},
		{"salt", "Salt", jsonValue(t, decoded.Salt)},
		{"nonce", "Nonce", jsonValue(t, decoded.Nonce)},
		{"ciphertext", "Ciphertext", jsonValue(t, decoded.Ciphertext)},
	}
	for _, field := range rootFields {
		t.Run("root "+field.name, func(t *testing.T) {
			variant := appendObjectField(t, valid, field.variant, field.value)
			_, err := Open([]byte("master"), variant)
			assertSanitizedError(t, err, ErrInvalidEnvelope, string(variant))
		})
	}

	kdfFields := []struct {
		name    string
		variant string
		value   string
	}{
		{"memory_kib", "MEMORY_KIB", jsonValue(t, decoded.KDF.MemoryKiB)},
		{"iterations", "Iterations", jsonValue(t, decoded.KDF.Iterations)},
		{"parallelism", "Parallelism", jsonValue(t, decoded.KDF.Parallelism)},
	}
	for _, field := range kdfFields {
		t.Run("kdf "+field.name, func(t *testing.T) {
			variant := appendKDFField(t, valid, field.variant, field.value)
			_, err := Open([]byte("master"), variant)
			assertSanitizedError(t, err, ErrInvalidEnvelope, string(variant))
		})
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

func appendKDFField(t *testing.T, data []byte, field, value string) []byte {
	t.Helper()
	decoded := decodeTestEnvelope(t, data)
	canonicalKDF := jsonValue(t, decoded.KDF)
	mutatedKDF := string(appendObjectField(t, []byte(canonicalKDF), field, value))
	needle := `"kdf":` + canonicalKDF
	replacement := `"kdf":` + mutatedKDF
	mutated := strings.Replace(string(data), needle, replacement, 1)
	if mutated == string(data) {
		t.Fatal("canonical kdf object not found")
	}
	return []byte(mutated)
}

func appendObjectField(t *testing.T, object []byte, field, value string) []byte {
	t.Helper()
	if len(object) == 0 || object[len(object)-1] != '}' {
		t.Fatalf("object = %q, want JSON object", object)
	}
	result := append([]byte(nil), object[:len(object)-1]...)
	result = append(result, ',')
	result = append(result, jsonValue(t, field)...)
	result = append(result, ':')
	result = append(result, value...)
	result = append(result, '}')
	return result
}

func jsonValue(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func dataWithPasswordSize(size int) Data {
	return Data{Servers: map[string]ServerSecret{
		"large": {
			Host:     "large.example.com",
			Port:     22,
			User:     "root",
			Password: bytes.Repeat([]byte{'x'}, size),
		},
	}}
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
