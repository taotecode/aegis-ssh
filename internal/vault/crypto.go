package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxEnvelopeBytes = 16 << 20

	envelopeVersion = 1
	saltSize        = 16
	keySize         = 32

	minMemoryKiB   = 8
	maxMemoryKiB   = 262144
	minIterations  = 1
	maxIterations  = 10
	minParallelism = 1
	maxParallelism = 16
)

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidEnvelope = errors.New("invalid vault envelope")
)

type ServerSecret struct {
	Host            string `json:"host"`
	Port            uint16 `json:"port"`
	User            string `json:"user"`
	Password        []byte `json:"password"`
	HostFingerprint string `json:"host_fingerprint"`
}

type Data struct {
	Servers map[string]ServerSecret `json:"servers"`
}

type KDFParams struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

type envelope struct {
	Version    int       `json:"version"`
	KDF        KDFParams `json:"kdf"`
	Salt       string    `json:"salt"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

func DefaultKDFParams() KDFParams {
	return KDFParams{MemoryKiB: 65536, Iterations: 3, Parallelism: 2}
}

func Seal(master []byte, data Data, params KDFParams) ([]byte, error) {
	if len(master) == 0 {
		return nil, ErrInvalidPassword
	}
	if !validKDFParams(params) {
		return nil, ErrInvalidEnvelope
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Zero(plaintext)

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Zero(salt)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Zero(nonce)

	key := argon2.IDKey(master, salt, params.Iterations, params.MemoryKiB, params.Parallelism, keySize)
	defer Zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData(params))
	defer Zero(ciphertext)

	encoded, err := json.Marshal(envelope{
		Version:    envelopeVersion,
		KDF:        params,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return encoded, nil
}

func Open(master, encoded []byte) (Data, error) {
	if len(encoded) == 0 || len(encoded) > MaxEnvelopeBytes {
		return Data{}, ErrInvalidEnvelope
	}
	if len(master) == 0 {
		return Data{}, ErrInvalidPassword
	}

	var sealed envelope
	if err := decodeEnvelopeJSON(encoded, &sealed); err != nil {
		return Data{}, ErrInvalidEnvelope
	}
	if sealed.Version != envelopeVersion || !validKDFParams(sealed.KDF) {
		return Data{}, ErrInvalidEnvelope
	}

	salt, err := base64.StdEncoding.DecodeString(sealed.Salt)
	if err != nil || len(salt) != saltSize {
		return Data{}, ErrInvalidEnvelope
	}
	defer Zero(salt)
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return Data{}, ErrInvalidEnvelope
	}
	defer Zero(nonce)
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil || len(ciphertext) < chacha20poly1305.Overhead {
		return Data{}, ErrInvalidEnvelope
	}
	defer Zero(ciphertext)

	key := argon2.IDKey(master, salt, sealed.KDF.Iterations, sealed.KDF.MemoryKiB, sealed.KDF.Parallelism, keySize)
	defer Zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Data{}, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData(sealed.KDF))
	if err != nil {
		return Data{}, ErrInvalidPassword
	}
	defer Zero(plaintext)

	var data Data
	if err := decodeStrictJSON(plaintext, &data); err != nil {
		return Data{}, ErrInvalidEnvelope
	}
	return data, nil
}

func Zero(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

func validKDFParams(params KDFParams) bool {
	return params.MemoryKiB >= minMemoryKiB && params.MemoryKiB <= maxMemoryKiB &&
		params.Iterations >= minIterations && params.Iterations <= maxIterations &&
		params.Parallelism >= minParallelism && params.Parallelism <= maxParallelism
}

func associatedData(params KDFParams) []byte {
	data := make([]byte, 13)
	binary.BigEndian.PutUint32(data[0:4], envelopeVersion)
	binary.BigEndian.PutUint32(data[4:8], params.MemoryKiB)
	binary.BigEndian.PutUint32(data[8:12], params.Iterations)
	data[12] = params.Parallelism
	return data
}

func decodeEnvelopeJSON(data []byte, target *envelope) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decodeExactObject(decoder, map[string]func() error{
		"version": func() error { return decoder.Decode(&target.Version) },
		"kdf": func() error {
			return decodeExactObject(decoder, map[string]func() error{
				"memory_kib":  func() error { return decoder.Decode(&target.KDF.MemoryKiB) },
				"iterations":  func() error { return decoder.Decode(&target.KDF.Iterations) },
				"parallelism": func() error { return decoder.Decode(&target.KDF.Parallelism) },
			})
		},
		"salt":       func() error { return decoder.Decode(&target.Salt) },
		"nonce":      func() error { return decoder.Decode(&target.Nonce) },
		"ciphertext": func() error { return decoder.Decode(&target.Ciphertext) },
	}); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	return nil
}

func decodeExactObject(decoder *json.Decoder, fields map[string]func() error) error {
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return ErrInvalidEnvelope
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidEnvelope
		}
		name, ok := token.(string)
		if !ok {
			return ErrInvalidEnvelope
		}
		decode, ok := fields[name]
		if !ok {
			return ErrInvalidEnvelope
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalidEnvelope
		}
		seen[name] = struct{}{}
		if err := decode(); err != nil {
			return ErrInvalidEnvelope
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
		return ErrInvalidEnvelope
	}
	return nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidEnvelope
		}
		return err
	}
	return nil
}
