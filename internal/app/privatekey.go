package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/taotecode/aegis-ssh/internal/vault"
	"golang.org/x/crypto/ssh"
)

const maxPrivateKeyBytes = 1 << 20

func readPrivateKeyFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrPrivateKey
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, ErrPrivateKey
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPrivateKey
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxPrivateKeyBytes {
		return nil, ErrPrivateKey
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return nil, ErrPrivateKey
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxPrivateKeyBytes {
		vault.Zero(data)
		return nil, ErrPrivateKey
	}
	return data, nil
}

func validAuthMethod(method vault.AuthMethod) bool {
	return method == vault.AuthMethodPassword || method == vault.AuthMethodPrivateKey
}

func (application *App) readAuthentication(terminal Terminal, method vault.AuthMethod) (vault.ServerSecret, error) {
	switch method {
	case vault.AuthMethodPassword:
		password, err := ReadSecret(terminal, "SSH password: ")
		if err != nil {
			return vault.ServerSecret{}, err
		}
		return vault.ServerSecret{AuthMethod: method, Password: password}, nil
	case vault.AuthMethodPrivateKey:
		path, err := ReadText(terminal, "Private key file: ")
		if err != nil {
			return vault.ServerSecret{}, ErrPrivateKey
		}
		privateKey, err := application.deps.ReadPrivateKey(path)
		if err != nil || len(privateKey) == 0 {
			vault.Zero(privateKey)
			return vault.ServerSecret{}, ErrPrivateKey
		}
		secret := vault.ServerSecret{AuthMethod: method, PrivateKey: privateKey}
		if _, err := ssh.ParsePrivateKey(secret.PrivateKey); err == nil {
			return secret, nil
		} else {
			var missing *ssh.PassphraseMissingError
			if !errors.As(err, &missing) {
				vault.ZeroServerSecret(&secret)
				return vault.ServerSecret{}, ErrPrivateKey
			}
		}
		passphrase, err := ReadSecret(terminal, "Private key passphrase: ")
		if err != nil {
			vault.ZeroServerSecret(&secret)
			return vault.ServerSecret{}, err
		}
		secret.PrivateKeyPassphrase = passphrase
		if _, err := ssh.ParsePrivateKeyWithPassphrase(secret.PrivateKey, secret.PrivateKeyPassphrase); err != nil {
			vault.ZeroServerSecret(&secret)
			return vault.ServerSecret{}, ErrPrivateKey
		}
		return secret, nil
	default:
		return vault.ServerSecret{}, ErrInvalidAuthMethod
	}
}
