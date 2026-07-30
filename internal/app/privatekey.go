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
	return application.readAuthenticationExisting(terminal, method, nil)
}

func (application *App) readAuthenticationExisting(terminal Terminal, method vault.AuthMethod, existing *vault.ServerSecret) (vault.ServerSecret, error) {
	lang := application.language()
	switch method {
	case vault.AuthMethodPassword:
		if existing != nil && existing.EffectiveAuthMethod() == method {
			password, err := ReadOptionalSecret(terminal, localize(lang, "SSH password [leave empty to keep current]: ", "SSH 密码（留空保留当前密码）："))
			if err != nil {
				return vault.ServerSecret{}, err
			}
			if len(password) == 0 {
				return vault.CloneServerSecret(*existing), nil
			}
			return vault.ServerSecret{AuthMethod: method, Password: password}, nil
		}
		password, err := ReadSecret(terminal, localize(lang, "SSH password: ", "SSH 密码："))
		if err != nil {
			return vault.ServerSecret{}, err
		}
		return vault.ServerSecret{AuthMethod: method, Password: password}, nil
	case vault.AuthMethodPrivateKey:
		if existing != nil && existing.EffectiveAuthMethod() == method {
			path, err := ReadText(terminal, localize(lang, "Private key file [leave empty to keep current]: ", "私钥文件（留空保留当前私钥）："))
			if err != nil {
				return vault.ServerSecret{}, ErrPrivateKey
			}
			if path == "" {
				return vault.CloneServerSecret(*existing), nil
			}
			return application.loadPrivateKeyAuthentication(terminal, path, method)
		}
		defaultPath := discoverPrivateKey()
		if defaultPath != "" {
			_, _ = io.WriteString(terminal, localize(lang, "Detected private key: ", "检测到私钥：")+defaultPath+"\n")
		}
		path, err := ReadTextDefault(terminal, localize(lang, "Private key file: ", "私钥文件："), defaultPath)
		if err != nil {
			return vault.ServerSecret{}, ErrPrivateKey
		}
		return application.loadPrivateKeyAuthentication(terminal, path, method)
	default:
		return vault.ServerSecret{}, ErrInvalidAuthMethod
	}
}

func (application *App) loadPrivateKeyAuthentication(terminal Terminal, path string, method vault.AuthMethod) (vault.ServerSecret, error) {
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
	passphrase, err := ReadSecret(terminal, application.text("Private key passphrase: ", "私钥口令："))
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
}

func discoverPrivateKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		path := filepath.Join(home, ".ssh", name)
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
			return path
		}
	}
	return ""
}
