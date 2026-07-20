package policy

import (
	"path/filepath"
	"strings"
)

func classifyCall(words []string) []Finding {
	var findings []Finding
	command := filepath.Base(words[0])
	args := words[1:]
	if isShell(command) {
		for i, word := range args {
			if word == "-c" {
				args = args[:i]
				break
			}
		}
	}
	for _, word := range args {
		findings = append(findings, classifyPath(word)...)
	}
	if command == "openssl" && isOpenSSLPrivateKeyInput(words[1:]) {
		findings = append(findings, Finding{PrivateKey, "private_key_input", "private key input"})
	}
	switch {
	case command == "env" && len(words) == 1:
		findings = append(findings, Finding{ProcessEnvironment, "environment_command", "environment listing command"})
	case command == "printenv":
		findings = append(findings, Finding{ProcessEnvironment, "environment_command", "environment listing command"})
		if containsCloudEnvironment(words[1:]) {
			findings = append(findings, Finding{CloudCredential, "cloud_environment", "cloud credential environment"})
		}
	case command == "set" && len(words) == 1:
		findings = append(findings, Finding{ProcessEnvironment, "environment_command", "environment listing command"})
	case command == "ip" && containsIPSubcommand(words[1:]):
		findings = append(findings, Finding{NetworkIdentity, "network_command", "network identity command"})
	case command == "ifconfig", command == "ss", command == "netstat", command == "route":
		findings = append(findings, Finding{NetworkIdentity, "network_command", "network identity command"})
	case command == "hostname" && containsWord(words[1:], "-I"):
		findings = append(findings, Finding{NetworkIdentity, "network_command", "network identity command"})
	case isPublicIPLookup(command, words[1:]):
		findings = append(findings, Finding{NetworkIdentity, "public_ip_lookup", "public IP lookup command"})
	}
	return findings
}

func classifyPath(value string) []Finding {
	normalized := strings.ToLower(strings.TrimSuffix(value, "/"))
	switch {
	case isSSHPath(normalized):
		return []Finding{{SSHSecret, "ssh_sensitive_path", "ssh sensitive path"}}
	case isCloudPath(normalized):
		return []Finding{{CloudCredential, "cloud_credential_path", "cloud credential path"}}
	case isProcessEnvironmentPath(normalized):
		return []Finding{{ProcessEnvironment, "process_environment_path", "process environment path"}}
	case isDatabasePath(normalized):
		return []Finding{{DatabaseCredential, "database_credential_path", "database credential path"}}
	case isKubernetesPath(normalized):
		return []Finding{{KubernetesSecret, "kubernetes_sensitive_path", "kubernetes sensitive path"}}
	case isNetworkPath(normalized):
		return []Finding{{NetworkIdentity, "network_identity_path", "network identity path"}}
	case isPrivateKeyPath(normalized):
		return []Finding{{PrivateKey, "private_key_path", "private key path"}}
	default:
		return nil
	}
}

func isSSHPath(path string) bool {
	base := filepath.Base(path)
	if base == "authorized_keys" || base == "known_hosts" {
		return true
	}
	if path == "~/.ssh" || strings.HasPrefix(path, "~/.ssh/") ||
		strings.Contains(path, "/.ssh/") || strings.HasSuffix(path, "/.ssh") {
		return true
	}
	if strings.HasPrefix(path, "/etc/ssh/") {
		if strings.HasPrefix(path, "/etc/ssh/ssh_config.d/") || strings.HasPrefix(path, "/etc/ssh/sshd_config.d/") {
			return strings.HasSuffix(path, ".conf")
		}
		return base == "ssh_config" || base == "sshd_config" ||
			(strings.HasPrefix(base, "ssh_host_") && !strings.HasSuffix(base, ".pub")) ||
			(base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" || base == "id_ed25519")
	}
	return false
}

func isCloudPath(path string) bool {
	return path == "~/.aws" || strings.HasPrefix(path, "~/.aws/") ||
		strings.HasSuffix(path, "/.aws") || strings.Contains(path, "/.aws/") ||
		path == "~/.config/gcloud" || strings.HasPrefix(path, "~/.config/gcloud/") ||
		strings.Contains(path, "/.config/gcloud/") || strings.HasSuffix(path, "/.config/gcloud") ||
		path == "~/.azure" || strings.HasPrefix(path, "~/.azure/") ||
		strings.Contains(path, "/.azure/") || strings.HasSuffix(path, "/.azure")
}

func isProcessEnvironmentPath(path string) bool {
	return strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/environ")
}

func isDatabasePath(path string) bool {
	base := filepath.Base(path)
	if base == ".pgpass" || base == ".my.cnf" {
		return true
	}
	compact := strings.NewReplacer("-", "_", ".", "_").Replace(base)
	return strings.Contains(compact, "database_credential") || strings.Contains(compact, "db_credential")
}

func isKubernetesPath(path string) bool {
	return path == "~/.kube/config" || strings.HasSuffix(path, "/.kube/config") ||
		path == "/etc/kubernetes" || strings.HasPrefix(path, "/etc/kubernetes/") ||
		path == "/var/run/secrets/kubernetes.io/serviceaccount" ||
		strings.HasPrefix(path, "/var/run/secrets/kubernetes.io/serviceaccount/")
}

func isNetworkPath(path string) bool {
	return path == "/proc/net" || strings.HasPrefix(path, "/proc/net/") ||
		path == "/etc/hosts" || path == "/etc/resolv.conf"
}

func isPrivateKeyPath(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".key") ||
		(strings.HasSuffix(base, ".pem") && (strings.Contains(base, "private") || strings.Contains(base, "private-key") || strings.Contains(path, "/private/")))
}

func containsCloudEnvironment(words []string) bool {
	for _, word := range words {
		if isCloudEnvironment(word) {
			return true
		}
	}
	return false
}

func isCloudEnvironment(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "AWS_") && (strings.Contains(upper, "KEY") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "CREDENTIAL")) ||
		upper == "GOOGLE_APPLICATION_CREDENTIALS" ||
		strings.HasPrefix(upper, "AZURE_") && (strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "CREDENTIAL"))
}

func isOpenSSLPrivateKeyInput(words []string) bool {
	privateSubcommand := false
	for _, word := range words {
		switch word {
		case "pkey", "rsa", "ec", "dsa", "pkcs8":
			privateSubcommand = true
		}
	}
	if !privateSubcommand {
		return false
	}
	for i := 0; i+1 < len(words); i++ {
		if words[i] != "-in" {
			continue
		}
		path := strings.ToLower(words[i+1])
		base := filepath.Base(path)
		return isPrivateKeyPath(path) || strings.HasSuffix(base, ".pem") && strings.Contains(path, "/private/")
	}
	return false
}

func containsIPSubcommand(words []string) bool {
	for _, word := range words {
		if strings.HasPrefix(word, "-") {
			continue
		}
		switch word {
		case "addr", "address", "route", "link", "neigh", "neighbor":
			return true
		default:
			return false
		}
	}
	return false
}

func containsWord(words []string, target string) bool {
	for _, word := range words {
		if word == target {
			return true
		}
	}
	return false
}

func isPublicIPLookup(command string, words []string) bool {
	if command != "curl" && command != "wget" && command != "dig" && command != "host" {
		return false
	}
	for _, word := range words {
		lower := strings.ToLower(word)
		if strings.Contains(lower, "api.ipify.org") || strings.Contains(lower, "ifconfig.me") ||
			strings.Contains(lower, "icanhazip.com") || strings.Contains(lower, "checkip.amazonaws.com") ||
			strings.Contains(lower, "myip.opendns.com") {
			return true
		}
	}
	return false
}
