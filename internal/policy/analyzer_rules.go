package policy

import (
	"path/filepath"
	"strings"
)

func classifyCall(args []staticArg) []Finding {
	var findings []Finding
	if len(args) == 0 || !args[0].Known {
		return nil
	}
	command := filepath.Base(args[0].Value)
	commandArgs := args[1:]
	if command == "openssl" && isOpenSSLPrivateKeyInput(commandArgs) {
		findings = append(findings, labeledFinding(PrivateKey, labelPrivateKeyInput))
	}
	switch {
	case command == "env" && isEnvironmentListing(commandArgs):
		findings = append(findings, labeledFinding(ProcessEnvironment, labelEnvironmentCommand))
	case command == "printenv":
		findings = append(findings, labeledFinding(ProcessEnvironment, labelEnvironmentCommand))
		if containsCloudEnvironment(commandArgs) {
			findings = append(findings, labeledFinding(CloudCredential, labelCloudEnvironment))
		}
	case command == "set" && len(commandArgs) == 0:
		findings = append(findings, labeledFinding(ProcessEnvironment, labelEnvironmentCommand))
	case command == "ip" && containsIPSubcommand(commandArgs):
		findings = append(findings, labeledFinding(NetworkIdentity, labelNetworkCommand))
	case command == "ifconfig", command == "ss", command == "netstat", command == "route":
		findings = append(findings, labeledFinding(NetworkIdentity, labelNetworkCommand))
	case command == "hostname" && containsWord(commandArgs, "-I"):
		findings = append(findings, labeledFinding(NetworkIdentity, labelNetworkCommand))
	case isPublicIPLookup(command, commandArgs):
		findings = append(findings, labeledFinding(NetworkIdentity, labelPublicIPLookup))
	}
	return findings
}

func isEnvironmentListing(args []staticArg) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !arg.Known {
			return false
		}
		switch arg.Value {
		case "-0", "-i", "--ignore-environment":
			continue
		case "--":
			return i == len(args)-1
		case "-u", "--unset":
			if i+1 >= len(args) || !args[i+1].Known || !isEnvironmentName(args[i+1].Value) {
				return false
			}
			i++
			continue
		}
		if strings.HasPrefix(arg.Value, "--unset=") {
			if !isEnvironmentName(strings.TrimPrefix(arg.Value, "--unset=")) {
				return false
			}
			continue
		}
		if isEnvironmentAssignment(arg.Value) {
			continue
		}
		return false
	}
	return true
}

func isEnvironmentAssignment(value string) bool {
	equals := strings.IndexByte(value, '=')
	if equals <= 0 {
		return false
	}
	return isEnvironmentName(value[:equals])
}

func isEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for i, char := range value {
		if char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || i > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func classifyPath(value string) []Finding {
	normalized := strings.ToLower(strings.TrimSuffix(value, "/"))
	switch {
	case isSSHPath(normalized):
		return []Finding{labeledFinding(SSHSecret, labelSSHSensitivePath)}
	case isApplicationCredentialPath(normalized):
		return []Finding{labeledFinding(CloudCredential, labelApplicationCredentialPath)}
	case isCloudPath(normalized):
		return []Finding{labeledFinding(CloudCredential, labelCloudCredentialPath)}
	case isProcessEnvironmentPath(normalized):
		return []Finding{labeledFinding(ProcessEnvironment, labelProcessEnvironmentPath)}
	case isDatabasePath(normalized):
		return []Finding{labeledFinding(DatabaseCredential, labelDatabaseCredentialPath)}
	case isKubernetesPath(normalized):
		return []Finding{labeledFinding(KubernetesSecret, labelKubernetesSensitivePath)}
	case isNetworkPath(normalized):
		return []Finding{labeledFinding(NetworkIdentity, labelNetworkIdentityPath)}
	case isPrivateKeyPath(normalized):
		return []Finding{labeledFinding(PrivateKey, labelPrivateKeyPath)}
	default:
		return nil
	}
}

func isApplicationCredentialPath(path string) bool {
	switch filepath.Base(path) {
	case ".git-credentials", ".netrc", ".npmrc", ".pypirc":
		return true
	}
	return path == "~/.docker/config.json" || strings.HasSuffix(path, "/.docker/config.json") ||
		path == "~/.config/gh/hosts.yml" || strings.HasSuffix(path, "/.config/gh/hosts.yml") ||
		path == "~/.cargo/credentials" || strings.HasSuffix(path, "/.cargo/credentials") ||
		path == "~/.cargo/credentials.toml" || strings.HasSuffix(path, "/.cargo/credentials.toml") ||
		path == "~/.config/git/credentials" || strings.HasSuffix(path, "/.config/git/credentials")
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

func containsCloudEnvironment(args []staticArg) bool {
	for _, arg := range args {
		if arg.Known && isCloudEnvironment(arg.Value) {
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

func isOpenSSLPrivateKeyInput(args []staticArg) bool {
	privateSubcommand := false
	for _, arg := range args {
		if !arg.Known {
			continue
		}
		switch arg.Value {
		case "pkey", "rsa", "ec", "dsa", "pkcs8":
			privateSubcommand = true
		}
	}
	if !privateSubcommand {
		return false
	}
	for i := 0; i+1 < len(args); i++ {
		if !args[i].Known || args[i].Value != "-in" || !args[i+1].Known {
			continue
		}
		path := strings.ToLower(args[i+1].Value)
		base := filepath.Base(path)
		return isPrivateKeyPath(path) || strings.HasSuffix(base, ".pem") && strings.Contains(path, "/private/")
	}
	return false
}

func containsIPSubcommand(args []staticArg) bool {
	for _, arg := range args {
		if !arg.Known {
			return false
		}
		if strings.HasPrefix(arg.Value, "-") {
			continue
		}
		switch arg.Value {
		case "addr", "address", "route", "link", "neigh", "neighbor":
			return true
		default:
			return false
		}
	}
	return false
}

func containsWord(args []staticArg, target string) bool {
	for _, arg := range args {
		if arg.Known && arg.Value == target {
			return true
		}
	}
	return false
}

func isPublicIPLookup(command string, args []staticArg) bool {
	if command != "curl" && command != "wget" && command != "dig" && command != "host" {
		return false
	}
	for _, arg := range args {
		if !arg.Known {
			continue
		}
		lower := strings.ToLower(arg.Value)
		if strings.Contains(lower, "api.ipify.org") || strings.Contains(lower, "ifconfig.me") ||
			strings.Contains(lower, "icanhazip.com") || strings.Contains(lower, "checkip.amazonaws.com") ||
			strings.Contains(lower, "myip.opendns.com") {
			return true
		}
	}
	return false
}
