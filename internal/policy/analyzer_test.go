package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestAnalyzerClassifiesCoreSensitiveOperations(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"ssh private key", `cat ~/.ssh/id_ed25519`, []Category{SSHSecret}},
		{"encoded root ssh key", `base64 /root/.ssh/id_rsa`, []Category{SSHSecret}},
		{"process environment pipeline", `env | sort`, []Category{ProcessEnvironment}},
		{"network route", `ip route`, []Category{NetworkIdentity}},
		{"kubernetes directory archive", `tar -cf /tmp/kube.tar /etc/kubernetes`, []Category{KubernetesSecret}},
		{"nested shell private key", `sh -c 'cat /srv/keys/server.key'`, []Category{PrivateKey}},
		{"ordinary command", `systemctl status nginx`, nil},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzer.Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
			if len(got.Findings) != len(tt.want) {
				t.Fatalf("Analyze() findings = %#v, want %d", got.Findings, len(tt.want))
			}
		})
	}
}

func TestAnalyzerRejectsInvalidShellWithoutEchoingInput(t *testing.T) {
	for _, command := range []string{"", "# comment only", `cat "private-input-marker`} {
		_, err := NewAnalyzer().Analyze(command)
		if !errors.Is(err, ErrInvalidShell) {
			t.Fatalf("Analyze(%q) error = %v, want ErrInvalidShell", command, err)
		}
		if err.Error() != ErrInvalidShell.Error() {
			t.Fatalf("Analyze() error = %q, want sanitized %q", err, ErrInvalidShell)
		}
	}
}

func TestAnalyzerClassifiesSensitiveRuleFamilies(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"ssh home variable", `grep host "$HOME/.ssh/config"`, []Category{SSHSecret}},
		{"ssh braced home variable", `sed -n 1p "${HOME}/.ssh/known_hosts"`, []Category{SSHSecret}},
		{"ssh authorized keys", `awk '{print $1}' /home/deploy/.ssh/authorized_keys`, []Category{SSHSecret}},
		{"ssh host private key", `xxd /etc/ssh/ssh_host_ed25519_key`, []Category{SSHSecret}},
		{"ssh etc private key", `cat /etc/ssh/id_rsa`, []Category{SSHSecret}},
		{"aws credentials", `cat ~/.aws/credentials`, []Category{CloudCredential}},
		{"aws config", `cat "$HOME/.aws/config"`, []Category{CloudCredential}},
		{"aws directory", `tar -cf /tmp/aws.tar ~/.aws`, []Category{CloudCredential}},
		{"gcloud credentials", `strings ~/.config/gcloud/credentials.db`, []Category{CloudCredential}},
		{"azure credentials", `tar -cf /tmp/a.tar ~/.azure`, []Category{CloudCredential}},
		{"cloud environment", `printenv AWS_SECRET_ACCESS_KEY`, []Category{CloudCredential, ProcessEnvironment}},
		{"cloud variable expansion", `printf '%s' "$AWS_SECRET_ACCESS_KEY"`, []Category{CloudCredential}},
		{"print environment", `printenv`, []Category{ProcessEnvironment}},
		{"set environment", `set`, []Category{ProcessEnvironment}},
		{"export environment", `export -p`, []Category{ProcessEnvironment}},
		{"proc environment", `cat /proc/123/environ`, []Category{ProcessEnvironment}},
		{"postgres credentials", `cat ~/.pgpass`, []Category{DatabaseCredential}},
		{"mysql credentials", `sed -n 1p ~/.my.cnf`, []Category{DatabaseCredential}},
		{"database credential file", `base64 /run/secrets/database_credentials.json`, []Category{DatabaseCredential}},
		{"kube config", `cat "${HOME}/.kube/config"`, []Category{KubernetesSecret}},
		{"service account token", `cat /var/run/secrets/kubernetes.io/serviceaccount/token`, []Category{KubernetesSecret}},
		{"private key suffix", `openssl rsa -in /srv/tls/server.key -check`, []Category{PrivateKey}},
		{"private pem name", `cat /run/secrets/private-key.pem`, []Category{PrivateKey}},
		{"private pem directory", `openssl pkey -in /etc/ssl/private/server.pem -noout`, []Category{PrivateKey}},
		{"network address", `ip addr show`, []Category{NetworkIdentity}},
		{"network option before link", `ip -json link`, []Category{NetworkIdentity}},
		{"network neighbor", `ip neigh`, []Category{NetworkIdentity}},
		{"ifconfig", `ifconfig -a`, []Category{NetworkIdentity}},
		{"hostname addresses", `hostname -I`, []Category{NetworkIdentity}},
		{"socket listing", `ss -lntp`, []Category{NetworkIdentity}},
		{"legacy socket listing", `netstat -rn`, []Category{NetworkIdentity}},
		{"legacy route", `route -n`, []Category{NetworkIdentity}},
		{"proc network", `cat /proc/net/tcp`, []Category{NetworkIdentity}},
		{"hosts file", `grep example /etc/hosts`, []Category{NetworkIdentity}},
		{"resolver config", `cat /etc/resolv.conf`, []Category{NetworkIdentity}},
		{"public ip curl", `curl -s https://api.ipify.org`, []Category{NetworkIdentity}},
		{"public ip dig", `dig +short myip.opendns.com @resolver1.opendns.com`, []Category{NetworkIdentity}},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzer.Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerTraversesCompleteShellAST(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"assignment", `KEY_FILE=~/.ssh/id_rsa true`, []Category{SSHSecret}},
		{"input redirect", `cat < ~/.ssh/config`, []Category{SSHSecret}},
		{"output redirect", `printf x > /etc/kubernetes/admin.conf`, []Category{KubernetesSecret}},
		{"command substitution", `printf '%s\n' "$(cat ~/.pgpass)"`, []Category{DatabaseCredential}},
		{"process substitution", `diff <(cat ~/.ssh/config) <(printf x)`, []Category{SSHSecret}},
		{"subshell and block", `(cat /proc/1/environ); { ip link; }`, []Category{NetworkIdentity, ProcessEnvironment}},
		{"multiline pipeline", "cat \\\n+~/.aws/credentials |\nstrings", []Category{CloudCredential}},
		{"find exec", `find /root/.ssh -type f -exec cat {} \;`, []Category{SSHSecret}},
		{"nested bash", `bash -c 'cat ~/.kube/config'`, []Category{KubernetesSecret}},
		{"nested dash", `dash -c "cat /etc/hosts"`, []Category{NetworkIdentity}},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzer.Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerAvoidsOrdinaryCommandFalsePositives(t *testing.T) {
	commands := []string{
		`journalctl -u nginx --since today`,
		`cat /var/log/application.log`,
		`cat ./config.yaml`,
		`cat /etc/ssl/certs/site.pem`,
		`app --version 1.2.3`,
		`echo 192.0.2.10`,
		`printf '%s\n' public-key.pem`,
	}

	for _, command := range commands {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		if len(got.Categories) != 0 || len(got.Findings) != 0 {
			t.Errorf("Analyze(%q) = %#v, want no findings", command, got)
		}
	}
}

func TestAnalyzerResultsAreDeterministicDeduplicatedAndSanitized(t *testing.T) {
	const marker = "user-secret-path-marker"
	command := "cat /proc/1/environ /proc/2/environ; env; ip route; cat /tmp/" + marker + "/server.key"
	analyzer := NewAnalyzer()
	first, err := analyzer.Analyze(command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := analyzer.Analyze(command)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Analyze() is nondeterministic: first=%#v second=%#v", first, second)
	}
	wantCategories := []Category{NetworkIdentity, PrivateKey, ProcessEnvironment}
	if !reflect.DeepEqual(first.Categories, wantCategories) {
		t.Fatalf("Analyze() categories = %#v, want %#v", first.Categories, wantCategories)
	}
	if len(first.Findings) != 4 {
		t.Fatalf("Analyze() findings = %#v, want four distinct rules", first.Findings)
	}
	for _, finding := range first.Findings {
		if len(finding.Rule) > 128 || len(finding.Evidence) > 128 {
			t.Errorf("finding label exceeds 128 characters: %#v", finding)
		}
		if strings.Contains(finding.Rule, marker) || strings.Contains(finding.Evidence, marker) {
			t.Errorf("finding echoes command content: %#v", finding)
		}
	}
}

func TestAnalyzerRejectsOversizedCommand(t *testing.T) {
	command := "echo " + strings.Repeat("x", (128<<10)+1)
	_, err := NewAnalyzer().Analyze(command)
	if !errors.Is(err, ErrInvalidShell) || err.Error() != ErrInvalidShell.Error() {
		t.Fatalf("Analyze(oversized) error = %v, want sanitized ErrInvalidShell", err)
	}
}

func TestAnalyzerIgnoresDynamicNestedShellWithoutPanicking(t *testing.T) {
	got, err := NewAnalyzer().Analyze(`read -r script; sh -c "$script"`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(got.Categories) != 0 {
		t.Fatalf("Analyze() categories = %#v, want best-effort no match", got.Categories)
	}
}

func TestAnalyzerRecursesStaticNestedScriptWithDynamicTrailingArgs(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"dynamic positional argument", `bash -c 'ip route' "$arg"`, []Category{NetworkIdentity}},
		{"options before command string", `bash --noprofile --norc -c 'ip route' "$0"`, []Category{NetworkIdentity}},
		{"dynamic command string", `bash -c "$script" 'cat /etc/hosts'`, nil},
		{"dynamic script positional path", `bash -c "$script" /etc/hosts`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerParsesNestedShellOptionBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"script file ends option phase", `bash script.sh -c 'ip route'`, nil},
		{"double dash ends option phase", `bash -- -c 'env'`, nil},
		{"relative script ends option phase", `bash ./script -c 'cat ~/.ssh/id_rsa'`, nil},
		{"short flag before command string", `bash -x -c 'ip route'`, []Category{NetworkIdentity}},
		{"short option cluster", `bash -lc 'ip route'`, []Category{NetworkIdentity}},
		{"long flags before command string", `bash --noprofile --norc -c 'ip route'`, []Category{NetworkIdentity}},
		{"short option with value", `bash -O extglob -c 'ip route'`, []Category{NetworkIdentity}},
		{"long option with value", `bash --rcfile /tmp/rc -c 'ip route'`, []Category{NetworkIdentity}},
		{"long option with dynamic value", `bash --rcfile "$rcfile" -c 'ip route'`, []Category{NetworkIdentity}},
		{"dynamic unknown option", `bash "$unknown" -c 'ip route'`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerHandlesNestedShellPlusOptions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"bash plus x", `bash +x -c 'ip route'`, []Category{NetworkIdentity}},
		{"sh plus x", `sh +x -c 'ip route'`, []Category{NetworkIdentity}},
		{"dash plus x", `dash +x -c 'ip route'`, []Category{NetworkIdentity}},
		{"zsh plus x", `zsh +x -c 'ip route'`, []Category{NetworkIdentity}},
		{"plus short cluster", `bash +xeu -c 'ip route'`, []Category{NetworkIdentity}},
		{"plus O with value", `bash +O extglob -c 'ip route'`, []Category{NetworkIdentity}},
		{"plus o with value", `bash +o verbose -c 'ip route'`, []Category{NetworkIdentity}},
		{"bash plus c selector", `bash +c 'ip route'`, []Category{NetworkIdentity}},
		{"dash plus c selector", `dash +c 'ip route'`, []Category{NetworkIdentity}},
		{"zsh plus c selector", `zsh +c 'ip route'`, []Category{NetworkIdentity}},
		{"unknown plus option", `bash +not-an-option -c 'ip route'`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerClassifiesPrivatePEMDirectories(t *testing.T) {
	for _, command := range []string{
		`cat /etc/ssl/private/server.pem`,
		`base64 /srv/tls/private/client.pem`,
		`xxd /run/private/signing.pem`,
	} {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		if !reflect.DeepEqual(got.Categories, []Category{PrivateKey}) {
			t.Errorf("Analyze(%q) categories = %#v, want private key", command, got.Categories)
		}
	}
}

func TestAnalyzerClassifiesEnvironmentExportListing(t *testing.T) {
	tests := []struct {
		command string
		want    []Category
	}{
		{`export`, []Category{ProcessEnvironment}},
		{`export -p`, []Category{ProcessEnvironment}},
		{`export FOO=bar`, nil},
	}

	for _, tt := range tests {
		got, err := NewAnalyzer().Analyze(tt.command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", tt.command, err)
		}
		if !reflect.DeepEqual(got.Categories, tt.want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", tt.command, got.Categories, tt.want)
		}
	}
}

func TestAnalyzerClassifiesSSHConfigFragments(t *testing.T) {
	tests := []struct {
		command string
		want    []Category
	}{
		{`cat /etc/ssh/ssh_config.d/20-proxy.conf`, []Category{SSHSecret}},
		{`sed -n 1p /etc/ssh/sshd_config.d/50-cloud.conf`, []Category{SSHSecret}},
		{`cat /etc/app/config.d/20-app.conf`, nil},
	}

	for _, tt := range tests {
		got, err := NewAnalyzer().Analyze(tt.command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", tt.command, err)
		}
		if !reflect.DeepEqual(got.Categories, tt.want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", tt.command, got.Categories, tt.want)
		}
	}
}

func TestAnalyzerClassifiesStaticWordsAcrossAST(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"for word iterator", `for p in ~/.ssh/id_rsa; do cat "$p"; done`, []Category{SSHSecret}},
		{"array element", `paths=(/etc/hosts /tmp/plain); printf '%s\n' "${paths[@]}"`, []Category{NetworkIdentity}},
		{"ordinary loop", `for p in /var/log/app.log; do cat "$p"; done`, nil},
		{"ordinary array", `paths=(/tmp/a /tmp/b); printf '%s\n' "${paths[@]}"`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerPreservesStaticArgumentPositions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"dynamic command does not promote env", `$cmd env`, nil},
		{"known path after dynamic command", `$cmd /etc/hosts`, []Category{NetworkIdentity}},
		{"printenv mixed arguments", `printenv "$dynamic" AWS_SECRET_ACCESS_KEY`, []Category{CloudCredential, ProcessEnvironment}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerOnlyExpandsSimpleHOMEParameters(t *testing.T) {
	commands := []string{
		`cat "${HOME:+/tmp}/.ssh/id_rsa"`,
		`cat "${HOME:-/tmp}/.ssh/id_rsa"`,
		`cat "${HOME:0:2}/.ssh/id_rsa"`,
		`cat "${HOME/foo/bar}/.ssh/id_rsa"`,
		`cat "${HOME[0]}/.ssh/id_rsa"`,
	}

	for _, command := range commands {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		if len(got.Categories) != 0 {
			t.Errorf("Analyze(%q) categories = %#v, want none", command, got.Categories)
		}
	}
}

func TestAnalyzerUsesShellSpecificInvocationOptions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"bash bundled c static", `bash -lc 'ip route' /etc/hosts`, []Category{NetworkIdentity}},
		{"bash bundled c dynamic", `bash -lc "$script" /etc/hosts`, nil},
		{"sh posix options", `sh -eu -c 'ip route'`, []Category{NetworkIdentity}},
		{"sh option value", `sh -o errexit -c 'ip route'`, []Category{NetworkIdentity}},
		{"sh rejects bash long", `sh --rcfile /tmp/rc -c 'ip route'`, nil},
		{"dash short cluster", `dash -ec 'ip route'`, []Category{NetworkIdentity}},
		{"dash option value", `dash -o errexit -c 'ip route'`, []Category{NetworkIdentity}},
		{"dash rejects bash long", `dash --noprofile -c 'ip route'`, nil},
		{"zsh named options", `zsh --no-rcs --no-globalrcs -c 'ip route'`, []Category{NetworkIdentity}},
		{"zsh option value", `zsh -o norcs -c 'ip route'`, []Category{NetworkIdentity}},
		{"zsh rejects bash rcfile", `zsh --rcfile /tmp/rc -c 'ip route'`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerClassifiesEnvOnlyWithoutUtility(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"plain", `env`, []Category{ProcessEnvironment}},
		{"null separated", `env -0`, []Category{ProcessEnvironment}},
		{"assignment only", `env FOO=bar`, []Category{ProcessEnvironment}},
		{"clean assignment only", `env -i FOO=bar`, []Category{ProcessEnvironment}},
		{"known utility", `env FOO=bar command`, nil},
		{"known sensitive utility path", `env FOO=bar /etc/hosts`, []Category{NetworkIdentity}},
		{"dynamic possible utility", `env FOO=bar "$utility"`, nil},
		{"dynamic after option", `env -i "$utility"`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerClassifiesApplicationCredentialPaths(t *testing.T) {
	commands := []string{
		`cat ~/.git-credentials`,
		`cat ~/.netrc`,
		`cat ~/.npmrc`,
		`cat ~/.docker/config.json`,
		`cat ~/.config/gh/hosts.yml`,
	}

	for _, command := range commands {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		want := Analysis{
			Categories: []Category{CloudCredential},
			Findings: []Finding{{
				Category: CloudCredential,
				Rule:     "application_credential_path",
				Evidence: "application credential path",
			}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Analyze(%q) = %#v, want %#v", command, got, want)
		}
	}
}

func TestAnalyzerAvoidsApplicationCredentialPathFalsePositives(t *testing.T) {
	for _, command := range []string{
		`cat ~/.gitconfig`,
		`cat ./package.json`,
		`cat /etc/docker/daemon.json`,
	} {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		if len(got.Categories) != 0 {
			t.Errorf("Analyze(%q) categories = %#v, want none", command, got.Categories)
		}
	}
}

func TestAnalyzerFindingLabelsAreCompleteAndBounded(t *testing.T) {
	want := []findingLabel{
		{"application_credential_path", "application credential path"},
		{"cloud_credential_path", "cloud credential path"},
		{"cloud_environment", "cloud credential environment"},
		{"database_credential_path", "database credential path"},
		{"environment_command", "environment listing command"},
		{"kubernetes_sensitive_path", "kubernetes sensitive path"},
		{"network_command", "network identity command"},
		{"network_identity_path", "network identity path"},
		{"private_key_input", "private key input"},
		{"private_key_path", "private key path"},
		{"process_environment_path", "process environment path"},
		{"public_ip_lookup", "public IP lookup command"},
		{"ssh_sensitive_path", "ssh sensitive path"},
	}
	if !reflect.DeepEqual(allFindingLabels, want) {
		t.Fatalf("allFindingLabels = %#v, want %#v", allFindingLabels, want)
	}
	for _, label := range allFindingLabels {
		if label.rule == "" || label.evidence == "" || len(label.rule) > 128 || len(label.evidence) > 128 {
			t.Errorf("invalid finding label: %#v", label)
		}
	}
}

func TestAnalyzerNestedShellDepthLimit(t *testing.T) {
	tests := []struct {
		name  string
		depth int
		want  []Category
	}{
		{"four levels", 4, []Category{NetworkIdentity}},
		{"five levels", 5, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(nestedShellCommand(tt.depth, "ip route"))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerCommandLengthBoundary(t *testing.T) {
	prefix := "echo "
	exact := prefix + strings.Repeat("x", maxCommandBytes-len(prefix))
	if _, err := NewAnalyzer().Analyze(exact); err != nil {
		t.Fatalf("Analyze(exact limit) error = %v", err)
	}
	_, err := NewAnalyzer().Analyze(exact + "x")
	if !errors.Is(err, ErrInvalidShell) || err.Error() != ErrInvalidShell.Error() {
		t.Fatalf("Analyze(limit + 1) error = %v, want sanitized ErrInvalidShell", err)
	}
}

func FuzzAnalyzerNoPanic(f *testing.F) {
	prefix := "echo "
	for _, command := range []string{
		`systemctl status nginx`,
		string([]byte{'c', 'a', 't', ' ', 0xff, 0xfe}),
		nestedShellCommand(4, "ip route"),
		prefix + strings.Repeat("x", maxCommandBytes-len(prefix)),
		`cat "unterminated`,
	} {
		f.Add(command)
	}

	f.Fuzz(func(t *testing.T, command string) {
		_, _ = NewAnalyzer().Analyze(command)
	})
}

func nestedShellCommand(depth int, leaf string) string {
	command := leaf
	for range depth {
		command = "sh -c '" + strings.ReplaceAll(command, "'", `'"'"'`) + "'"
	}
	return command
}

func TestAnalyzerClassifiesShellFileScriptOperands(t *testing.T) {
	tests := []struct {
		command string
		want    []Category
	}{
		{`bash ~/.ssh/config`, []Category{SSHSecret}},
		{`sh /etc/hosts`, []Category{NetworkIdentity}},
		{`bash -c 'ip route' /etc/hosts`, []Category{NetworkIdentity}},
		{`bash -c "$script" /etc/hosts`, nil},
	}

	for _, tt := range tests {
		got, err := NewAnalyzer().Analyze(tt.command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", tt.command, err)
		}
		if !reflect.DeepEqual(got.Categories, tt.want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", tt.command, got.Categories, tt.want)
		}
	}
}

func TestAnalyzerClassifiesEnvUnsetWithoutUtility(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []Category
	}{
		{"short unset", `env -u NAME`, []Category{ProcessEnvironment}},
		{"long unset", `env --unset NAME`, []Category{ProcessEnvironment}},
		{"long unset equals", `env --unset=NAME`, []Category{ProcessEnvironment}},
		{"option terminator", `env --`, []Category{ProcessEnvironment}},
		{"short unset utility", `env -u NAME command`, nil},
		{"long unset utility", `env --unset NAME command`, nil},
		{"terminator utility", `env -- command`, nil},
		{"short unset missing value", `env -u`, nil},
		{"short unset dynamic value", `env -u "$name"`, nil},
		{"long unset dynamic value", `env --unset="$name"`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAnalyzer().Analyze(tt.command)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if !reflect.DeepEqual(got.Categories, tt.want) {
				t.Fatalf("Analyze() categories = %#v, want %#v", got.Categories, tt.want)
			}
		})
	}
}

func TestAnalyzerHandlesCommandSelectorsInValueOptionClusters(t *testing.T) {
	tests := []struct {
		command string
		want    []Category
	}{
		{`bash -oc 'ip route'`, nil},
		{`bash -Oc 'ip route'`, nil},
		{`bash +oc 'ip route'`, nil},
		{`dash -oc 'ip route'`, nil},
		{`dash +oc 'ip route'`, nil},
		{`zsh -oc ignored 'ip route'`, nil},
		{`zsh +oc ignored 'ip route'`, nil},
		{`bash -oc errexit 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`bash -Oc extglob 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`dash -oc errexit 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`bash +oc errexit 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`bash +Oc extglob 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`dash +oc errexit 'cat ~/.ssh/id_rsa'`, []Category{SSHSecret}},
		{`bash -oc errexit 'ip route'`, []Category{NetworkIdentity}},
		{`bash -Oc extglob 'ip route'`, []Category{NetworkIdentity}},
		{`dash -oc errexit 'ip route'`, []Category{NetworkIdentity}},
		{`bash +oc errexit 'ip route'`, []Category{NetworkIdentity}},
		{`bash +Oc extglob 'ip route'`, []Category{NetworkIdentity}},
		{`dash +oc errexit 'ip route'`, []Category{NetworkIdentity}},
		{`bash -xo`, nil},
		{`bash -xO`, nil},
		{`dash -xo`, nil},
		{`bash -o errexit -c 'ip route'`, []Category{NetworkIdentity}},
		{`dash -o errexit -c 'ip route'`, []Category{NetworkIdentity}},
	}

	for _, tt := range tests {
		got, err := NewAnalyzer().Analyze(tt.command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", tt.command, err)
		}
		if !reflect.DeepEqual(got.Categories, tt.want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", tt.command, got.Categories, tt.want)
		}
	}
}

func TestAnalyzerAcceptsVerifiedZshNamedOptions(t *testing.T) {
	tests := []struct {
		command string
		want    []Category
	}{
		{`zsh --no-rcexpandparam -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh --rcexpandparam -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh -onorcs -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh +onorcs -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh -orcs -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh +oglobalrcs -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh -onoglobalrcs -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh +onorcexpandparam -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh -orcexpandparam -c 'ip route'`, []Category{NetworkIdentity}},
		{`zsh -onorcs 'ip route'`, nil},
		{`zsh -onot-a-real-option -c 'ip route'`, nil},
		{`zsh -onot ignored -c 'ip route'`, nil},
		{`zsh --not-a-real-option -c 'ip route'`, nil},
	}

	for _, tt := range tests {
		got, err := NewAnalyzer().Analyze(tt.command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", tt.command, err)
		}
		if !reflect.DeepEqual(got.Categories, tt.want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", tt.command, got.Categories, tt.want)
		}
	}
}

func TestAnalyzerClassifiesAdditionalApplicationCredentialPaths(t *testing.T) {
	for _, command := range []string{
		`cat ~/.pypirc`,
		`cat ~/.cargo/credentials`,
		`cat ~/.cargo/credentials.toml`,
		`cat ~/.config/git/credentials`,
	} {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		want := []Category{CloudCredential}
		if !reflect.DeepEqual(got.Categories, want) {
			t.Errorf("Analyze(%q) categories = %#v, want %#v", command, got.Categories, want)
		}
	}

	for _, command := range []string{`cat pyproject.toml`, `cat Cargo.toml`, `cat ~/.gitconfig`} {
		got, err := NewAnalyzer().Analyze(command)
		if err != nil {
			t.Fatalf("Analyze(%q) error = %v", command, err)
		}
		if len(got.Categories) != 0 {
			t.Errorf("Analyze(%q) categories = %#v, want none", command, got.Categories)
		}
	}
}
