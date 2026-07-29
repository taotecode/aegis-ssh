# Aegis SSH Implementation Plan

> **For AI-agent workers:** Required sub-skill: use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task by task. Track each
> step by changing its checkbox from `- [ ]` to `- [x]` only after the stated
> verification succeeds.

**Goal:** Build a cross-platform local SSH broker that lets AI agents operate
password-only servers by alias without exposing connection credentials, while
applying best-effort sensitive-command approval, output redaction, and audit.

**Architecture:** One Go binary runs as a user daemon, stdio MCP bridge, and
management CLI. The daemon decrypts a local vault, exposes a small JSON protocol
over a mode-0600 Unix socket, performs in-process password SSH, and returns only
policy-filtered results. MCP and CLI clients never receive vault fields.

**Technical stack:** Go 1.25, official MCP Go SDK v1.6.1,
`golang.org/x/crypto`, `golang.org/x/term`, `mvdan.cc/sh/v3`, YAML v3, Unix
domain sockets, Go standard testing, `go vet`, race detector, GitHub Actions.

---

## Planned File Structure

```text
cmd/aegis-ssh/main.go                    command entrypoint and signal handling
internal/app/app.go                      CLI command routing and dependency wiring
internal/app/prompt.go                   /dev/tty-only secret and confirmation input
internal/paths/paths.go                  ~/.aegis-ssh path and permission rules
internal/config/config.go                non-secret YAML configuration
internal/model/model.go                  shared request, result, and error types
internal/vault/crypto.go                 Argon2id and XChaCha20-Poly1305 envelope
internal/vault/store.go                  atomic encrypted vault persistence
internal/policy/analyzer.go              shell AST sensitive-operation analysis
internal/policy/redactor.go              bounded sensitive-output filtering
internal/approval/store.go               expiring single-use approvals
internal/audit/logger.go                 filtered JSONL audit and rotation
internal/sshclient/client.go             password SSH execution and host-key pinning
internal/testssh/server.go                reusable password-only SSH test fixture
internal/broker/service.go               policy, approval, SSH, redaction orchestration
internal/broker/protocol.go              Unix-socket JSON request and response schema
internal/broker/server.go                daemon socket server
internal/broker/client.go                MCP and CLI socket client
internal/mcpserver/server.go             four MCP tools and stdio transport
skills/aegis-ssh/SKILL.md                generic Agent Skill behavior
examples/mcp/                            major-client MCP configuration examples
scripts/install.sh                       unprivileged user installation
scripts/package.sh                       cross-platform archives and SHA256 checksums
.github/workflows/ci.yml                 macOS/Linux CI and cross-build checks
README.md                                setup and operation guide
SECURITY.md                              explicit threat model and disclosure process
LICENSE                                  Apache-2.0 license
```

Tests live beside their packages as `*_test.go`. This keeps each package's
behavior and fixtures close to the implementation and avoids a separate test
utility layer.

### Task 1: Bootstrap module, paths, configuration, and shared types

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `internal/model/model.go`
- Create: `internal/paths/paths.go`
- Create: `internal/paths/paths_test.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [x] **Step 1: Create the module manifest and ignore runtime artifacts**

```go
module github.com/chenjw/aegis-ssh

go 1.25.0

require (
    github.com/modelcontextprotocol/go-sdk v1.6.1
    golang.org/x/crypto v0.48.0
    golang.org/x/term v0.41.0
    gopkg.in/yaml.v3 v3.0.1
    mvdan.cc/sh/v3 v3.13.1
)
```

`.gitignore` must contain `/aegis-ssh`, `/dist/`, `/.aegis-ssh/`, and common
editor files. Run `go mod tidy` only after the first importing package exists.

- [x] **Step 2: Write failing path and configuration tests**

```go
func TestEnsureLayoutCreatesPrivatePaths(t *testing.T) {
    root := t.TempDir() + "/state"
    got, err := paths.EnsureLayout(root)
    if err != nil { t.Fatal(err) }
    assertMode(t, got.Root, 0o700)
    assertMode(t, got.AuditDir, 0o700)
    assertMode(t, got.RunDir, 0o700)
}

func TestEnsureLayoutRejectsBroadExistingPermissions(t *testing.T) {
    root := t.TempDir() + "/state"
    if err := os.Mkdir(root, 0o755); err != nil { t.Fatal(err) }
    if _, err := paths.EnsureLayout(root); !errors.Is(err, paths.ErrUnsafePermissions) {
        t.Fatalf("got %v", err)
    }
}

func TestConfigDoesNotAcceptConnectionFields(t *testing.T) {
    raw := []byte("servers:\n  prod:\n    host: 192.0.2.1\n")
    if _, err := config.Parse(raw); err == nil {
        t.Fatal("expected unknown secret field to be rejected")
    }
}
```

- [x] **Step 3: Run tests and confirm the red state**

Run: `go test ./internal/paths ./internal/config`

Expected: FAIL because the packages or exported functions do not exist.

- [x] **Step 4: Implement minimal paths, model, and strict YAML configuration**

Define:

```go
type Paths struct {
    Root, ConfigFile, VaultFile, AuditDir, RunDir, SocketFile string
}
func DefaultRoot() (string, error)
func EnsureLayout(root string) (Paths, error)

type Config struct {
    Version  int                     `yaml:"version"`
    Defaults Defaults                `yaml:"defaults"`
    Servers  map[string]ServerPublic `yaml:"servers"`
}
type ServerPublic struct {
    Description string `yaml:"description,omitempty"`
}
func Parse([]byte) (Config, error)
func Load(string) (Config, error)
func Save(string, Config) error
```

Use `yaml.Decoder.KnownFields(true)`. `EnsureLayout` must use `os.Lstat`, reject
symlinks and non-owned/broad paths, create directories with `0700`, and never
silently chmod an unsafe pre-existing path.

Shared `model` types must include `Status`, `ErrorCode`, `ExecuteRequest`,
`ApprovedRequest`, `ExecuteResult`, `ApprovalInfo`, `RedactionSummary`,
`ServerSummary`, and `BrokerStatus`. Define a sanitized `CodedError` plus
sentinel errors for authentication, host key, timeout, unavailable daemon,
locked vault, validation, and approval failures so callers can use `errors.Is`
without receiving raw dependency errors. Do not include host, port, username,
password, or fingerprint in any public result type.

- [x] **Step 5: Verify green state and commit**

Run: `go mod tidy && go test ./internal/paths ./internal/config && git diff --check`

Expected: all tests PASS and no diff errors.

```bash
git add go.mod go.sum .gitignore internal/model internal/paths internal/config
git commit -m "feat: establish secure local configuration"
```

### Task 2: Encrypted vault and atomic persistence

**Files:**
- Create: `internal/vault/crypto.go`
- Create: `internal/vault/store.go`
- Create: `internal/vault/vault_test.go`

- [x] **Step 1: Write failing crypto and persistence tests**

```go
func TestRoundTripAndWrongPassword(t *testing.T) {
    plain := vault.Data{Servers: map[string]vault.ServerSecret{
        "prod": {Host: "secret-host", Port: 22, User: "root", Password: []byte("pw")},
    }}
    testKDF := vault.KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}
    blob, err := vault.Seal([]byte("master"), plain, testKDF)
    if err != nil { t.Fatal(err) }
    got, err := vault.Open([]byte("master"), blob)
    if err != nil { t.Fatal(err) }
    if diff := cmp.Diff(plain, got); diff != "" { t.Fatal(diff) }
    if _, err := vault.Open([]byte("wrong"), blob); !errors.Is(err, vault.ErrInvalidPassword) {
        t.Fatalf("got %v", err)
    }
}

func TestTamperingIsRejected(t *testing.T) {
    blob, _ := vault.Seal([]byte("master"), vault.Data{}, vault.KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1})
    blob[len(blob)-1] ^= 1
    if _, err := vault.Open([]byte("master"), blob); !errors.Is(err, vault.ErrInvalidPassword) {
        t.Fatalf("got %v", err)
    }
}

func TestStoreWritesMode0600AndPreservesOldVaultOnRenameFailure(t *testing.T) {
    path := filepath.Join(t.TempDir(), "vault.enc")
    if err := os.WriteFile(path, []byte("old"), 0o600); err != nil { t.Fatal(err) }
    injected := errors.New("injected rename failure")
    s := vault.Store{
        Path: path,
        WriteAtomic: func(string, []byte, fs.FileMode) error { return injected },
    }
    err := s.Save([]byte("master"), vault.Data{})
    if !errors.Is(err, injected) { t.Fatalf("got %v", err) }
    got, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    if string(got) != "old" { t.Fatalf("old vault replaced with %q", got) }
}
```

- [x] **Step 2: Run the focused test and confirm the red state**

Run: `go test ./internal/vault -run 'TestRoundTrip|TestTampering|TestStore' -v`

Expected: FAIL because `Seal`, `Open`, `Store`, and vault types are missing.

- [x] **Step 3: Implement the versioned authenticated envelope**

Define:

```go
type ServerSecret struct {
    Host            string `json:"host"`
    Port            uint16 `json:"port"`
    User            string `json:"user"`
    Password        []byte `json:"password"`
    HostFingerprint string `json:"host_fingerprint"`
}
type Data struct { Servers map[string]ServerSecret `json:"servers"` }
type KDFParams struct { MemoryKiB uint32; Iterations uint32; Parallelism uint8 }

func Seal(master []byte, data Data, params KDFParams) ([]byte, error)
func Open(master, envelope []byte) (Data, error)
func Zero([]byte)
```

Use Argon2id and `chacha20poly1305.NewX`. Authenticate the envelope version and
KDF parameters as additional data. Production defaults are 64 MiB memory,
three iterations, and parallelism two. Tests use intentionally cheap parameters.
Map all AEAD authentication failures to `ErrInvalidPassword` without leaking
whether the password or file was wrong.

- [x] **Step 4: Implement atomic store operations**

```go
type AtomicWriteFunc func(path string, data []byte, mode fs.FileMode) error
type Store struct { Path string; WriteAtomic AtomicWriteFunc }
func (s Store) Initialize(master []byte) error
func (s Store) Load(master []byte) (Data, error)
func (s Store) Save(master []byte, data Data) error
```

The writer must create a random same-directory temporary file with `0600`, write
and sync it, close it, rename it, and sync the parent directory. Reject symlink
targets and broad file modes before load or save.

- [x] **Step 5: Verify vault behavior and commit**

Run: `go test ./internal/vault -v && go test ./...`

Expected: PASS, including wrong password and tampering cases.

```bash
git add internal/vault
git commit -m "feat: add encrypted credential vault"
```

### Task 3: Shell policy analyzer

**Files:**
- Create: `internal/policy/analyzer.go`
- Create: `internal/policy/analyzer_test.go`

- [x] **Step 1: Write table-driven failing policy tests**

```go
func TestAnalyzerClassifiesCommands(t *testing.T) {
    tests := []struct{ command string; want []policy.Category }{
        {"systemctl status nginx", nil},
        {"cat ~/.ssh/id_ed25519", []policy.Category{policy.SSHSecret}},
        {"base64 /root/.ssh/id_rsa", []policy.Category{policy.SSHSecret}},
        {"env | sort", []policy.Category{policy.ProcessEnvironment}},
        {"ip route", []policy.Category{policy.NetworkIdentity}},
        {"tar czf - /etc/kubernetes", []policy.Category{policy.KubernetesSecret}},
        {"sh -c 'cat /etc/ssh/ssh_host_rsa_key'", []policy.Category{policy.SSHSecret}},
    }
    for _, tt := range tests {
        got, err := policy.NewAnalyzer().Analyze(tt.command)
        if err != nil { t.Fatalf("%q: %v", tt.command, err) }
        if diff := cmp.Diff(tt.want, got.Categories); diff != "" { t.Errorf("%q: %s", tt.command, diff) }
    }
}

func TestAnalyzerRejectsUnparseableShell(t *testing.T) {
    if _, err := policy.NewAnalyzer().Analyze("$(unterminated"); !errors.Is(err, policy.ErrInvalidShell) {
        t.Fatalf("got %v", err)
    }
}
```

- [x] **Step 2: Run tests and confirm the red state**

Run: `go test ./internal/policy -run Analyzer -v`

Expected: FAIL because the analyzer API does not exist.

- [x] **Step 3: Implement AST traversal and normalized rules**

```go
type Category string
const (
    SSHSecret Category = "ssh_secret"
    CloudCredential Category = "cloud_credential"
    ProcessEnvironment Category = "process_environment"
    DatabaseCredential Category = "database_credential"
    KubernetesSecret Category = "kubernetes_secret"
    PrivateKey Category = "private_key"
    NetworkIdentity Category = "network_identity"
)
type Finding struct { Category Category; Rule string; Evidence string }
type Analysis struct { Categories []Category; Findings []Finding }
func (a *Analyzer) Analyze(command string) (Analysis, error)
```

Parse with `syntax.NewParser(syntax.Variant(syntax.LangBash))`, walk every word,
redirection, command substitution, and nested `sh -c` literal. Normalize paths
without filesystem access. Evidence must be a bounded, sanitized rule label,
never the content of a local or remote file. Deduplicate and sort categories for
stable results.

- [x] **Step 4: Add bypass-regression cases and keep them red-green**

Add separate tests for quoted paths, `${HOME}`, pipelines, redirections,
`find -exec`, `awk`, `sed`, `xxd`, `strings`, `openssl`, and multiline commands.
For each group, run the named test before and after adding its rule.

Run: `go test ./internal/policy -run Analyzer -v`

Expected: PASS.

- [x] **Step 5: Commit the analyzer**

```bash
git add internal/policy/analyzer.go internal/policy/analyzer_test.go go.mod go.sum
git commit -m "feat: classify sensitive remote shell operations"
```

### Task 4: Streaming output redaction

**Files:**
- Create: `internal/policy/redactor.go`
- Create: `internal/policy/redactor_test.go`

- [x] **Step 1: Write failing redaction tests**

```go
func TestRedactorRemovesSupportedSecrets(t *testing.T) {
    input := "peer=192.0.2.10 v6=2001:db8::1 password=hunter2\n" + testPEM
    got := policy.NewRedactor(nil).RedactString(input)
    for _, secret := range []string{"192.0.2.10", "2001:db8::1", "hunter2", "PRIVATE KEY"} {
        if strings.Contains(got.Text, secret) { t.Fatalf("leaked %q", secret) }
    }
    if got.Counts[policy.IPAddress] != 2 { t.Fatalf("counts=%v", got.Counts) }
}

func TestRedactorDetectsSecretAcrossChunks(t *testing.T) {
    var out bytes.Buffer
    r := policy.NewStreamRedactor(&out, nil)
    _, _ = r.Write([]byte("token=abc"))
    _, _ = r.Write([]byte("def123\n"))
    _ = r.Close()
    if strings.Contains(out.String(), "abcdef123") { t.Fatal("token leaked") }
}

func TestApprovedCategoryOnlyBypassesThatCategory(t *testing.T) {
    got := policy.NewRedactor(map[policy.RedactionCategory]bool{policy.IPAddress: true}).RedactString("192.0.2.1 password=x")
    if !strings.Contains(got.Text, "192.0.2.1") || strings.Contains(got.Text, "password=x") { t.Fatal(got.Text) }
}
```

Define `testPEM` in the test file as a complete synthetic
`-----BEGIN PRIVATE KEY-----` block with a non-production payload. The
`NewStreamRedactor` test writer records every emitted byte so the assertion
checks the public output boundary, not an internal buffer.

- [x] **Step 2: Run tests and confirm the red state**

Run: `go test ./internal/policy -run Redactor -v`

Expected: FAIL because redactor types are missing.

- [x] **Step 3: Implement bounded filtering and category counts**

Define `RedactionCategory`, `RedactionResult`, `Redactor`, and
`StreamRedactor`. Validate IP candidates with `net/netip` rather than replacing
version-like numbers. Replace secrets with stable markers such as
`[REDACTED:IP_ADDRESS]`. Keep an overlap window large enough for the maximum
supported token and PEM delimiter, and enforce the broker output byte limit
before returning data.

- [x] **Step 4: Run package tests, fuzz seeds, and commit**

Add fuzz seeds containing invalid UTF-8, very long lines, adjacent IPv6 text,
split PEM blocks, and empty writes.

Run: `go test ./internal/policy -run 'Redactor|Fuzz' -v && go test ./...`

Expected: PASS with no panic and no supported seed leak.

```bash
git add internal/policy
git commit -m "feat: redact sensitive remote output"
```

### Task 5: Expiring single-use approvals

**Files:**
- Create: `internal/approval/store.go`
- Create: `internal/approval/store_test.go`

- [x] **Step 1: Write failing state-machine tests with a fake clock**

```go
func TestApprovalIsBoundAndSingleUse(t *testing.T) {
    now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
    s := approval.NewStore(func() time.Time { return now }, deterministicReader())
    created, err := s.Create("prod", []byte("ip route"), []policy.Category{policy.NetworkIdentity})
    if err != nil { t.Fatal(err) }
    req, err := s.Consume(created.ID, created.Code)
    if err != nil { t.Fatal(err) }
    if req.ServerAlias != "prod" || string(req.Command) != "ip route" { t.Fatal(req) }
    if _, err := s.Consume(created.ID, created.Code); !errors.Is(err, approval.ErrUsed) { t.Fatal(err) }
}

func TestApprovalExpires(t *testing.T) {
    now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
    s := approval.NewStore(func() time.Time { return now }, deterministicReader())
    created, err := s.Create("prod", []byte("ip route"), []policy.Category{policy.NetworkIdentity})
    if err != nil { t.Fatal(err) }
    now = now.Add(5*time.Minute + time.Nanosecond)
    if _, err := s.Consume(created.ID, created.Code); !errors.Is(err, approval.ErrExpired) {
        t.Fatalf("got %v", err)
    }
}

func TestWrongCodeDoesNotConsumeApproval(t *testing.T) {
    s := approval.NewStore(time.Now, deterministicReader())
    created, err := s.Create("prod", []byte("ip route"), []policy.Category{policy.NetworkIdentity})
    if err != nil { t.Fatal(err) }
    if _, err := s.Consume(created.ID, "ZZZZ"); !errors.Is(err, approval.ErrCode) {
        t.Fatalf("got %v", err)
    }
    if _, err := s.Consume(created.ID, created.Code); err != nil {
        t.Fatalf("correct code was consumed by failed attempt: %v", err)
    }
}
```

Define `deterministicReader()` in the test file as
`bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))`; every test creates a fresh
reader so it cannot exhaust shared state.

- [x] **Step 2: Run tests and confirm the red state**

Run: `go test ./internal/approval -v`

Expected: FAIL because approval storage is missing.

- [x] **Step 3: Implement mutex-protected create and consume**

Use `crypto/rand` for 128-bit IDs and an unambiguous uppercase code alphabet.
Store exact command bytes, alias, sorted categories, creation time, expiry, and
state. Compare codes in constant time. Mark used under the same mutex before
returning the stored command. Periodically remove expired records during create
and consume; no background goroutine is needed.

- [x] **Step 4: Verify race safety and commit**

Run: `go test -race ./internal/approval -v`

Expected: PASS with no race report.

```bash
git add internal/approval
git commit -m "feat: add one-time command approvals"
```

### Task 6: Password SSH execution and host-key pinning

**Files:**
- Create: `internal/sshclient/client.go`
- Create: `internal/sshclient/client_test.go`
- Create: `internal/testssh/server.go`

- [x] **Step 1: Create an in-process password-only SSH test server**

The reusable fixture must listen on `127.0.0.1:0`, generate an ephemeral host key, accept
exactly one configured username/password pair, reject public keys, execute
commands through a deterministic test handler, and expose its SHA256 host-key
fingerprint. It is imported only by tests, so it is not linked into release
binaries.

- [x] **Step 2: Write failing client integration tests**

```go
func TestExecuteUsesPasswordAndPinnedHostKey(t *testing.T) {
    srv := testssh.Start(t, "root", "pw")
    c := sshclient.New()
    got, err := c.Execute(context.Background(), vault.ServerSecret{
        Host: srv.Host, Port: srv.Port, User: "root", Password: []byte("pw"),
        HostFingerprint: srv.Fingerprint,
    }, "printf ok", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 1024})
    if err != nil { t.Fatal(err) }
    if got.Stdout != "ok" || got.ExitCode != 0 { t.Fatal(got) }
}

func TestExecuteRejectsBadPassword(t *testing.T) {
    srv := testssh.Start(t, "root", "pw")
    _, err := sshclient.New().Execute(context.Background(), srv.Secret("root", "wrong"), "printf ok", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 1024})
    if !errors.Is(err, model.ErrAuthentication) { t.Fatalf("got %v", err) }
}

func TestExecuteRejectsHostKeyMismatch(t *testing.T) {
    srv := testssh.Start(t, "root", "pw")
    secret := srv.Secret("root", "pw")
    secret.HostFingerprint = "SHA256:not-the-server"
    _, err := sshclient.New().Execute(context.Background(), secret, "printf ok", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 1024})
    if !errors.Is(err, model.ErrHostKey) { t.Fatalf("got %v", err) }
}

func TestExecuteTimesOut(t *testing.T) {
    srv := testssh.Start(t, "root", "pw")
    srv.Handle("wait", func(ctx context.Context) testssh.Output { <-ctx.Done(); return testssh.Output{} })
    _, err := sshclient.New().Execute(context.Background(), srv.Secret("root", "pw"), "wait", sshclient.Limits{Timeout: time.Millisecond, MaxOutputBytes: 1024})
    if !errors.Is(err, model.ErrTimeout) { t.Fatalf("got %v", err) }
}

func TestExecuteTruncatesOutput(t *testing.T) {
    srv := testssh.Start(t, "root", "pw")
    srv.Handle("large", func(context.Context) testssh.Output { return testssh.Output{Stdout: strings.Repeat("x", 2048)} })
    got, err := sshclient.New().Execute(context.Background(), srv.Secret("root", "pw"), "large", sshclient.Limits{Timeout: time.Second, MaxOutputBytes: 32})
    if err != nil { t.Fatal(err) }
    if !got.Truncated || len(got.Stdout) > 32 { t.Fatalf("got %+v", got) }
}
```

- [x] **Step 3: Run tests and confirm the red state**

Run: `go test ./internal/sshclient -v`

Expected: FAIL because `Client.Execute` is missing.

- [x] **Step 4: Implement in-process SSH execution**

Use `ssh.Password(string(secret.Password))`, a custom
`ssh.HostKeyCallback` comparing `ssh.FingerprintSHA256`, `net.Dialer` with
context, `ssh.NewClientConn`, and a session with separate bounded stdout and
stderr writers. Never include `net.JoinHostPort`, username, password, or raw SSH
errors containing the address in returned errors. Map failures to stable model
error codes.

- [x] **Step 5: Verify integration behavior and commit**

Run: `go test -race ./internal/sshclient -v`

Expected: all password, pinning, timeout, exit, and truncation tests PASS.

```bash
git add internal/sshclient internal/testssh
git commit -m "feat: execute password-authenticated SSH commands"
```

### Task 7: Filtered audit logging and rotation

**Files:**
- Create: `internal/audit/logger.go`
- Create: `internal/audit/logger_test.go`

- [x] **Step 1: Write failing no-leak and rotation tests**

```go
func TestLoggerNeverWritesForbiddenFields(t *testing.T) {
    dir := t.TempDir()
    l, _ := audit.New(dir, audit.Options{MaxBytes: 4096, Backups: 2})
    event := audit.Event{ServerAlias: "prod", Command: "curl http://user:pw@192.0.2.1", Decision: "completed"}
    if err := l.Write(event); err != nil { t.Fatal(err) }
    raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
    for _, leaked := range []string{"192.0.2.1", "user:pw"} {
        if bytes.Contains(raw, []byte(leaked)) { t.Fatalf("leaked %s", leaked) }
    }
}

func TestLoggerRotatesAtBound(t *testing.T) {
    dir := t.TempDir()
    l, err := audit.New(dir, audit.Options{MaxBytes: 128, Backups: 2})
    if err != nil { t.Fatal(err) }
    for i := 0; i < 20; i++ {
        event := audit.Event{ServerAlias: "prod", Command: fmt.Sprintf("printf %d", i), Decision: "completed"}
        if err := l.Write(event); err != nil { t.Fatal(err) }
    }
    if _, err := os.Stat(filepath.Join(dir, "audit.jsonl.1")); err != nil { t.Fatal(err) }
    if _, err := os.Stat(filepath.Join(dir, "audit.jsonl.3")); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("retention exceeded: %v", err)
    }
}
```

- [x] **Step 2: Run tests and confirm the red state**

Run: `go test ./internal/audit -v`

Expected: FAIL because logger types are missing.

- [x] **Step 3: Implement append-only JSONL with sanitized command preview**

The logger owns a redactor, hashes exact command bytes with SHA-256, stores at
most 160 filtered preview bytes, opens logs with `0600`, syncs each sensitive
approval event, and rotates using atomic renames. `Event` must not have fields
for host, port, username, password, fingerprint, or raw output.

- [x] **Step 4: Verify and commit**

Run: `go test -race ./internal/audit -v && go test ./...`

Expected: PASS and no secret appears in temporary audit files.

```bash
git add internal/audit
git commit -m "feat: add redacted audit logging"
```

### Task 8: Broker service and Unix-socket protocol

**Files:**
- Create: `internal/broker/service.go`
- Create: `internal/broker/service_test.go`
- Create: `internal/broker/protocol.go`
- Create: `internal/broker/server.go`
- Create: `internal/broker/client.go`
- Create: `internal/broker/protocol_test.go`

- [x] **Step 1: Write failing orchestration tests using fakes**

```go
func TestExecuteOrdinaryCommandFiltersBeforeReturn(t *testing.T) {
    exec := &fakeExecutor{result: sshclient.Result{Stdout: "peer 192.0.2.1"}}
    svc := newTestService(exec)
    got := svc.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
    if got.Status != model.StatusCompleted || strings.Contains(got.Stdout, "192.0.2.1") { t.Fatal(got) }
}

func TestExecuteSensitiveCommandCreatesApprovalWithoutSSH(t *testing.T) {
    exec := &fakeExecutor{}
    svc := newTestService(exec)
    got := svc.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
    if got.Status != model.StatusRequiresApproval || exec.calls != 0 || got.Approval == nil { t.Fatal(got) }
}

func TestExecuteApprovedUsesStoredCommand(t *testing.T) {
    exec := &fakeExecutor{result: sshclient.Result{Stdout: "route 192.0.2.1"}}
    svc := newTestService(exec)
    blocked := svc.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "ip route"})
    got := svc.ExecuteApproved(context.Background(), model.ApprovedRequest{
        ApprovalID: blocked.Approval.ID, ApprovalCode: blocked.Approval.Code,
    })
    if got.Status != model.StatusCompleted || exec.calls != 1 || exec.lastCommand != "ip route" {
        t.Fatalf("result=%+v calls=%d command=%q", got, exec.calls, exec.lastCommand)
    }
}

func TestUnknownAliasNeverRevealsVaultData(t *testing.T) {
    svc := newTestService(&fakeExecutor{})
    got := svc.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "missing", Command: "uptime"})
    raw, err := json.Marshal(got)
    if err != nil { t.Fatal(err) }
    for _, secret := range []string{"secret-host", "root", "password-value", "SHA256:fixture"} {
        if bytes.Contains(raw, []byte(secret)) { t.Fatalf("result leaked %q", secret) }
    }
}

func TestAuditFailurePreventsRemoteExecution(t *testing.T) {
    exec := &fakeExecutor{}
    svc := newTestServiceWithAudit(exec, &fakeAudit{err: errors.New("disk full")})
    got := svc.Execute(context.Background(), model.ExecuteRequest{ServerAlias: "prod", Command: "uptime"})
    if got.Status != model.StatusFailed || got.Error.Code != model.CodeAudit || exec.calls != 0 {
        t.Fatalf("result=%+v calls=%d", got, exec.calls)
    }
}
```

`service_test.go` defines `fakeExecutor` with `calls`, `lastCommand`, `result`,
and `err` fields; `fakeAudit` with an `err` field; and an in-memory secret lookup
containing the four fixture values used by the no-leak test. `newTestService`
uses a real analyzer, redactor, and approval store with a fake clock while
injecting those fakes. `newTestServiceWithAudit` replaces only the auditor.

- [x] **Step 2: Run service tests and confirm the red state**

Run: `go test ./internal/broker -run Service -v`

Expected: FAIL because service interfaces and methods are missing.

- [x] **Step 3: Implement service dependency interfaces and orchestration**

Define narrow interfaces for secret lookup, analyzer, approvals, SSH executor,
redactor, and auditor. `Execute` order is validate -> alias lookup -> policy ->
approval creation or audit-preflight -> SSH -> redaction -> audit -> result.
`ExecuteApproved` consumes the stored request, maps approved risk categories to
redaction bypass categories, then follows the same SSH and audit path.
The default fail-closed audit preflight occurs before SSH; the optional
fail-open setting must be explicit in non-secret configuration and covered by a
separate test.

- [x] **Step 4: Write failing Unix protocol tests**

Use a temporary Unix socket and a real `broker.Server` with a fake service.
Test `status`, `list_servers`, `execute`, and `execute_approved`; malformed JSON,
unknown method, oversized frame, socket mode, cancellation, and concurrent calls.

Run: `go test ./internal/broker -run Protocol -v`

Expected: FAIL before server and client are implemented.

- [x] **Step 5: Implement one-request-per-connection JSON protocol**

Frames are newline-delimited JSON capped at 1 MiB. `Request` contains version,
request ID, method, and `json.RawMessage` params. `Response` contains the same
request ID, result, or a stable structured error. The server removes a stale
socket only after proving no daemon is listening, binds with umask `0077`,
verifies mode `0600`, and closes cleanly on context cancellation.

- [x] **Step 6: Verify race safety and commit**

Run: `go test -race ./internal/broker -v && go test ./...`

Expected: PASS with no race report.

```bash
git add internal/broker
git commit -m "feat: expose broker service over private unix socket"
```

### Task 9: Standard MCP tools

**Files:**
- Create: `internal/mcpserver/server.go`
- Create: `internal/mcpserver/server_test.go`

- [x] **Step 1: Write failing MCP tool discovery and call tests**

```go
func TestToolsExposeOnlyPublicSchemas(t *testing.T) {
    server := mcpserver.New(fakeBrokerClient{})
    clientTransport, serverTransport := mcp.NewInMemoryTransports()
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go server.Run(ctx, serverTransport)
    client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
    session, err := client.Connect(ctx, clientTransport, nil)
    if err != nil { t.Fatal(err) }
    names := listToolNames(t, session)
    want := []string{"get_ssh_broker_status", "list_ssh_servers", "ssh_execute", "ssh_execute_approved"}
    if diff := cmp.Diff(want, names); diff != "" { t.Fatal(diff) }
    keys := schemaPropertyKeys(t, session)
    for _, forbidden := range []string{"password", "host", "host_fingerprint", "username", "port"} {
        if keys[forbidden] { t.Fatalf("schema exposed property %s", forbidden) }
    }
}

func TestSensitiveResultIsStructuredAndActionable(t *testing.T) {
    server := mcpserver.New(fakeBrokerClient{executeResult: model.ExecuteResult{
        Status: model.StatusRequiresApproval,
        Approval: &model.ApprovalInfo{ID: "approval-id", Code: "ABCD", Message: "Reply 允许 ABCD"},
    }})
    session := connectMCP(t, server)
    result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
        Name: "ssh_execute", Arguments: map[string]any{"server_alias": "prod", "command": "ip route"},
    })
    if err != nil { t.Fatal(err) }
    if result.IsError { t.Fatal("approval is a workflow result, not a tool error") }
    text := result.Content[0].(*mcp.TextContent).Text
    if !strings.Contains(text, "允许 ABCD") { t.Fatal(text) }
}

func TestBrokerUnavailableReturnsIsError(t *testing.T) {
    server := mcpserver.New(fakeBrokerClient{err: broker.ErrUnavailable})
    session := connectMCP(t, server)
    result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_ssh_broker_status"})
    if err != nil { t.Fatal(err) }
    if !result.IsError { t.Fatal("expected MCP tool error") }
    text := result.Content[0].(*mcp.TextContent).Text
    if strings.Contains(text, ".aegis-ssh") { t.Fatalf("socket path leaked: %s", text) }
}
```

`server_test.go` defines `fakeBrokerClient` methods for status, list, execute,
and approved execute. `connectMCP` connects the returned server to a standard
SDK client with `mcp.NewInMemoryTransports` and registers cleanup for both
sessions. `listToolNames` sorts discovered names. `schemaPropertyKeys` walks
only each JSON Schema `properties` map recursively and does not scan human tool
descriptions.

- [x] **Step 2: Run tests and confirm the red state**

Run: `go test ./internal/mcpserver -v`

Expected: FAIL because the MCP server is missing.

- [x] **Step 3: Register typed tools with the official SDK**

Use `mcp.NewServer`, generic `mcp.AddTool`, descriptive JSON-schema tags, and
`mcp.StdioTransport`. Each handler calls only the broker client. Return a short
human-readable `TextContent` plus the typed structured result. Set `IsError`
for transport and broker failures, not for `requires_approval`.

Tool descriptions must state purpose, returned data, and the credential
non-disclosure boundary. `ssh_execute_approved` accepts only `approval_id` and
`approval_code`.

Add a locked-vault tool test in which the broker returns `model.ErrVaultLocked`;
the MCP result must set `IsError`, recommend starting and unlocking the daemon,
and contain no socket path or vault filename.

- [x] **Step 4: Verify in-memory MCP integration and commit**

Run: `go test -race ./internal/mcpserver -v && go test ./...`

Expected: all four tools are discoverable and calls return valid MCP results.

```bash
git add internal/mcpserver
git commit -m "feat: provide standard MCP SSH tools"
```

### Task 10: Interactive management CLI and daemon lifecycle

**Files:**
- Create: `internal/app/prompt.go`
- Create: `internal/app/prompt_test.go`
- Create: `internal/app/app.go`
- Create: `internal/app/app_test.go`
- Create: `cmd/aegis-ssh/main.go`

- [x] **Step 1: Write failing `/dev/tty` prompt tests through an injected terminal**

```go
func TestSecretPromptDoesNotUseStdinOrEcho(t *testing.T) {
    term := newFakeTerminal("master\n")
    got, err := app.ReadSecret(term, "Master password: ")
    if err != nil { t.Fatal(err) }
    if string(got) != "master" || term.EchoedSecret() { t.Fatal("unsafe prompt") }
}

func TestSecretFlagsAndEnvironmentAreRejected(t *testing.T) {
    a := app.New(testDeps())
    err := a.Run(context.Background(), []string{"server", "add", "--password", "pw"})
    if !errors.Is(err, app.ErrSecretArgument) { t.Fatal(err) }
}
```

`newFakeTerminal` implements separate visible writes and hidden reads while
recording whether the hidden input was copied to visible output. `testDeps`
uses temporary paths, an in-memory broker client, and an injected host-key
probe; it never opens the developer's real `~/.aegis-ssh` directory.

- [x] **Step 2: Run prompt tests and confirm the red state**

Run: `go test ./internal/app -run 'Prompt|Secret' -v`

Expected: FAIL because prompt and command routing do not exist.

- [x] **Step 3: Implement CLI routing and interactive vault management**

Use the standard `flag` package with a separate `FlagSet` per command. Open
`/dev/tty` directly on macOS/Linux and use `term.ReadPassword`. `init` prompts
twice and rejects a mismatch. `server add/edit` prompts for every secret field,
shows the probed host-key fingerprint, requires exact user confirmation, and
saves config plus vault without printing secret values. `server list` prints
alias and description only.

Vault management commands run offline: they refuse to modify `config.yaml` or
`vault.enc` while a daemon is listening, prompt for the master password, load
and update both files, then zero secret buffers. This prevents a running daemon
from retaining stale server records.

`daemon` remains in the foreground after unlock; users can background it after
the interactive prompt. `lock` asks the daemon to clear secrets and exit.
`exec` and `status` use the broker client. `mcp` runs the MCP stdio server.

- [x] **Step 4: Write app integration tests and implement main wiring**

Test help, invalid commands, initialized/uninitialized vault, alias validation,
daemon lock, signal cancellation, and a complete `server add -> server list ->
server edit -> server remove` sequence through a fake terminal and test SSH
fingerprint probe. Assert that captured stdout/stderr contain the alias but none
of the fixture host, username, password, or stored fingerprint. `main.go`
creates a signal-aware context, constructs dependencies, calls `app.Run`,
prints sanitized errors to stderr, and uses nonzero exit codes on failure.

- [x] **Step 5: Build, run CLI smoke tests, and commit**

Run:

```bash
go test -race ./internal/app ./cmd/aegis-ssh
go build -o ./aegis-ssh ./cmd/aegis-ssh
./aegis-ssh --help
./aegis-ssh status
```

Expected: tests and build PASS; help lists documented commands; status reports
the daemon as unavailable without leaking the socket path or connection data.

```bash
git add internal/app cmd/aegis-ssh
git commit -m "feat: add secure CLI and daemon entrypoint"
```

### Task 11: Skill, client examples, documentation, installation, and release checks

**Files:**
- Create: `skills/aegis-ssh/SKILL.md`
- Create: `examples/mcp/codex.toml`
- Create: `examples/mcp/claude-code.json`
- Create: `examples/mcp/cursor.json`
- Create: `examples/mcp/openclaw.json`
- Create: `scripts/install.sh`
- Create: `scripts/package.sh`
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `LICENSE`
- Create: `.github/workflows/ci.yml`
- Create: `internal/e2e/e2e_test.go`

- [x] **Step 1: Write the failing end-to-end acceptance test**

The test must create a temporary state directory, initialize a cheap-test vault,
start the password-only SSH fixture and broker Unix server, connect a real broker
client, and assert this sequence:

1. list returns only alias and description;
2. `printf ok` executes successfully;
3. output containing an IP is redacted;
4. `ip route` returns `requires_approval` without contacting SSH;
5. wrong code fails;
6. correct code executes exactly once;
7. replay fails;
8. serialized results and audit files contain none of the fixture host,
   username, password, or fingerprint.

Run: `go test ./internal/e2e -v`

Expected: FAIL until test-friendly broker construction and all integration
boundaries are connected.

- [x] **Step 2: Add only the wiring needed to make the acceptance test pass**

Export no secret-bearing types beyond internal packages. Add constructors or
interfaces rather than test-only production branches. Re-run after each missing
connection is added.

Run: `go test ./internal/e2e -v`

Expected: PASS for the complete acceptance sequence.

- [x] **Step 3: Create the Agent Skill and MCP examples**

`SKILL.md` must require alias-only access, MCP preference, verbatim approval
messages, waiting for the exact user reply, no self-approval, no credential
inference, and preservation of redaction markers. Every client example must
launch `aegis-ssh mcp` and contain no server information or secrets.

- [x] **Step 4: Write user and security documentation**

README must cover installation, `init`, server enrollment, daemon unlock,
MCP setup, Agent Skill installation, command examples, backup of `vault.enc`,
credential rotation, audit location, and troubleshooting. `SECURITY.md` must
state both accepted limitations: arbitrary remote shell is bypassable, and a
same-user malicious local process can inspect broker memory.

- [x] **Step 5: Add installer and CI**

`scripts/install.sh` installs a supplied or locally built binary into
`${XDG_BIN_HOME:-$HOME/.local/bin}` with `0755`, installs the Skill only when an
explicit destination is provided, and never initializes or reads the vault.

`scripts/package.sh <output-dir>` builds the four supported OS/architecture
targets with `-trimpath`, places each binary with README, SECURITY, LICENSE, and
the Skill in a versioned tar archive, and writes `SHA256SUMS`. It uses
`sha256sum` on Linux and `shasum -a 256` on macOS, sorts entries by filename,
and fails when the worktree version is empty.

CI matrix runs `go test ./...`, `go test -race ./...`, `go vet ./...`, checks
`gofmt -l`, and builds darwin/linux for amd64/arm64 using Go 1.25. It must not
require repository secrets. A packaging job runs `scripts/package.sh dist` and
uploads the archives plus `SHA256SUMS` as workflow artifacts.

- [x] **Step 6: Run the complete verification suite**

```bash
test -z "$(gofmt -l .)"
go test ./...
go test -race ./...
go vet ./...
GOOS=darwin GOARCH=amd64 go build -o /tmp/aegis-darwin-amd64 ./cmd/aegis-ssh
GOOS=darwin GOARCH=arm64 go build -o /tmp/aegis-darwin-arm64 ./cmd/aegis-ssh
GOOS=linux GOARCH=amd64 go build -o /tmp/aegis-linux-amd64 ./cmd/aegis-ssh
GOOS=linux GOARCH=arm64 go build -o /tmp/aegis-linux-arm64 ./cmd/aegis-ssh
scripts/package.sh /tmp/aegis-dist
test -s /tmp/aegis-dist/SHA256SUMS
rg -n --hidden -g '*.go' -g '*.json' -g '*.toml' -g '*.yaml' -g '*.yml' \
  'sshpass|-p[[:space:]]+[^ ]+|PreferredAuthentications=password|StrictHostKeyChecking=no'
```

Expected: formatting check is empty; tests, race detector, vet, and all builds
exit zero; the banned-pattern scan returns no matches in shipped files.

- [x] **Step 7: Review acceptance criteria and commit release-ready source**

Read the design's eight acceptance criteria and cite the test or command proving
each one in the commit notes. Do not mark this task complete when any criterion
lacks current evidence.

```bash
git add skills examples scripts README.md SECURITY.md LICENSE .github internal/e2e
git commit -m "docs: package Aegis SSH for agent clients"
git status --short --branch
```

Expected: final commit succeeds and the worktree is clean.
