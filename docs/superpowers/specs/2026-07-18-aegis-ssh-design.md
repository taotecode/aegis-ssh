# Aegis SSH Design

## 1. Purpose

Aegis SSH is an open-source local SSH broker for AI agents. It lets an agent
operate password-only SSH servers without placing the server address, port,
username, or password in prompts, shell history, process arguments, MCP
configuration, or agent-readable plaintext configuration.

The first release supports macOS and Linux. It exposes a standard stdio MCP
server, a generic Agent Skill, and a CLI fallback from one Go binary.

## 2. Security Boundary

### 2.1 Protected data

The encrypted vault contains:

- SSH host address and port
- SSH username and password
- pinned SSH host-key fingerprint

These values are never returned by an MCP tool, printed by a management
command, written to an audit log, or placed in a child process argument.

### 2.2 Threat model

Aegis SSH is designed to prevent accidental disclosure through agent prompts,
tool calls, command history, process listings, logs, and ordinary remote
diagnostic output.

The remote command policy is a best-effort misuse guard, not an unbreakable
remote sandbox. An agent allowed to execute arbitrary shell code can transform
commands, invoke interpreters, inspect process state, or send data over the
network in ways that evade static policy analysis.

The local broker is also not a hard boundary against a malicious process with
the same operating-system identity and debugger or process-memory access. A
stronger adversarial deployment requires running the daemon as a separate OS
user or behind a dedicated privileged service. That deployment mode is outside
the first release.

### 2.3 Non-goals

The first release does not provide:

- a complete remote shell sandbox
- a full interactive TTY
- a web administration or approval interface
- team or cloud credential sharing
- Windows support
- unattended daemon unlock after reboot

## 3. Architecture

The project builds one `aegis-ssh` binary with multiple subcommands.

```text
AI agent
  -> stdio MCP or Skill-guided CLI
  -> ~/.aegis-ssh/run/aegis.sock
  -> aegis-ssh daemon
  -> in-process Go SSH client
  -> target server
```

### 3.1 Daemon

`aegis-ssh daemon` reads the vault master password from `/dev/tty`, decrypts the
vault, retains connection data in memory, listens on a user-owned Unix socket,
evaluates policy, performs SSH operations, filters output, and writes audit
events.

The daemon never invokes `ssh`, `sshpass`, or a shell on the local machine for
the SSH connection. It uses a Go SSH library so connection values do not enter
local process arguments.

### 3.2 MCP bridge

`aegis-ssh mcp` is a stdio MCP server. It contains no SSH credentials and does
not decrypt the vault. It validates MCP inputs, forwards requests to the Unix
socket, and converts broker responses to MCP structured content.

MCP protocol output is written only to stdout. Diagnostics use stderr so they
cannot corrupt the stdio protocol stream.

### 3.3 Management CLI

The management CLI provides:

```text
aegis-ssh init
aegis-ssh daemon
aegis-ssh lock
aegis-ssh status
aegis-ssh server add
aegis-ssh server edit <alias>
aegis-ssh server remove <alias>
aegis-ssh server list
aegis-ssh exec <alias> -- <command>
aegis-ssh mcp
```

`init`, vault unlock, and all secret fields are read from `/dev/tty`. Secret
values are rejected if supplied as command arguments or environment variables.
`server list` returns aliases and descriptions only.

### 3.4 SSH executor

Each execution opens a password-authenticated SSH connection, checks the pinned
host key, starts a non-interactive remote session, and executes the exact shell
string supplied by the request. Multiline commands are supported. Stateful
work must be expressed in one request, for example `cd /srv/app && ...`.

Every request has a bounded timeout and output-size limit. Timeout terminates
the remote session and returns a structured timeout error. Output truncation is
reported explicitly.

## 4. Local Storage and Cryptography

```text
~/.aegis-ssh/
|-- config.yaml
|-- vault.enc
|-- audit/
`-- run/aegis.sock
```

The root directory is mode `0700`; regular files and the Unix socket are mode
`0600`. The daemon refuses to start when an existing sensitive path has broader
permissions or unsafe ownership.

`config.yaml` contains only non-secret server aliases, descriptions, default
timeouts, output limits, and policy settings. It contains no address, port,
username, password, or host fingerprint.

`vault.enc` uses a versioned envelope with:

- Argon2id password-based key derivation
- a random per-vault salt
- XChaCha20-Poly1305 authenticated encryption
- a random nonce for every write
- authenticated format version and KDF parameters

Vault updates are written to a same-directory temporary file, synced, renamed
atomically, and followed by a directory sync. Existing vault data remains
usable if a write is interrupted before the rename.

The master password is never persisted. The daemon reads it once from
`/dev/tty` at startup. Lock and shutdown paths overwrite mutable in-memory
secret buffers on a best-effort basis before releasing them.

During `server add`, the user enters the address, port, username, and password
interactively. The SSH host fingerprint is displayed for explicit confirmation
and then stored inside the encrypted vault. Later connections fail closed when
the host key differs.

## 5. Command Policy

### 5.1 Pre-execution analysis

The policy engine parses shell syntax and evaluates commands, arguments,
redirections, substitutions, pipelines, and multiline constructs. It requests
approval for operations that appear to reveal:

- SSH keys, SSH configuration, or host identity material
- cloud, package-registry, source-control, or application credentials
- environment secrets and process environments
- database connection files
- Kubernetes configuration and service-account tokens
- certificate private keys
- network addresses, routes, interfaces, resolver data, or connection tables

The engine recognizes common read and transformation utilities, including
`cat`, `sed`, `awk`, `grep`, `find`, `tar`, `strings`, `base64`, `xxd`, command
substitution, pipelines, and redirections. It also checks sensitive path
patterns after shell normalization where possible.

Commands that do not trigger a rule execute immediately. A triggered command
is not partially executed.

### 5.2 Post-execution filtering

Before any output leaves the daemon, the filter detects and replaces:

- valid IPv4 and IPv6 addresses
- PEM private-key blocks
- bearer tokens and common access-key forms
- credentials embedded in URLs
- common password, secret, and token assignments

Each replacement uses a stable category marker such as
`[REDACTED:IP_ADDRESS]`. The result reports the categories and counts that were
removed. Filters use bounded streaming buffers so a secret spanning adjacent
chunks is still detected without retaining unbounded output.

An approved command disables filtering only for the risk categories included
in that approval. All other categories remain filtered.

## 6. Approval Protocol

When pre-execution policy triggers, the daemon creates an approval record bound
to:

- a random approval identifier
- a four-character human confirmation code
- the server alias
- a cryptographic hash of the exact command bytes
- the detected risk categories
- a five-minute expiry
- an unused state

The MCP result includes a user-facing message that the agent must show
verbatim. The user approves by replying `允许 CODE` in the agent conversation.
The agent then calls `ssh_execute_approved` with the approval identifier and
code.

The daemon rejects expired, previously used, mismatched, or malformed
approvals. A valid approval is consumed atomically before remote execution and
can never be replayed. Any command modification requires a new approval; the
approved tool executes the command retained by the daemon rather than accepting
a replacement command from the agent.

The broker cannot cryptographically prove that the chat confirmation came from
a human. The Skill requires agents not to self-approve, and the audit trail
records the approval lifecycle. This limitation is part of the accepted
best-effort threat model.

## 7. MCP Contract

The stdio MCP server exposes four tools.

### 7.1 `list_ssh_servers`

Returns configured aliases, descriptions, and availability. It never returns
connection fields.

### 7.2 `ssh_execute`

Inputs:

- `server_alias`: configured public alias
- `command`: exact remote shell string
- `timeout_seconds`: optional bounded timeout
- `max_output_bytes`: optional bounded output limit

Returns one of `completed`, `requires_approval`, `denied`, or `failed`, plus
filtered stdout, filtered stderr, exit code, truncation state, redaction
summary, and approval metadata when applicable.

### 7.3 `ssh_execute_approved`

Inputs:

- `approval_id`: identifier returned by `ssh_execute`
- `approval_code`: four-character code confirmed by the user

The tool accepts no server or command replacement. It executes the stored
request after successful approval validation.

### 7.4 `get_ssh_broker_status`

Returns daemon reachability, vault lock state, broker version, and policy
version. It returns no process details or sensitive paths.

All tools return MCP errors as structured, actionable responses. Daemon
unavailable, vault locked, unknown alias, host-key mismatch, authentication
failure, timeout, output limit, policy denial, and approval failure are distinct
error codes.

## 8. Agent Skill and Client Compatibility

The repository includes `skills/aegis-ssh/SKILL.md` using the standard Agent
Skills layout. It instructs an agent to:

- address servers only by alias
- prefer MCP and use the CLI only as a fallback
- never attempt to inspect or infer broker credentials
- show approval messages verbatim and wait for the user's matching reply
- never call the approved tool without the user's reply
- preserve redaction markers and not attempt policy bypasses

Client examples cover Codex, Claude Code, Cursor, and OpenClaw. Each MCP example
launches the same `aegis-ssh mcp` command. Other clients that support standard
stdio MCP use the same command without a client-specific adapter.

## 9. Audit Model

Audit entries are append-only JSON Lines records containing:

- timestamp and request identifier
- calling interface type
- server alias
- hash and bounded preview of the command after local secret filtering
- policy decision and risk categories
- approval lifecycle state
- duration, exit code, timeout, and truncation state
- redaction categories and counts

Audit entries never contain vault fields or unfiltered remote output. Logs
rotate by size with a bounded retention count. Failure to write a required audit
entry prevents a sensitive approved operation from executing; ordinary command
logging failures are surfaced prominently and follow the configured fail-open
or fail-closed policy, which defaults to fail closed.

## 10. Testing Strategy

Development follows red-green-refactor TDD.

Unit tests cover:

- vault encryption, wrong passwords, tampering, atomic writes, and permissions
- shell parsing and each sensitive command category
- output redaction, chunk boundaries, false-positive boundaries, and limits
- approval binding, expiry, atomic consumption, and replay rejection
- RPC input validation, error mapping, and audit filtering

Integration tests start an in-process SSH server that supports password
authentication only. They verify successful execution, bad passwords, pinned
host-key mismatch, timeout, output truncation, exit codes, policy blocking,
approval execution, and output filtering.

MCP tests use a standard MCP client over linked transports to verify tool
discovery, schemas, structured results, locked-vault behavior, and daemon
unavailability.

Continuous integration runs on macOS and Linux and includes unit and integration
tests, formatting, static analysis, the Go race detector, and amd64/arm64 build
checks.

## 11. Distribution

The repository uses the Apache-2.0 license. Releases contain signed or
checksummed macOS and Linux binaries for amd64 and arm64, an unprivileged
`install.sh`, the Agent Skill, MCP configuration examples, and documentation.

`SECURITY.md` documents the threat model, disclosure process, local same-user
limitation, arbitrary-shell limitation, credential rotation guidance, and safe
debug-log collection.

## 12. Acceptance Criteria

The first release is acceptable when:

1. A user can initialize and unlock an encrypted local vault without putting a
   secret in arguments, stdin, environment variables, or logs.
2. A password-only test SSH server can be added by interactive CLI and operated
   through its alias.
3. MCP clients can list aliases and execute ordinary remote shell commands
   without receiving connection details.
4. Sensitive commands require an exact, expiring, single-use approval and
   cannot be altered between request and execution.
5. IP addresses, private keys, tokens, and credential assignments are filtered
   before ordinary output reaches an MCP client.
6. Audit logs contain enough information to reconstruct decisions without
   containing vault data or raw sensitive output.
7. The full test suite, static analysis, race tests, and macOS/Linux builds pass.
8. Codex, Claude Code, Cursor, and OpenClaw setup examples all invoke the same
   standard MCP entrypoint.
