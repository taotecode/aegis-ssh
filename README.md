# Aegis SSH

Aegis SSH is a lightweight local broker for AI agents that must operate password-only SSH servers without putting connection details in prompts, MCP parameters, logs, environment variables, or process arguments.

It is one Go binary for macOS and Linux. Agents use public aliases through standard MCP; the foreground daemon owns the decrypted vault and performs password authentication with the Go SSH library.

## Install

Build and install locally:

```bash
scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
```

Install a packaged binary and the companion Skill explicitly:

```bash
scripts/install.sh --binary ./aegis-ssh --skill-dir "$HOME/.codex/skills"
```

The installer never initializes or reads `~/.aegis-ssh`.

## Initialize

Create encrypted local storage and choose a master password:

```bash
aegis-ssh init
```

Enroll a password-only server. Address, port, username, and password are read interactively from `/dev/tty`. Verify the displayed SSH host-key fingerprint before typing `TRUST`.

```bash
aegis-ssh server add
aegis-ssh server list
```

Edit or remove an alias only while the daemon is stopped:

```bash
aegis-ssh server edit prod
aegis-ssh server remove prod
```

## Run

Unlock the broker in a terminal and leave it in the foreground:

```bash
aegis-ssh daemon
```

From another terminal:

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
aegis-ssh exec prod -- 'cd /srv/app && git status --short'
```

Quote the complete command after `--`. A command that may reveal sensitive server data requires an exact interactive approval code. Stop the daemon and clear in-memory credentials with:

```bash
aegis-ssh lock
```

## MCP

Every supported client launches the same stdio server:

```text
aegis-ssh mcp
```

Copy the matching example from `examples/mcp/` into the client's MCP configuration:

- `codex.toml`
- `claude-code.json`
- `cursor.json`
- `openclaw.json`

The tools are `get_ssh_broker_status`, `list_ssh_servers`, `ssh_execute`, and `ssh_execute_approved`. They expose aliases and filtered command results, never connection fields.

Install `skills/aegis-ssh` into the agent's Skill directory or point the client at that directory. The Skill tells agents to prefer MCP, wait for real user approval, and preserve redaction markers.

## Storage And Operations

State is stored under `~/.aegis-ssh/` with private permissions:

- `config.yaml`: aliases, descriptions, limits, and policy settings only
- `vault.enc`: encrypted connection details and pinned host keys
- `audit/audit.jsonl`: bounded command metadata, decisions, and redaction counts
- `run/aegis.sock`: local user-owned broker socket while the daemon runs

Back up `config.yaml` and `vault.enc` together while the daemon is stopped. Keep the backup private. The master password is not recoverable; losing it makes the vault unusable.

Rotate a server password with `aegis-ssh server edit <alias>`, then restart `aegis-ssh daemon`. Reconfirm the host key only against a trusted source.

## Troubleshooting

- `daemon: unavailable`: run `aegis-ssh daemon` in a separate terminal.
- `credential vault is locked` or storage failure at startup: verify the master password and private ownership/modes under `~/.aegis-ssh`.
- Host-key verification failure: stop and investigate the server identity; do not bypass pinning.
- Authentication failure: stop the daemon, run `server edit`, and enter the current password.
- Server changes are refused: run `aegis-ssh lock`, then retry the management command.
- Output contains `[REDACTED:...]`: the broker intentionally withheld sensitive data. Do not attempt to reconstruct it.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
scripts/package.sh ./dist
```

See [SECURITY.md](SECURITY.md) for the security boundary and reporting policy.

## License

Apache License 2.0. See [LICENSE](LICENSE).
