# Aegis SSH

English | [简体中文](README.zh-CN.md)

Aegis SSH is a lightweight local broker for AI agents that operate password- or private-key-authenticated SSH servers without putting connection details or credentials in prompts, MCP parameters, logs, environment variables, or process arguments.

It is one Go binary for macOS and Linux. Agents use public aliases through standard MCP; the foreground daemon owns the decrypted vault and performs SSH authentication with the Go SSH library.

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

Run `server add` once for each server. Every server gets a unique public alias, so the same vault can hold `prod`, `staging`, `db-primary`, and any other servers you add.

```bash
aegis-ssh server add
aegis-ssh server list
```

Password authentication prompts:

```text
Master password: [hidden]
Alias: prod
Description: Production application server
Host: <server-host>
Port: 22
User: <ssh-user>
Authentication method (password/private-key): password
Host key fingerprint: SHA256:<fingerprint>
Type TRUST to pin this host key: TRUST
SSH password: [hidden]
```

Private-key authentication uses the same fields, but select `private-key`:

```text
Authentication method (password/private-key): private-key
Host key fingerprint: SHA256:<fingerprint>
Type TRUST to pin this host key: TRUST
Private key file: ~/.ssh/id_ed25519
Private key passphrase: [hidden, prompted only when the key is encrypted]
```

The private key file is read locally, validated, and imported into `vault.enc`; its path is not stored. All connection fields are read from `/dev/tty`. Verify the displayed host-key fingerprint through a trusted channel before typing `TRUST`.

See [Add And Manage SSH Servers](docs/server-setup.md) for multiple-server examples, every prompt, key-file requirements, trusted host-key verification, credential rotation, removal, and troubleshooting.

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

Register it in Codex with the installed binary's absolute path:

```bash
codex mcp add aegis-ssh -- "$HOME/.local/bin/aegis-ssh" mcp
codex mcp list
```

Restart Codex after installing or updating the MCP configuration or Skill.

Copy the matching example from `examples/mcp/` into the client's MCP configuration:

- `codex.toml`
- `claude-code.json`
- `cursor.json`
- `openclaw.json`

The tools are `get_ssh_broker_status`, `list_ssh_servers`, `ssh_execute`, and `ssh_execute_approved`. They expose aliases and filtered command results, never connection fields.

Install `skills/aegis-ssh` into the agent's Skill directory or point the client at that directory. The Skill tells agents to prefer MCP, wait for real user approval, and preserve redaction markers.

After starting `aegis-ssh daemon`, ask the Agent by alias:

```text
Use Aegis SSH to list the configured servers.
Use Aegis SSH to run uptime on prod.
Use Aegis SSH to run `cd /srv/app && git status --short` on staging.
```

See [Use Aegis SSH With Agents](docs/agent-usage.md) for Codex setup, the MCP/Skill relationship, tool-call flow, prompt examples, approvals, and troubleshooting.

## Storage And Operations

State is stored under `~/.aegis-ssh/` with private permissions:

- `config.yaml`: aliases, descriptions, limits, and policy settings only
- `vault.enc`: encrypted connection details and pinned host keys
- `audit/audit.jsonl`: bounded command metadata, decisions, and redaction counts
- `run/aegis.sock`: local user-owned broker socket while the daemon runs

Back up `config.yaml` and `vault.enc` together while the daemon is stopped. Keep the backup private. The master password is not recoverable; losing it makes the vault unusable.

Rotate a server password or replace a private key with `aegis-ssh server edit <alias>`, then restart `aegis-ssh daemon`. Reconfirm the host key only against a trusted source.

## Troubleshooting

- `daemon: unavailable`: run `aegis-ssh daemon` in a separate terminal.
- `credential vault is locked` or storage failure at startup: verify the master password and private ownership/modes under `~/.aegis-ssh`.
- Host-key verification failure: stop and investigate the server identity; do not bypass pinning.
- Authentication failure: stop the daemon, run `server edit`, and enter the current password or import the current private key.
- Server changes are refused: run `aegis-ssh lock`, then retry the management command.
- Output contains `[REDACTED:...]`: the broker intentionally withheld sensitive data. Do not attempt to reconstruct it.

## Releases

Published versions and platform archives are available from [GitHub Releases](https://github.com/taotecode/aegis-ssh/releases).

Maintainers release a version by adding a non-empty, bilingual `.github/releases/vX.Y.Z.md` file and pushing the matching `vX.Y.Z` tag. The Release workflow runs tests on macOS and Linux, builds all supported archives, verifies checksums, and publishes the GitHub Release. A missing release-notes file fails the workflow, so every published version has an explicit description.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
scripts/package.sh ./dist
```

See [SECURITY.md](SECURITY.md) for the security boundary and reporting policy. A complete Chinese translation is available in [SECURITY.zh-CN.md](SECURITY.zh-CN.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
