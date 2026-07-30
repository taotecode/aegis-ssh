# Aegis SSH

English | [简体中文](README.zh-CN.md)

> **Give AI agents SSH access without giving them your SSH secrets.**

Aegis SSH is a local privacy firewall between AI agents and your servers. Agents see aliases such as `prod`; passwords, imported private keys, hosts, usernames, fingerprints, and master-password material stay outside prompts, MCP parameters, logs, environment variables, and process arguments.

It is one Go binary for macOS and Linux. Agents use public aliases through standard MCP; the background broker owns the decrypted vault and performs SSH authentication with the Go SSH library.

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

Enable recovery while you still know the master password, then store the one-time displayed recovery code offline:

```bash
aegis-ssh recovery enable
aegis-ssh recovery restore  # reset a forgotten master password without losing servers
```

Vaults created before recovery was enabled cannot be decrypted after the master password is lost. `aegis-ssh recovery reset` archives the old encrypted files and creates a new empty vault.

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

## Background operation

Start the broker, unlock it, and then close the terminal:

```bash
aegis-ssh start
```

From another terminal:

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
aegis-ssh exec prod -- 'cd /srv/app && git status --short'
```

Quote the complete command after `--`. Commands selected by the default `enforce` risk policy wait for approval in the local approval center; approval codes no longer enter agent chat.

```bash
aegis-ssh lock
aegis-ssh unlock
aegis-ssh stop
```

Use `aegis-ssh service install` for an optional launchd/systemd user service. It starts locked and never stores the master password.

## Risk policy, batching, and logs

```bash
aegis-ssh config set risk-policy enforce  # enforce | warn | off
aegis-ssh config set log-level debug      # debug | info | warn | error | off
aegis-ssh approval list
aegis-ssh exec --servers prod,staging -- 'uptime'
aegis-ssh exec --all -- 'df -h'
```

Credential isolation, host-key verification, audit logging, and output redaction remain active in every risk mode. Operational logs are available with `aegis-ssh log path`, `aegis-ssh log show`, and `aegis-ssh log follow`.

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

The tools are `get_ssh_broker_status`, `list_ssh_servers`, `ssh_execute`, and `ssh_execute_batch`. They expose aliases and filtered command results, never connection fields.

Install `skills/aegis-ssh` into the agent's Skill directory or point the client at that directory. The Skill tells agents to prefer MCP, wait for real user approval, and preserve redaction markers.

After running `aegis-ssh start`, ask the Agent by alias:

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

Rotate a server password or replace a private key with `aegis-ssh server edit <alias>`, then run `aegis-ssh start`. Reconfirm the host key only against a trusted source.

To reveal a password-authenticated server's password locally, run `aegis-ssh server password <alias>` and enter the master password. The password is written only to the controlling terminal, never MCP or redirected stdout.

## Troubleshooting

- `daemon: unavailable`: run `aegis-ssh start`.
- `credential vault is locked` or storage failure at startup: verify the master password and private ownership/modes under `~/.aegis-ssh`.
- Host-key verification failure: stop and investigate the server identity; do not bypass pinning.
- Authentication failure: stop the daemon, run `server edit`, and enter the current password or import the current private key.
- Server changes are refused: run `aegis-ssh stop`, then retry the management command.
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
