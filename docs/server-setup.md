# Add And Manage SSH Servers

English | [简体中文](server-setup.zh-CN.md)

This guide covers initial vault setup, password-only server enrollment, host-key verification, connection testing, credential rotation, and server removal.

## Before You Start

You need:

- Aegis SSH installed on the local computer.
- A reachable SSH server with password authentication enabled.
- The server address, port, username, and password.
- A trusted way to verify the server's SSH host-key fingerprint, such as its provider console or an administrator.

Run enrollment commands in a real terminal. Secrets are read from `/dev/tty`; do not put the master password, server address, port, username, SSH password, or fingerprint in command arguments, environment variables, MCP configuration, or an Agent prompt.

The daemon must be stopped before initializing the vault or changing servers.

## 1. Initialize The Vault

Initialize once and choose a master password:

```bash
aegis-ssh init
```

Enter the same master password at both prompts. It encrypts the local vault under `~/.aegis-ssh/` and cannot be recovered if lost. Skip this step when Aegis SSH is already initialized.

## 2. Add A Server

Start interactive enrollment:

```bash
aegis-ssh server add
```

The prompts appear in this order:

| Prompt | Meaning |
| --- | --- |
| `Master password` | Unlocks the local encrypted vault. Input is hidden. |
| `Alias` | Public name used by Codex and other Agents, such as `prod` or `db-primary`. It must start with a letter or digit, may contain letters, digits, `.`, `_`, and `-`, and may be at most 64 characters. |
| `Description` | Optional public description shown to Agents. Do not include an address, username, customer name, or other private infrastructure details. |
| `Host` | Server hostname or IP address. It is stored only in the encrypted vault. |
| `Port` | SSH port from `1` to `65535`. |
| `User` | SSH login username. |
| `Host key fingerprint` | Fingerprint discovered before password authentication. Verify it through a trusted channel. |
| `Type TRUST to pin this host key` | Type the exact uppercase word `TRUST` only after verification. |
| `SSH password` | Server password. Input is hidden and stored only in the encrypted vault. |

Example transcript with placeholders:

```text
$ aegis-ssh server add
Master password: [hidden]
Alias: prod
Description: Production application server
Host: <server-host>
Port: 22
User: <ssh-user>
Host key fingerprint: SHA256:<fingerprint>
Type TRUST to pin this host key: TRUST
SSH password: [hidden]
server prod added
```

The command does not authenticate with the SSH password during enrollment. It first connects only far enough to discover the host key, asks you to verify and pin that key, and then stores the password.

## 3. Verify The Host Key

Do not accept a fingerprint merely because Aegis SSH displayed it. Compare it with a value obtained independently from the hosting provider, the server console, or an administrator.

When you have trusted console access to the server, an administrator can list its public host-key fingerprints with:

```bash
for key in /etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$key" -E sha256
done
```

The displayed Aegis SSH fingerprint must exactly match one of the server's active host keys. `ssh-keyscan` over the same untrusted network path is useful for inspection but is not independent identity verification.

If the fingerprint cannot be verified, do not type `TRUST`. Investigate the server identity and network path first.

## 4. Test The Connection

Confirm the public alias was saved:

```bash
aegis-ssh server list
```

Start the broker in a dedicated terminal and leave it running:

```bash
aegis-ssh daemon
```

Enter the master password when prompted. In another terminal, run a low-risk test command:

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
```

Codex can use the same alias after its MCP configuration is loaded. Refer only to the alias in Agent conversations; do not provide the address or credentials.

## 5. Edit Or Remove A Server

Stop the daemon before making changes:

```bash
aegis-ssh lock
```

Replace a server's description and all connection fields, including its password and pinned host key:

```bash
aegis-ssh server edit prod
```

Use this command for password rotation. Verify the displayed host key again before typing `TRUST`.

Remove a server:

```bash
aegis-ssh server remove prod
```

Type the exact alias when prompted. Removal deletes the alias from both public configuration and the encrypted vault.

## Troubleshooting

- `aegis-ssh is not initialized`: run `aegis-ssh init` in a terminal.
- Server changes are refused: run `aegis-ssh lock` and retry.
- `unable to probe SSH host key`: confirm the host and port, network reachability, firewall rules, and that an SSH service is listening.
- Host-key verification fails during execution: stop and investigate. Use `server edit` only after confirming a legitimate key rotation through a trusted source.
- SSH authentication fails: stop the daemon and use `server edit <alias>` to enter the current password.
- `interactive terminal unavailable`: run the management command in a real terminal rather than through an MCP tool or redirected stdin.
- Lost master password: it cannot be recovered; the existing vault cannot be decrypted.

## After Local Codex Installation

Restart Codex so it discovers the newly installed Skill and MCP configuration. Keep `aegis-ssh daemon` running in a terminal, then ask Codex to operate a server by alias, for example: `Use Aegis SSH to run uptime on prod.`

