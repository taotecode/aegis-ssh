# Security

> Aegis SSH isolates SSH credentials from normal AI-agent interfaces. It does not turn arbitrary remote shell access into a sandbox.

[README](README.md) · [Server setup](docs/server-setup.md) · [Agent usage](docs/agent-usage.md) · [Operations](docs/operations.md) · **Security** · [简体中文](SECURITY.zh-CN.md)

## Security boundary

| Protected by Aegis SSH | Outside the guarantee |
| --- | --- |
| Credentials encrypted at rest | A determined Agent with arbitrary shell access |
| Secrets entered through `/dev/tty` | Malicious code running as the same OS user |
| No connection secrets in MCP schemas or CLI arguments | A compromised local host or SSH server |
| Pinned SSH host keys checked on every connection | Data encoded to evade static analysis or redaction |
| Local approval, output filtering, and audit records | Recovery from a lost password without prior recovery setup |

Imported private-key contents and passphrases are encrypted in the vault; the source key path is not stored. The daemon owns decrypted credentials and uses them for SSH authentication. Agents receive public aliases and filtered results.

> [!IMPORTANT]
> This is credential isolation and best-effort disclosure control, not a remote shell sandbox.

## Accepted limitations

An Agent allowed to execute arbitrary remote shell can construct commands that evade static analysis or encode sensitive data in forms the output filter does not recognize. Local approval and redaction reduce accidental disclosure; they cannot guarantee containment against a determined command author.

A malicious process running as the same local OS user may inspect process memory, interact with the Unix socket, trace the daemon, or modify user files. Use a separate OS account or stronger host isolation when defending against same-user local code.

Local approval prevents the Agent from self-approving through MCP, but it cannot prove who controls the local terminal. Protect the local account and review the exact alias, risk categories, and command before approval.

## Operational rules

- Protect `~/.aegis-ssh`, timestamped recovery archives, backups, recovery codes, and the local user account.
- Run `aegis-ssh lock` to clear in-memory credentials; run `aegis-ssh stop` when the broker is not needed.
- Verify host-key fingerprints through an independent trusted channel before enrollment.
- Never pass credentials or recovery material through flags, environment variables, Agent prompts, MCP configuration, tickets, or chat.
- Treat every `[REDACTED:...]` marker and truncation warning as final.
- Back up `config.yaml`, `vault.enc`, and `recovery.enc` together while the broker is stopped.
- Use `server password <alias>` only in a private terminal; terminal recording and clipboard tools may capture the displayed password.

## Safe diagnostics

| Usually safe after review | Never share |
| --- | --- |
| `aegis-ssh status` | `vault.enc`, `recovery.enc`, or archived vault files |
| Public aliases from `server list` | Master, recovery, SSH, or private-key passwords |
| Stable error codes | Private keys, passphrases, or source paths |
| Reviewed operational log records | Process memory, core dumps, debugger output, or socket traffic |
| Sanitized audit metadata | Enrollment/password-reveal terminal recordings |
| Preserved redaction markers | Raw remote output that triggered sensitive approval |

Private aliases and command previews may still identify infrastructure or workloads. Remove them from public reports when necessary.

## Vulnerability reporting

Do not publish real credentials, hosts, addresses, audit records, recovery codes, or vault files in an issue. Open a minimal public issue containing only sanitized reproduction steps and ask the maintainers for a private reporting channel.

Include:

- affected version and operating system;
- sanitized reproduction steps;
- expected and observed security behavior;
- whether the issue is reproducible without real infrastructure.

---

[Back to README](README.md) · [Operations reference](docs/operations.md)
