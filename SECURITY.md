# Security

English | [简体中文](SECURITY.zh-CN.md)

## Boundary

Aegis SSH protects password-only connection details from normal AI-agent interfaces. Credentials are encrypted at rest, entered through `/dev/tty`, held by the daemon, and omitted from MCP schemas, CLI arguments, logs, and public result types. SSH host keys are pinned and checked on every connection.

This is credential isolation and best-effort disclosure control, not a remote shell sandbox.

## Accepted Limitations

An agent allowed to execute arbitrary remote shell can construct commands that evade static analysis or encode sensitive data in forms the output filter does not recognize. Approval and redaction reduce accidental disclosure; they cannot guarantee containment against a determined command author.

A malicious process running as the same local OS user can inspect process memory, interact with the user's Unix socket, trace the daemon, or modify the user's files. Use a separate OS account or stronger host isolation when defending against same-user local code.

The broker cannot cryptographically prove that an approval reply came from a human. The companion Skill requires agents to wait for the user's exact reply, and the audit log records approval lifecycle events.

## Operational Rules

- Keep `~/.aegis-ssh`, backups, and the local user account private.
- Stop the daemon with `aegis-ssh lock` when it is not needed.
- Verify host-key fingerprints through a trusted channel before enrollment.
- Do not pass passwords through flags, environment variables, prompts, or MCP configuration.
- Treat redaction markers as final; do not ask an agent to bypass them.
- Back up `config.yaml` and `vault.enc` together while the daemon is stopped.

## Safe Diagnostics

Share only the output of `aegis-ssh status`, public aliases from `aegis-ssh server list`, error codes, and audit lines reviewed to contain only aliases, command hashes/previews, decisions, and redaction counts. Preserve every redaction marker.

Never share `vault.enc`, master or SSH passwords, process memory/core dumps, socket traffic, terminal recordings from enrollment, or raw remote output that triggered approval. Remove private aliases and command previews from public reports when they identify infrastructure or workloads.

## Reporting

Do not publish suspected vulnerabilities with real credentials, hostnames, addresses, audit records, or vault files. Open a private maintainer contact first when one is available; otherwise open a minimal public issue containing only sanitized reproduction steps and request a private channel.
