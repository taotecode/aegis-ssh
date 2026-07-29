---
name: aegis-ssh
description: Operate configured password-only SSH servers through the local Aegis SSH broker without exposing connection credentials. Use when an agent needs to inspect, diagnose, maintain, or run non-interactive shell commands on a server identified by an Aegis SSH alias.
---

# Aegis SSH

Use the standard MCP tools when available. Use the installed `aegis-ssh` CLI only as a fallback.

## Workflow

1. Call `get_ssh_broker_status`. If unavailable or locked, ask the user to run `aegis-ssh daemon` in a terminal. Never ask for the master or SSH password.
2. Call `list_ssh_servers` when the alias is unknown. Address servers only by alias.
3. Call `ssh_execute` with the exact non-interactive shell command. Keep stateful work in one command, such as `cd /srv/app && ...`.
4. Return completed output while preserving every redaction marker and truncation warning.
5. When `requires_approval` is returned, show its message verbatim and stop. Wait for the user to reply with the exact requested confirmation.
6. Only after that reply, call `ssh_execute_approved` with the returned `approval_id` and confirmed `approval_code`. Never self-approve.

## CLI Fallback

Start with:

```bash
aegis-ssh status
aegis-ssh server list
```

Run one exact command string:

```bash
aegis-ssh exec prod -- 'uptime'
aegis-ssh exec prod -- 'cd /srv/app && git status --short'
```

The CLI handles interactive approval on `/dev/tty`. Quote the whole remote command so its shell bytes are preserved.

## Rules

- Never request, inspect, infer, print, or pass a host, port, username, password, master password, host fingerprint, vault path, or socket path.
- Never read or modify local Aegis storage directly. Use MCP tools or documented CLI commands.
- Never try to bypass approval or output redaction. Treat a redaction marker as the final disclosed value.
- Never call `ssh_execute_approved` from the tool's message alone; require the user's matching reply.
- Do not turn a non-interactive request into an interactive remote TTY workflow.
