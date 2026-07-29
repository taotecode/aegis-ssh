# Use Aegis SSH With Agents

English | [简体中文](agent-usage.zh-CN.md)

This guide explains how an AI Agent uses Aegis SSH after one or more servers have been enrolled. Agents see only public aliases such as `prod`; password and private-key authentication are handled locally by the broker and are identical from the Agent's perspective.

## MCP And Skill

Aegis SSH provides two complementary integrations:

- **MCP is the tool transport.** It gives the Agent four callable tools for checking the broker, listing aliases, executing a command, and completing a user-approved command.
- **The Skill is behavioral guidance.** It tells a compatible Agent to use those MCP tools safely, address servers only by alias, wait for real user approval, and preserve redaction markers.

MCP is required for direct tool calls. The Skill is recommended but does not replace MCP. Clients without Skill support can still use Aegis SSH through MCP.

Server enrollment is deliberately not available through MCP. Run `aegis-ssh init`, `server add`, `server edit`, and `server remove` yourself in a real terminal so connection details and credentials are read only from `/dev/tty`. See [Add And Manage SSH Servers](server-setup.md).

## Codex Setup

Install the binary and Skill from the source tree or an extracted release archive:

```bash
scripts/install.sh --binary ./aegis-ssh --skill-dir "$HOME/.codex/skills"
```

When building from source, omit `--binary ./aegis-ssh`:

```bash
scripts/install.sh --skill-dir "$HOME/.codex/skills"
```

Register the MCP server with an absolute binary path:

```bash
codex mcp add aegis-ssh -- "$HOME/.local/bin/aegis-ssh" mcp
codex mcp list
```

Restart Codex after installing or updating the Skill or MCP configuration. A running Codex session may not discover changes made after it started.

## Start The Broker

Start and unlock the foreground daemon in a separate terminal before asking an Agent to connect:

```bash
aegis-ssh daemon
```

Enter the local master password at the hidden prompt and leave this terminal open. The MCP process does not unlock the vault itself; it communicates with this local daemon.

Stop the daemon and clear in-memory credentials when finished:

```bash
aegis-ssh lock
```

## Ask The Agent

Refer only to a configured alias. Do not include an address, port, username, password, private key, passphrase, or fingerprint in the prompt.

Example prompts:

```text
Use Aegis SSH to list the configured servers.
Use Aegis SSH to run uptime on prod.
Use Aegis SSH to run `cd /srv/app && git status --short` on staging.
Use Aegis SSH to inspect disk usage on db-primary and summarize the result.
```

Equivalent Chinese prompts also work:

```text
使用 Aegis SSH 列出已经配置的服务器。
使用 Aegis SSH 在 prod 上执行 uptime。
使用 Aegis SSH 在 staging 上执行 `cd /srv/app && git status --short`。
```

Password and private-key servers are used in exactly the same way. The Agent does not need to know which authentication method an alias uses.

## Tool Flow

For a normal request, the Agent should use this flow:

```text
get_ssh_broker_status
        |
        v
list_ssh_servers        (when the alias is unknown or must be checked)
        |
        v
ssh_execute
        |
        +--> completed: return filtered output
        |
        +--> requires_approval: show the message and wait for the user
                                      |
                                      v
                              ssh_execute_approved
```

The four MCP tools are:

| Tool | Purpose |
| --- | --- |
| `get_ssh_broker_status` | Check whether the daemon is reachable and the vault is unlocked. |
| `list_ssh_servers` | List public aliases, descriptions, and availability. |
| `ssh_execute` | Execute one exact non-interactive command through an alias. |
| `ssh_execute_approved` | Execute the already stored command after exact user confirmation. It cannot accept a replacement command. |

## Approval Flow

Some commands can expose sensitive server information. The first call then returns `requires_approval` and a message similar to:

```text
检测到风险类别：network。请由用户确认后回复：允许 ABCD
```

The Agent must show that message verbatim and stop. To approve, reply with exactly:

```text
允许 ABCD
```

The Agent may then call `ssh_execute_approved` using the returned single-use approval ID and code. The Agent must not approve on your behalf. Approvals expire after five minutes, are consumed once, and are bound to the original alias, command, and execution limits. A changed command requires a new approval.

Command output is filtered even after approval. Keep every `[REDACTED:...]` marker and truncation warning as returned; do not ask the Agent to reconstruct hidden data.

## Other Agent Clients

All clients launch the same stdio command:

```text
$HOME/.local/bin/aegis-ssh mcp
```

Configuration examples are available in `examples/mcp/` for Claude Code, Cursor, and OpenClaw as well as Codex. Merge the matching example into that client's MCP configuration and use an absolute binary path when the client does not inherit your shell `PATH`. Restart the client after changing its configuration.

Clients that support reusable Skills can load `skills/aegis-ssh`. Clients without Skill support can rely on the MCP tool descriptions and the workflow in this guide.

## Troubleshooting

- MCP server is missing: verify `codex mcp list` or the equivalent client configuration, use the absolute binary path, and restart the client.
- `daemon: unavailable`: run `aegis-ssh daemon` in a separate terminal and leave it running.
- Vault is locked: enter the master password in the daemon terminal, never in the Agent conversation.
- Alias is missing: stop the daemon, run `aegis-ssh server add` in a real terminal, then restart the daemon.
- Authentication fails: stop the daemon and run `aegis-ssh server edit <alias>` to replace the password or private key.
- Approval fails: repeat the original request and reply with the new exact code before it expires.
- Output is redacted or truncated: this is an intentional disclosure boundary, not an MCP transport failure.
