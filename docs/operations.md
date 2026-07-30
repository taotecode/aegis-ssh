# Operations Reference

> Run, inspect, recover, update, and troubleshoot the local Aegis SSH broker.

[README](../README.md) · [Server setup](server-setup.md) · [Agent usage](agent-usage.md) · **Operations** · [Security](../SECURITY.md) · [简体中文](operations.zh-CN.md)

## Command map

| Area | Commands |
| --- | --- |
| Broker lifecycle | `start`, `status`, `lock`, `unlock`, `stop` |
| Login service | `service install`, `service status`, `service uninstall` |
| Configuration | `config show`, `config set` |
| Logs | `log path`, `log show`, `log follow` |
| Recovery | `recovery enable`, `recovery restore`, `recovery reset` |
| Distribution | raw GitHub `install.sh` for install/update/uninstall |

## Broker lifecycle

```bash
aegis-ssh start     # detached process, then interactive unlock
aegis-ssh status    # daemon, vault, version, policy, logs, concurrency, service
aegis-ssh lock      # clear credentials; keep the process alive
aegis-ssh unlock    # load credentials again from the encrypted vault
aegis-ssh stop      # terminate the broker
```

`start` launches a detached broker in locked state and immediately asks for the master password through `/dev/tty`. The terminal can be closed after unlock. Use `lock` when the process should remain available without credentials; use `stop` before changing server storage.

> [!NOTE]
> A login service always starts locked. No master password or unlock material is persisted.

## Login service

```bash
aegis-ssh service install
aegis-ssh service status
aegis-ssh service uninstall
```

On macOS this installs a user LaunchAgent. On Linux it installs a systemd user service. `status` reports both broker availability and whether the login service is installed and enabled.

## Configuration

```bash
aegis-ssh config show
aegis-ssh config set language auto           # auto | en | zh-CN
aegis-ssh config set risk-policy enforce     # enforce | warn | off
aegis-ssh config set log-level info          # debug | info | warn | error | off
aegis-ssh config set batch-concurrency 8     # 1..32
```

Safe settings update the running broker through its local socket and are persisted for the next start. `risk-policy off` disables command-risk review, but it does not disable encrypted credential storage, pinned host keys, output redaction, or audit logging.

## Logs and diagnostics

```bash
aegis-ssh log path
aegis-ssh log show
aegis-ssh log follow
```

Operational JSONL logs live under `~/.aegis-ssh/logs/`. They contain levels, components, events, aliases, request IDs, stable error codes, and durations. They never contain commands or connection credentials.

Audit logs are separate from operational logs and cannot be disabled through `log-level`. Before sharing diagnostics, follow [Safe Diagnostics](../SECURITY.md#safe-diagnostics).

## Master-password recovery

Enable recovery while the master password is still known:

```bash
aegis-ssh stop
aegis-ssh recovery enable
```

Store the displayed recovery code offline. If the master password is later forgotten:

```bash
aegis-ssh recovery restore
```

This preserves configured servers and sets a new master password. If recovery was never enabled, the existing vault cannot be decrypted. `aegis-ssh recovery reset` requires exact confirmation, archives the old encrypted files with timestamped names, and initializes an empty vault.

> [!WARNING]
> A recovery code is equivalent to a high-value secret. Never put it in an Agent prompt, ticket, log, command argument, or cloud note shared with others.

## Install, update, and uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- update
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- uninstall
```

The installer downloads the matching checksum-verified Release, atomically replaces `~/.local/bin/aegis-ssh`, and configures every detected Agent. An update restores a previously running broker in locked state; run `aegis-ssh unlock` afterward. Normal uninstall removes managed Agent integrations and preserves encrypted user data.

Permanent removal requires both `--purge` and interactive `PURGE` confirmation:

```bash
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- uninstall --purge
```

Use `scripts/install.sh --source` only from a source checkout with Go 1.25+, or `--binary PATH` for an already-built binary.

## Troubleshooting checklist

| Symptom | Check |
| --- | --- |
| `daemon: unavailable` | Run `aegis-ssh start`, then `aegis-ssh status`. |
| Vault is locked | Run `aegis-ssh unlock` in a real local terminal. |
| Server changes are refused | Run `aegis-ssh stop` before add/edit/remove. |
| Approval is pending | Run `aegis-ssh approval list` and inspect the request locally. |
| Authentication fails | Stop the broker, run `server edit <alias>`, then test again. |
| Output is redacted or truncated | Treat it as an intentional disclosure boundary. |

---

[Back to README](../README.md) · [Server setup](server-setup.md) · [Agent usage](agent-usage.md)
