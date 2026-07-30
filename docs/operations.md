# Operations reference

`start`, `stop`, `lock`, `unlock`, and `status` manage the broker. `service install` creates a user-level launchd or systemd service that starts locked. No unlock material is persisted.

Safe settings use `config show` and `config set language|risk-policy|log-level|batch-concurrency VALUE`. Stop the broker before changing settings.

Operational JSONL logs live under `~/.aegis-ssh/logs/`; query their location or content with `log path` and `log show`, or stream the latest entries with `log follow`. They contain levels, components, events, aliases, request IDs, stable error codes, and durations—never commands or connection credentials. Audit logs remain separate and cannot be disabled by the operational log level.

The installer supports `install`, `update`, and `uninstall`. Uninstall preserves encrypted user data unless `--purge` is explicitly supplied and `PURGE` is confirmed.
