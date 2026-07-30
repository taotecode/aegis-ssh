# 运维参考

使用 `start`、`stop`、`lock`、`unlock` 和 `status` 管理 broker。`service install` 创建用户级 launchd 或 systemd 服务，并始终以锁定状态自启；程序不会保存解锁材料。

使用 `config show` 和 `config set language|risk-policy|log-level|batch-concurrency 值` 管理安全配置，修改前需要停止 broker。

结构化运维日志位于 `~/.aegis-ssh/logs/`，可通过 `log path` 和 `log show` 查看，或使用 `log follow` 持续跟踪最新日志。日志只包含级别、组件、事件、别名、请求 ID、稳定错误码和耗时，不记录命令或连接凭据。审计日志与运维日志独立，不能通过日志级别关闭。

安装脚本支持 `install`、`update` 和 `uninstall`。普通卸载保留加密用户数据；只有显式传入 `--purge` 并输入 `PURGE` 才永久删除。
