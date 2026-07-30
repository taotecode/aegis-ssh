# 运维参考

> 运行、查看、恢复、更新和排查本机 Aegis SSH broker。

[项目首页](../README.zh-CN.md) · [服务器配置](server-setup.zh-CN.md) · [Agent 使用](agent-usage.zh-CN.md) · **运维** · [安全](../SECURITY.zh-CN.md) · [English](operations.md)

## 命令地图

| 范围 | 命令 |
| --- | --- |
| Broker 生命周期 | `start`、`status`、`lock`、`unlock`、`stop` |
| 登录服务 | `service install`、`service status`、`service uninstall` |
| 配置 | `config show`、`config set` |
| 日志 | `log path`、`log show`、`log follow` |
| 恢复 | `recovery enable`、`recovery restore`、`recovery reset` |
| 分发 | raw GitHub `install.sh` 安装/更新/卸载 |

## Broker 生命周期

```bash
aegis-ssh start     # 启动后台进程，然后交互解锁
aegis-ssh status    # 查看 daemon、vault、版本、策略、日志和服务状态
aegis-ssh lock      # 清除凭据，保持进程运行
aegis-ssh unlock    # 从加密 vault 重新加载凭据
aegis-ssh stop      # 终止 broker
```

`start` 会先启动锁定状态的后台 broker，紧接着通过 `/dev/tty` 请求主密码。解锁后可以关闭终端。需保留进程但清除凭据时使用 `lock`；修改服务器存储前使用 `stop`。

> [!NOTE]
> 登录服务始终以锁定状态启动，程序不会持久化主密码或解锁材料。

## 登录服务

```bash
aegis-ssh service install
aegis-ssh service status
aegis-ssh service uninstall
```

macOS 上安装用户 LaunchAgent，Linux 上安装 systemd 用户服务。`status` 同时报告 broker 可用性和登录服务是否已安装、已启用。

## 配置

```bash
aegis-ssh config show
aegis-ssh config set language auto           # auto | en | zh-CN
aegis-ssh config set risk-policy enforce     # enforce | warn | off
aegis-ssh config set log-level info          # debug | info | warn | error | off
aegis-ssh config set batch-concurrency 8     # 1..32
```

安全配置会通过本机 socket 动态更新运行中的 broker，并持久化供下次启动使用。`risk-policy off` 会关闭命令风险审查，但不会关闭凭据加密、主机指纹固定、输出脱敏或审计。

## 日志与诊断

```bash
aegis-ssh log path
aegis-ssh log show
aegis-ssh log follow
```

结构化运维日志位于 `~/.aegis-ssh/logs/`，只包含级别、组件、事件、别名、请求 ID、稳定错误码和耗时，不记录命令或连接凭据。

审计日志与运维日志相互独立，不能通过 `log-level` 关闭。分享诊断材料前，请阅读[安全诊断材料](../SECURITY.zh-CN.md#安全诊断材料)。

## 主密码恢复

在仍记得主密码时启用恢复：

```bash
aegis-ssh stop
aegis-ssh recovery enable
```

将显示的恢复码离线保存。以后忘记主密码时执行：

```bash
aegis-ssh recovery restore
```

该命令会保留已配置服务器并设置新主密码。若从未启用恢复，现有 vault 无法解密。`aegis-ssh recovery reset` 需要精确确认，会使用时间戳名称归档旧加密文件，并初始化空 vault。

> [!WARNING]
> 恢复码是高价值机密。不得将它放入 Agent 提示词、工单、日志、命令参数或与他人共享的云笔记。

## 安装、更新和卸载

```bash
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- update
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- uninstall
```

安装器会下载匹配平台且经过 checksum 校验的 Release，原子替换 `~/.local/bin/aegis-ssh`，并配置检测到的 Agent。更新会把原本运行的 broker 恢复为锁定状态，之后运行 `aegis-ssh unlock`。普通卸载会移除托管的 Agent 集成并保留加密用户数据。

永久删除还必须同时提供 `--purge` 并交互输入 `PURGE`：

```bash
curl -fsSL https://raw.githubusercontent.com/taotecode/aegis-ssh/main/scripts/install.sh | sh -s -- uninstall --purge
```

仅在 Go 1.25+ 的源码 checkout 中使用 `scripts/install.sh --source`；已有二进制可用 `--binary PATH` 安装。

## 排障检查表

| 现象 | 检查 |
| --- | --- |
| `daemon: unavailable` | 运行 `aegis-ssh start`，然后查看 `status`。 |
| Vault 已锁定 | 在真实本机终端运行 `aegis-ssh unlock`。 |
| 拒绝修改服务器 | 在 add/edit/remove 之前运行 `aegis-ssh stop`。 |
| 审批待处理 | 运行 `aegis-ssh approval list` 并在本机检查请求。 |
| 认证失败 | 停止 broker，运行 `server edit <别名>` 后重新测试。 |
| 输出被脱敏或截断 | 视为有意设置的数据披露边界。 |

---

[返回项目首页](../README.zh-CN.md) · [服务器配置](server-setup.zh-CN.md) · [Agent 使用](agent-usage.zh-CN.md)
