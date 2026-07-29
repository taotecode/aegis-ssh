# Aegis SSH

[简体中文] | [English](README.md)

Aegis SSH 是一个轻量级本地 SSH 代理，让 AI Agent 能够操作必须使用密码登录的 SSH 服务器，同时避免将服务器地址、端口、用户名和密码放入 Agent 提示词、MCP 参数、日志、环境变量或进程参数中。

项目是一个同时支持 macOS 和 Linux 的 Go 单二进制文件。Agent 通过标准 MCP 使用公开别名访问服务器；前台 daemon 负责持有解密后的凭据，并通过 Go SSH 库执行密码认证。

## 安装

在源码目录中构建并安装：

```bash
scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
```

安装已经构建好的二进制文件，并显式安装 Agent Skill：

```bash
scripts/install.sh --binary ./aegis-ssh --skill-dir "$HOME/.codex/skills"
```

安装脚本不会初始化或读取 `~/.aegis-ssh`。

## 初始化

创建加密本地存储，并设置主密码：

```bash
aegis-ssh init
```

添加一台仅支持密码登录的服务器。服务器地址、端口、用户名和密码都会通过 `/dev/tty` 交互式读取。输入 `TRUST` 之前，必须通过可信渠道核对显示的 SSH 主机密钥指纹。

```bash
aegis-ssh server add
aegis-ssh server list
```

每个交互字段、可信主机密钥校验、连接测试、密码轮换、删除和故障排查的完整说明见[添加和管理 SSH 服务器](docs/server-setup.zh-CN.md)。

只能在 daemon 已停止时修改或删除服务器别名：

```bash
aegis-ssh server edit prod
aegis-ssh server remove prod
```

## 运行

在终端中解锁 broker，并保持 daemon 在前台运行：

```bash
aegis-ssh daemon
```

在另一个终端中执行：

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
aegis-ssh exec prod -- 'cd /srv/app && git status --short'
```

`--` 后的整条远程命令必须使用引号包裹，以保持命令原始字节。可能暴露服务器敏感信息的命令会要求输入精确的交互式批准码。

停止 daemon 并清除内存中的凭据：

```bash
aegis-ssh lock
```

## MCP

所有支持的 Agent 客户端都启动同一个标准 stdio MCP 服务：

```text
aegis-ssh mcp
```

将 `examples/mcp/` 中对应的示例合并到客户端的 MCP 配置中：

- `codex.toml`
- `claude-code.json`
- `cursor.json`
- `openclaw.json`

MCP 提供以下工具：

- `get_ssh_broker_status`：查询 broker 和 vault 状态
- `list_ssh_servers`：列出公开别名和描述
- `ssh_execute`：通过别名执行精确的非交互式 Shell 命令
- `ssh_execute_approved`：在用户明确确认后执行已存储的待批准命令

这些工具只会返回别名和经过过滤的命令结果，不会返回服务器连接字段。

将 `skills/aegis-ssh` 安装到 Agent 的 Skill 目录，或让客户端直接加载该目录。Skill 会要求 Agent 优先使用 MCP、等待用户真实批准，并保留所有脱敏标记。

## 本地存储与运维

本地状态保存在 `~/.aegis-ssh/` 下，并使用严格的私有权限：

- `config.yaml`：仅保存别名、描述、超时、输出限制和策略设置
- `vault.enc`：保存加密的连接信息和已固定的主机密钥指纹
- `audit/audit.jsonl`：保存有界的命令元数据、策略决策和脱敏计数
- `run/aegis.sock`：daemon 运行时的本地用户私有 socket

只能在 daemon 已停止时，将 `config.yaml` 和 `vault.enc` 作为同一组一起备份。备份也必须使用私有权限存储。主密码无法恢复；丢失主密码后，vault 将无法再解密。

轮换服务器密码：

```bash
aegis-ssh lock
aegis-ssh server edit <alias>
aegis-ssh daemon
```

仅能根据可信源重新确认主机密钥指纹。

## 故障排查

- `daemon: unavailable`：在单独终端中运行 `aegis-ssh daemon`。
- daemon 启动时提示 vault 锁定或存储失败：检查主密码，以及 `~/.aegis-ssh` 的归属和权限。
- 主机密钥校验失败：立即停止操作并调查服务器身份，不得绕过指纹固定。
- SSH 认证失败：停止 daemon，执行 `server edit`，然后输入当前有效密码。
- 服务器修改被拒绝：先执行 `aegis-ssh lock`，再重试管理命令。
- 输出中出现 `[REDACTED:...]`：broker 有意隐藏了敏感数据，不得尝试还原。

## 安全边界

Aegis SSH 提供凭据隔离、最佳努力的命令风险分析、批准、输出脱敏和审计，但它不是完整的远程 Shell 沙箱。允许执行任意远程 Shell 的 Agent 可能构造绕过静态分析或输出过滤的命令。

同一本地 OS 用户下的恶意进程也可以尝试读取 daemon 内存、追踪进程、访问 Unix socket 或修改用户文件。如果需要防御同用户本地代码，应使用独立 OS 账户或更强的主机隔离。

完整的威胁边界、安全操作规则和漏洞报告方式见 [SECURITY.zh-CN.md](SECURITY.zh-CN.md)。

## 版本发布

已发布版本和各平台压缩包可从 [GitHub Releases](https://github.com/taotecode/aegis-ssh/releases) 下载。

维护者发布新版本时，需要先添加非空的中英双语 `.github/releases/vX.Y.Z.md` 文件，再推送对应的 `vX.Y.Z` 标签。Release 工作流会在 macOS 和 Linux 上运行测试，构建全部支持平台的压缩包，校验校验和，然后发布 GitHub Release。如果缺少版本说明文件，工作流会直接失败，因此每个正式发布的版本都会有明确说明。

## 开发

```bash
go test ./...
go test -race ./...
go vet ./...
scripts/package.sh ./dist
```

## 许可证

Apache License 2.0，详见 [LICENSE](LICENSE)。
