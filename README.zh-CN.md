# Aegis SSH

[简体中文] | [English](README.md)

> **让 AI Agent 操作 SSH 服务器，但绝不把 SSH 凭据交给 Agent。**

Aegis SSH 是 AI Agent 与服务器之间的本机隐私防火墙。Agent 只看到 `prod` 这样的公开别名；密码、导入的私钥、地址、用户名、主机指纹和主密码材料不会进入提示词、MCP 参数、环境变量、进程参数或运维日志。

项目是一个同时支持 macOS 和 Linux 的 Go 单二进制文件，提供加密存储、固定主机身份、三档风险策略、本机审批、输出脱敏、有界审计和多服务器并发执行。

## v0.3 快速开始

```bash
scripts/install.sh
aegis-ssh init
aegis-ssh server add
aegis-ssh start
```

启动后可以关闭终端。`lock` 只清除内存凭据，`unlock` 重新解锁，`stop` 停止后台进程；`service install` 可安装登录时自动启动但保持锁定的 launchd/systemd 用户服务。

风险命令通过 `approval list/show/approve/deny` 在本机审批，不再污染 Agent 对话。可使用 `config set risk-policy enforce|warn|off` 切换策略，并使用 `exec --servers prod,staging` 或 `exec --all` 并发执行。

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

每台服务器执行一次 `server add`，并设置唯一的公开别名。同一个 vault 可以同时保存 `prod`、`staging`、`db-primary` 以及后续继续添加的其他服务器。

```bash
aegis-ssh server add
aegis-ssh server list
```

在仍记得主密码时启用恢复，并将仅显示在终端的恢复码离线保存：

```bash
aegis-ssh recovery enable
aegis-ssh recovery restore  # 忘记主密码后保留服务器数据重设
```

未提前启用恢复的旧 vault 在主密码丢失后无法解密。`aegis-ssh recovery reset` 会归档旧加密文件并创建新的空 vault。

使用密码认证时，依次输入：

```text
Master password: 本地主密码，不显示
Alias: 给 Agent 使用的公开别名，例如 prod
Description: 公开描述，不要填写 IP 等机密
Host: 服务器 IP 或域名
Port: SSH 端口
User: SSH 用户名
Authentication method (password/private-key): password
Host key fingerprint: 程序自动显示
Type TRUST to pin this host key: 核对指纹后输入 TRUST
SSH password: 服务器密码，不显示
```

使用私钥认证时，前面的字段相同，但认证方式选择 `private-key`：

```text
Authentication method (password/private-key): private-key
Host key fingerprint: 程序自动显示
Type TRUST to pin this host key: 核对指纹后输入 TRUST
Private key file: ~/.ssh/id_ed25519
Private key passphrase: 私钥口令，不显示；仅加密私钥会出现此提示
```

程序会在本机读取并校验私钥，然后将私钥内容导入 `vault.enc`，不会保存私钥原始路径。所有连接字段都通过 `/dev/tty` 读取。输入 `TRUST` 之前，必须通过可信渠道核对显示的 SSH 主机密钥指纹。

多服务器示例、每个字段、私钥文件要求、可信主机密钥校验、凭据轮换、删除和故障排查的完整说明见[添加和管理 SSH 服务器](docs/server-setup.zh-CN.md)。

只能在 daemon 已停止时修改或删除服务器别名：

```bash
aegis-ssh server edit prod
aegis-ssh server remove prod
```

## 后台运行

启动并解锁 broker，随后即可关闭终端：

```bash
aegis-ssh start
```

需要在本机查看密码认证服务器的密码时，运行 `aegis-ssh server password <别名>` 并输入主密码。密码只显示在当前真实终端，不会进入 MCP 或重定向的 stdout。

在另一个终端中执行：

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
aegis-ssh exec prod -- 'cd /srv/app && git status --short'
```

`--` 后的整条远程命令必须使用引号包裹。默认 `enforce` 策略下，风险命令会等待本机审批中心处理，不会要求在 Agent 对话中回复批准码。

按需锁定、重新解锁或停止：

```bash
aegis-ssh lock
aegis-ssh unlock
aegis-ssh stop
```

## MCP

所有支持的 Agent 客户端都启动同一个标准 stdio MCP 服务：

```text
aegis-ssh mcp
```

使用已安装二进制文件的绝对路径为 Codex 注册 MCP：

```bash
codex mcp add aegis-ssh -- "$HOME/.local/bin/aegis-ssh" mcp
codex mcp list
```

安装或更新 MCP 配置、Skill 后，请重新启动 Codex。

将 `examples/mcp/` 中对应的示例合并到客户端的 MCP 配置中：

- `codex.toml`
- `claude-code.json`
- `cursor.json`
- `openclaw.json`

MCP 提供以下工具：

- `get_ssh_broker_status`：查询 broker 和 vault 状态
- `list_ssh_servers`：列出公开别名和描述
- `ssh_execute`：通过别名执行精确的非交互式 Shell 命令
- `ssh_execute_batch`：在多个公开别名上并发执行相同命令

这些工具只会返回别名和经过过滤的命令结果，不会返回服务器连接字段。

将 `skills/aegis-ssh` 安装到 Agent 的 Skill 目录，或让客户端直接加载该目录。Skill 会要求 Agent 优先使用 MCP、等待用户真实批准，并保留所有脱敏标记。

启动 `aegis-ssh start` 后，可以直接通过别名要求 Agent 操作：

```text
使用 Aegis SSH 列出已经配置的服务器。
使用 Aegis SSH 在 prod 上执行 uptime。
使用 Aegis SSH 在 staging 上执行 `cd /srv/app && git status --short`。
```

Codex 配置、MCP 与 Skill 的关系、工具调用流程、提示词示例、审批和故障排查见[让 Agent 使用 Aegis SSH](docs/agent-usage.zh-CN.md)。

## 本地存储与运维

本地状态保存在 `~/.aegis-ssh/` 下，并使用严格的私有权限：

- `config.yaml`：仅保存别名、描述、超时、输出限制和策略设置
- `vault.enc`：保存加密的连接信息和已固定的主机密钥指纹
- `audit/audit.jsonl`：保存有界的命令元数据、策略决策和脱敏计数
- `run/aegis.sock`：daemon 运行时的本地用户私有 socket

只能在 daemon 已停止时，将 `config.yaml` 和 `vault.enc` 作为同一组一起备份。备份也必须使用私有权限存储。请提前运行 `recovery enable` 并离线保存恢复码；否则丢失主密码后无法解密现有 vault。

轮换服务器密码或替换私钥：

```bash
aegis-ssh stop
aegis-ssh server edit <alias>
aegis-ssh start
```

仅能根据可信源重新确认主机密钥指纹。

## 故障排查

- `daemon: unavailable`：运行 `aegis-ssh start`。
- daemon 启动时提示 vault 锁定或存储失败：检查主密码，以及 `~/.aegis-ssh` 的归属和权限。
- 主机密钥校验失败：立即停止操作并调查服务器身份，不得绕过指纹固定。
- SSH 认证失败：停止 daemon，执行 `server edit`，然后输入当前有效密码或导入当前私钥。
- 服务器修改被拒绝：先执行 `aegis-ssh stop`，再重试管理命令。
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
