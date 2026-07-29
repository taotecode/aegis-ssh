# 添加和管理 SSH 服务器

[English](server-setup.md) | 简体中文

本文介绍首次初始化 vault、添加多台服务器、密码和私钥认证、校验主机密钥、测试连接、轮换凭据和删除服务器的完整流程。

## 开始前准备

你需要准备：

- 已在本机安装 Aegis SSH。
- 一台或多台网络可达，并使用密码或私钥认证的 SSH 服务器。
- 每台服务器的地址、端口、用户名，以及密码或私钥。
- 一个能够可信核对 SSH 主机密钥指纹的渠道，例如云厂商控制台、服务器控制台或管理员。

请在真实终端中执行服务器管理命令。所有机密信息都通过 `/dev/tty` 读取；不要把主密码、服务器地址、端口、用户名、密码、私钥、私钥口令或主机指纹放入命令参数、环境变量、MCP 配置或 Agent 提示词。

初始化 vault 或修改服务器前，daemon 必须处于停止状态。

## 1. 初始化 Vault

首次使用时执行一次初始化并设置主密码：

```bash
aegis-ssh init
```

在两次提示中输入相同的主密码。该密码用于加密 `~/.aegis-ssh/` 下的本地 vault，丢失后无法恢复。如果 Aegis SSH 已经初始化，请跳过此步骤。

## 2. 添加服务器

启动交互式添加流程：

```bash
aegis-ssh server add
```

程序会按以下顺序询问：

| 提示 | 含义 |
| --- | --- |
| `Master password` | 解锁本地加密 vault，输入内容不会显示。 |
| `Alias` | Codex 和其他 Agent 使用的公开别名，例如 `prod` 或 `db-primary`。别名必须以字母或数字开头，只能包含字母、数字、`.`、`_`、`-`，最长 64 个字符。 |
| `Description` | Agent 可见的可选公开描述。不要填写 IP、用户名、客户名称或其他私有基础设施信息。 |
| `Host` | 服务器域名或 IP 地址，仅保存在加密 vault 中。 |
| `Port` | SSH 端口，范围为 `1` 到 `65535`。 |
| `User` | SSH 登录用户名。 |
| `Authentication method (password/private-key)` | 必须输入 `password` 或 `private-key`。 |
| `Host key fingerprint` | 在认证前探测到的主机密钥指纹，必须通过可信渠道核对。 |
| `Type TRUST to pin this host key` | 只有核对无误后，才输入全大写的 `TRUST`。 |
| `SSH password` | 选择 `password` 时显示。输入内容不会显示，并且仅保存在加密 vault 中。 |
| `Private key file` | 选择 `private-key` 时显示。必须是当前用户拥有、组和其他用户均无权限、最大 1 MiB 的本地普通文件，支持 `~/` 路径。 |
| `Private key passphrase` | 仅当导入的私钥已加密时显示，输入内容不会显示。 |

以下是密码认证的交互示例：

```text
$ aegis-ssh server add
Master password: [hidden]
Alias: prod
Description: Production application server
Host: <server-host>
Port: 22
User: <ssh-user>
Authentication method (password/private-key): password
Host key fingerprint: SHA256:<fingerprint>
Type TRUST to pin this host key: TRUST
SSH password: [hidden]
server prod added
```

以下是私钥认证的交互示例：

```text
$ aegis-ssh server add
Master password: [hidden]
Alias: key-prod
Description: Production key server
Host: <server-host>
Port: 22
User: <ssh-user>
Authentication method (password/private-key): private-key
Host key fingerprint: SHA256:<fingerprint>
Type TRUST to pin this host key: TRUST
Private key file: ~/.ssh/id_ed25519
Private key passphrase: [hidden，仅加密私钥会显示]
server key-prod added
```

程序会读取并解析私钥，然后把私钥内容导入加密 vault。程序不会保存原始路径，后续 SSH 连接也不依赖原文件继续存在。符号链接、非普通文件、组或其他用户拥有权限的文件、无效私钥以及超过 1 MiB 的文件都会被拒绝。

添加服务器时，程序不会执行认证。它只会先建立足以获取主机密钥的连接，要求你核对并固定该密钥，然后保存选定的凭据。

## 3. 添加多台服务器

每增加一台服务器，就重新执行一次相同命令，并使用不同别名：

```bash
aegis-ssh server add  # 添加 prod
aegis-ssh server add  # 添加 staging
aegis-ssh server add  # 添加 db-primary
aegis-ssh server list
```

同一个 vault 可以同时保存密码服务器和私钥服务器。每次 `server add` 都会要求输入主密码，并在对应别名下保存一组独立连接信息。`server list` 只返回别名和公开描述，不会返回地址、用户名、认证方式或凭据。

## 4. 核对主机密钥

不能仅因为指纹由 Aegis SSH 显示就直接信任。必须将其与云厂商、服务器控制台或管理员通过独立可信渠道提供的指纹进行比较。

如果管理员能够通过可信控制台进入服务器，可以使用以下命令列出服务器的公钥指纹：

```bash
for key in /etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$key" -E sha256
done
```

Aegis SSH 显示的指纹必须与服务器当前启用的某个主机密钥完全一致。通过同一条不可信网络路径运行 `ssh-keyscan` 可以用于辅助检查，但不能作为独立的身份验证依据。

如果无法确认指纹，请不要输入 `TRUST`，应先调查服务器身份和网络路径。

## 5. 测试连接

确认公开别名已经保存：

```bash
aegis-ssh server list
```

在一个独立终端中启动 broker，并保持它在前台运行：

```bash
aegis-ssh daemon
```

根据提示输入主密码，然后在另一个终端执行低风险测试命令：

```bash
aegis-ssh status
aegis-ssh exec prod -- 'uptime'
```

Codex 加载 MCP 配置后也可以使用同一个别名。与 Agent 对话时只需提供别名，不要提供服务器地址或凭据。

## 6. 修改或删除服务器

修改前先停止 daemon：

```bash
aegis-ssh lock
```

替换服务器描述和全部连接字段，包括认证方式、凭据及已固定的主机密钥：

```bash
aegis-ssh server edit prod
```

服务器密码轮换、替换私钥或切换认证方式都使用此命令。输入 `TRUST` 前，必须重新核对显示的主机密钥。

删除服务器：

```bash
aegis-ssh server remove prod
```

根据提示输入完全一致的别名。删除操作会同时清除公开配置中的别名和加密 vault 中的连接信息。

## 故障排查

- 提示 `aegis-ssh is not initialized`：在终端中运行 `aegis-ssh init`。
- 拒绝修改服务器：运行 `aegis-ssh lock` 后重试。
- 提示 `unable to probe SSH host key`：检查地址和端口、网络连通性、防火墙规则，以及目标端口是否有 SSH 服务监听。
- 执行时主机密钥校验失败：立即停止并调查。只有通过可信来源确认服务器发生了合法密钥轮换后，才能使用 `server edit` 更新。
- SSH 认证失败：停止 daemon，使用 `server edit <alias>` 输入当前有效密码或导入当前私钥。
- 提示 `interactive terminal unavailable`：请在真实终端中运行管理命令，不要通过 MCP 工具或重定向的 stdin 执行。
- 丢失主密码：主密码无法恢复，现有 vault 将无法再解密。

## 本机 Codex 安装完成后

重新启动 Codex，使其发现新安装的 Skill 和 MCP 配置。在终端中保持 `aegis-ssh daemon` 运行，然后通过别名让 Codex 操作服务器，例如：`使用 Aegis SSH 在 prod 上执行 uptime。` 完整配置和提示词示例见[让 Agent 使用 Aegis SSH](agent-usage.zh-CN.md)。
