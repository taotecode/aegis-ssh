# Aegis SSH 重构设计：从 broker 二进制到 Agent Skill

> 状态：设计草案，待评审
> 目标版本：v1.0.0（相对 v0.4.0 为断裂式变更）
> 适用平台：macOS / Linux / Windows（amd64 + arm64）
> 最后更新：2026-08-26

---

## 1. 结论先行

- **形态变更**：仓库从「Go broker + MCP server +（附属）Skill」重构为「Agent Skill 为主体 + 极小 Go 二进制为执行器」。`SKILL.md` 成为唯一的 Agent 集成入口，MCP 层整体删除。
- **安全模型换挡**：删除加密 vault、主密码、常驻 daemon、本地审批中心、命令风险静态分析。保留主机密钥严格校验、输出脱敏、本地审计日志、批量并发执行。
- **代码规模**：现有 20122 行 Go（非测试 10112 行 / 测试 10010 行）预计压缩到非测试 3500~4500 行，删除 6 个包、移植 2 个包、新增 2 个包。
- **技术栈**：继续用 Go 1.25。加入 Windows 之后它从「可选项」变成「唯一合理选项」，理由见 §6。
- **必须正视的代价**：密码明文落盘、Agent 可见连接信息、审批下沉到宿主 Agent 的权限系统。这三条改变项目对外定位，README 核心卖点必须重写，见 §4。

---

## 2. 需求确认结果

本节记录已确认的需求，作为后续实现的唯一依据。

### 2.1 由你确认的决策

| 编号 | 决策项 | 结论 |
| --- | --- | --- |
| D1 | 凭据与连接信息存储 | 自有 `servers.yaml`，**无主密码**，靠文件权限保护 |
| D2 | 认证方式 | **密码认证与密钥认证都要支持** |
| D3 | 保留能力 | 主机密钥严格校验、输出脱敏、本地审计日志、批量并发多机执行 |
| D4 | 放弃能力 | 加密 vault、主密码、本地审批、命令风险分析（「Agent 自己会审批」） |
| D5 | 实现载体 | `SKILL.md` + 极小 Go 二进制 |
| D6 | 目标平台 | macOS、Linux、Windows 三端 |
| D7 | 旧代码处置 | main 分支全删，靠 `v0.4.0` tag 归档 |
| D8 | 技术栈细节 | 授权由本设计文档决定 |

### 2.2 D7 的准确含义

「全删」指**不保留旧的架构与包结构**，不等于「所有代码从零重写」。下列两块经过充分测试的实现按「移植」处理，见 §7 映射表：

- `internal/policy/redactor.go`（794 行 + 测试）：6 类输出脱敏规则，与 broker 架构无耦合，直接搬。
- `internal/sshclient/client.go`（348 行 + 测试）：SSH 执行、主机指纹常量时间比对、输出上限，去掉 `vault.ServerSecret` 依赖后可搬。

---

## 3. 放弃的能力与已接受的风险

这一节必须在动手前读完并确认。下面每一条都是「本次重构主动放弃」，不是遗漏。

### 3.1 放弃清单

| 放弃项 | 现状实现 | 放弃后的后果 |
| --- | --- | --- |
| 加密 vault | Argon2id(64MiB, t=3, p=2) + XChaCha20-Poly1305，`vault.enc` | 主机、端口、用户名、密码、私钥全部明文存在磁盘上 |
| 主密码与解锁态 | daemon 持有解密后的 vault，`unlock` / `lock` | 无需输入任何密码即可执行远程命令；一次误调用没有第二道闸门 |
| 恢复码 | `recovery.enc` + 离线恢复码 | 不再需要（没有主密码可丢） |
| 本地审批中心 | 5 分钟 TTL、一次性、绑定别名快照 | 阻塞式「等人批准」语义消失，改由宿主 Agent 的权限系统承担 |
| 命令风险静态分析 | `mvdan.cc/sh` AST 解析，7 类敏感读取检测（约 1527 行） | 不再识别 `cat ~/.ssh/id_rsa`、`env`、`kubectl get secret` 这类请求 |
| MCP server | 4 个工具（status / list / execute / execute_batch） | 只支持 skill 形态；纯 MCP 客户端失去支持 |
| 常驻 daemon 与 Unix socket | `~/.aegis-ssh/run/aegis.sock` + 自定义分帧协议 | 每次 `exec` 都是全新进程与全新 SSH 连接；顺带解决了 Windows 无 Unix socket 的问题 |
| launchd / systemd 登录服务 | `service install` | 不再需要（没有 daemon 可托管） |

### 3.2 已接受的风险

**R1 — 密码明文落盘（高严重度）。** `servers.yaml` 里的 `password` 字段是明文，唯一保护是文件权限。以下场景会直接泄露：同机其他进程以同一 OS 用户身份读取、`rsync` / `tar` / Time Machine 等备份工具、误将文件纳入 git、云盘同步目录。**缓解措施是强制项，见 §5.4 与 §5.5。**

**R2 — Agent 可见连接信息（高严重度）。** 旧架构的核心卖点是「Agent 只看到 `prod` 这样的别名」。新架构里 skill 脚本通过 Bash 工具运行，宿主 Agent 具备读取 `servers.yaml` 的能力，无法在技术上阻止。SKILL.md 只能以行为约束的方式要求 Agent 不读该文件——**这是约定，不是隔离**。

**R3 — 审批强度等于宿主 Agent 的权限模式（中严重度）。** 「Agent 自己会审批」在 Claude Code 的默认权限模式下成立（Bash 调用会弹权限提示），但在 `bypassPermissions` / 自动模式下不成立；Codex、Gemini CLI、OpenClaw 的门控机制各不相同。因此**不能**在文档里承诺「危险命令一定会被拦下」。

---

## 4. 定位变更与对外表述

现有 README 的第一句是：

> Let AI agents operate your servers without handing over your SSH secrets.

R1 + R2 之后这句话不再成立，必须重写。建议的新定位：

> **一个让 AI Agent 规范、可审计地操作远程服务器的 Agent Skill。** 连接由本地执行器完成，主机密钥强制校验，服务器输出在回到模型上下文之前先脱敏，每一条命令都留下本地审计记录。

对应的表述纪律：

- 可以说：主机密钥固定、输出脱敏、审计留痕、别名化操作、三端一致。
- 不可以说：凭据隔离、Agent 看不到密码、模型上下文无凭据、零信任、沙箱。
- `SECURITY.md` 的威胁模型章节需整体重写：威胁模型从「防止凭据进入模型上下文」变为「防止服务器上的凭据回流到模型上下文 + 防止中间人 + 事后可追查」。

---

## 5. 目标架构

### 5.1 仓库结构

```
aegis-ssh/
├── skill/aegis-ssh/              # 安装产物：整目录拷进各 Agent 的 skills 目录
│   ├── SKILL.md                  # 唯一 Agent 入口（≤120 行）
│   └── references/
│       ├── output-contract.md    # JSON 输出契约，按需读取
│       └── troubleshooting.md    # 排障流程，按需读取
├── cmd/aegis-ssh/main.go
├── internal/
│   ├── cli/                      # 命令解析、交互向导、JSON 渲染
│   ├── store/                    # servers.yaml 读写 + 校验 + 原子写
│   ├── ssh/                      # 移植自 sshclient：连接、指纹固定、密码/密钥认证
│   ├── redact/                   # 移植自 policy/redactor.go
│   ├── audit/                    # 极简 JSONL（约 120 行，去掉 fail-closed 与轮转锁）
│   ├── fanout/                   # 批量并发调度
│   └── platform/                 # 三端差异唯一收口处：路径、权限、控制台读密码
├── install/
│   ├── install.sh                # macOS / Linux
│   └── install.ps1               # Windows
├── docs/
└── .github/workflows/            # ci.yml 三端矩阵 + release.yml 六目标交叉编译
```

关键约束：**三端差异只允许出现在 `internal/platform`**。其余包不得出现 `runtime.GOOS` 判断或 `syscall` 直接调用，靠 `platform` 暴露的接口 + `_darwin.go` / `_linux.go` / `_windows.go` 构建标签实现。这一条是可用 `go vet` + 自定义 lint 强制检查的。

### 5.2 Skill 设计

**frontmatter 只用可移植基线字段。** 本机 `~/.claude/skills/` 下 30 余个已安装 skill 的实测样本显示，主流写法就是 `name` + `description`（少数附 `license`）。为了同一份 SKILL.md 能被 Claude Code、Codex、Gemini CLI、OpenClaw 共同加载，**不使用**任何单一客户端的专有字段（`argument-hint`、`disable-model-invocation`、`context`、`agent`、`model`、`paths`）。

```yaml
---
name: aegis-ssh
description: Run non-interactive shell commands on remote servers by alias through the local aegis-ssh executor, with pinned host keys, redacted output, and local audit records. Use when a task requires inspecting, diagnosing, or maintaining a server identified by an aegis-ssh alias.
license: Apache-2.0
---
```

`name` 必须与目录名 `aegis-ssh` 一致；`description` 是模型判断是否触发的唯一依据，必须同时写清「做什么」和「何时用」，控制在 1024 字符内。

**三级渐进披露。** ① 常驻上下文只有 `name` + `description`；② 命中后读 `SKILL.md` 正文（命令模板 + 行为约束 + 判定分支）；③ 正文按需指向 `references/` 下的两份文档。正文不得内嵌 JSON 字段表和完整排障树——那属于第三级。

**SKILL.md 正文必须包含的行为约束：**

1. 先跑 `aegis-ssh doctor --json` 判定可用性，失败时按 `references/troubleshooting.md` 处理，**不要**尝试自己修配置。
2. 只用别名寻址。禁止读取、打印、推断 `servers.yaml` 的任何内容，禁止把 host / port / user / password / 私钥路径 / 指纹写进回复或提交信息。
3. 有状态操作合并进一条命令（`cd /srv/app && ...`），不要试图维持远程会话。
4. 原样保留 `[REDACTED:...]` 标记与截断提示，不得尝试还原。
5. 服务器录入、修改、删除属于用户的交互操作，只能提示用户自己在终端执行 `aegis-ssh server add`，Agent 不代跑向导。

### 5.3 二进制命令面

命令面按「谁来调用」硬性切成两半，这是替代旧 `/dev/tty` 隔离机制的新边界。

**Agent 面：非交互、`--json` 输出、绝不读密钥输入、绝不写配置。**

| 命令 | 说明 |
| --- | --- |
| `aegis-ssh doctor --json` | 配置是否存在、文件权限是否合规、别名清单、二进制版本 |
| `aegis-ssh list --json` | 别名 + 描述 + 认证方式（不含 host / user / 凭据） |
| `aegis-ssh exec <alias> --json -- <command>` | 单机执行 |
| `aegis-ssh exec --servers a,b --json -- <command>` | 指定多机并发 |
| `aegis-ssh exec --all --json -- <command>` | 全部别名并发 |

**用户面：交互式，只从真实控制台读输入，永不输出 JSON。**

| 命令 | 说明 |
| --- | --- |
| `aegis-ssh server add \| edit <alias> \| remove <alias>` | 交互向导；密码与私钥口令无回显 |
| `aegis-ssh server list \| show <alias>` | `show` 默认掩码，`--reveal` 才显示完整连接信息 |
| `aegis-ssh server test <alias>` | 连通性 + 指纹校验 |
| `aegis-ssh doctor` | 人类可读版，附修复建议 |
| `aegis-ssh log path \| show` | 审计日志位置与内容 |
| `aegis-ssh skill install \| uninstall \| status` | 把 `skill/aegis-ssh` 拷进检测到的客户端 skills 目录 |
| `aegis-ssh version` | 版本 |

沿用现有的两道输入防线（`internal/app/app.go` 已实现，需移植）：拒绝 `--password` / `--host` / `--user` / `--private-key` 等**任何在命令行上传递凭据的写法**，拒绝 `AEGIS_SSH_PASSWORD` 等环境变量。理由是命令行与环境变量会进入 shell 历史、进程列表和 Agent 的工具调用记录。

相比 v0.4.0 删除的命令：`init`、`daemon`、`daemon-locked`、`start`、`start-locked`、`stop`、`lock`、`unlock`、`status`、`mcp`、`approval *`、`recovery *`、`service *`、`agent *`（多客户端 MCP 自动配置）、`server password`、`config set risk-policy`、`config set batch-concurrency`（改为 `exec --concurrency` 参数）。

### 5.4 数据文件

统一根目录：三端都用 `<用户主目录>/.aegis-ssh`（Windows 即 `%USERPROFILE%\.aegis-ssh`）。不引入 XDG / `%APPDATA%` 分歧，换取文档和排障口径一致。

```
~/.aegis-ssh/
├── servers.yaml        # 唯一配置源，权限见 §5.5
└── audit/aegis.jsonl   # 追加写审计日志，单文件上限 8 MiB，滚动保留 3 份
```

`servers.yaml` 格式：

```yaml
version: 1
servers:
  prod:
    description: "生产 Web"
    host: 10.0.0.5
    port: 22
    user: deploy
    auth: password              # password | key
    password: "s3cr3t"          # auth=password 时必填，明文
    host_key: "SHA256:xxxxxxxx" # 必填，强制校验，不允许 TOFU 自动接受
  db:
    host: 10.0.0.9
    user: root
    auth: key
    private_key_path: ~/.ssh/id_ed25519
    private_key_passphrase: ""  # 可选，明文
    host_key: "SHA256:yyyyyyyy"
```

设计要点：私钥**只存路径不存内容**（区别于旧 vault 把私钥字节搬进 `vault.enc`），降低明文落盘的暴露面；`host_key` 为必填字段，`server add` 时探测并要求用户通过可信渠道确认，运行期只做常量时间比对，不写 `known_hosts`、不接受未知主机。

### 5.5 三端差异矩阵

`internal/platform` 需要收口的全部差异：

| 关注点 | macOS / Linux | Windows |
| --- | --- | --- |
| 根目录 | `$HOME/.aegis-ssh` | `%USERPROFILE%\.aegis-ssh` |
| 目录权限 | `0700`，创建后复核 mode 与 uid | DACL：只保留当前用户 SID 的完全控制，移除继承 |
| 配置文件权限 | `0600` | 同上 DACL |
| 权限实现 | `os.Mkdir` + `os.Chmod` + `Lstat` 复核（现有 `internal/paths` 已实现） | `golang.org/x/sys/windows` 调 `SetNamedSecurityInfo`，显式 `PROTECTED_DACL_SECURITY_INFORMATION` |
| 无回显读密码 | 打开 `/dev/tty`（`O_RDWR`，不用进程 stdin） | 打开 `CONIN$` / `CONOUT$`，`SetConsoleMode` 去掉 `ENABLE_ECHO_INPUT` |
| 原子写 | 同目录临时文件 + `rename` | 同目录临时文件 + `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`（Windows 上 `os.Rename` 覆盖已存在文件会失败） |
| 符号链接防护 | `O_NOFOLLOW` | 检查 reparse point，拒绝 `FILE_ATTRIBUTE_REPARSE_POINT` |
| 换行 | `\n` | 写文件统一 `\n`；仅控制台输出按平台处理 |
| 私钥路径展开 | `~` → `$HOME` | `~` → `%USERPROFILE%`，同时接受 `/` 与 `\` 分隔符 |

**Windows 上「0600」不存在，因此 DACL 加固不是可选项，是三端一致性的硬性要求。** 只靠用户目录的默认继承 ACL 不够：Administrators 组与 SYSTEM 默认可读，且父目录 ACL 变更会向下继承。必须显式设置 protected DACL。

**`doctor` 必须实现权限自检并在不合规时判定为 fail：** Unix 检查 mode 是否为 `0700` / `0600` 且 uid 匹配；Windows 检查 DACL 是否只含当前用户 SID 且已断开继承。这是 R1 唯一的技术缓解手段，不能做成 warning。

### 5.6 可选加固（v1.1 候选，本次不做）

在不引入主密码的前提下，仍有平台原生方案可以把密码从明文变成静态加密：

- Windows：DPAPI `CryptProtectData`（用户范围），天然无需用户记密码。
- macOS：Keychain（`security add-generic-password`），首次访问可能弹系统授权框。
- Linux：libsecret / secret-service，缺失时退回明文。

不在 v1.0 做的理由：三端行为不一致（Linux 无统一后端）、macOS 授权框在非交互场景会挂住、会重新引入「解锁态」概念——而删除解锁态正是本次重构的目标之一。作为 §11 待确认项之一提出。

---

## 6. 技术栈决策与被否方案

**决策：Go 1.25，单静态二进制，`golang.org/x/crypto/ssh` 做 SSH 客户端。**

加入 Windows 之后，密码认证成了决定性约束。SSH 协议本身支持 password 认证，但**命令行 `ssh` 客户端不接受从标准输入喂密码**，必须借助外部工具：

| 方案 | 三端单文件 | 原生密码认证 | 运行时依赖 | 判定 |
| --- | --- | --- | --- | --- |
| Go + `x/crypto/ssh` | 是（6 目标交叉编译） | 是（协议层直接实现） | 无 | **采用** |
| bash + 系统 `ssh` | 否（Windows 无 POSIX shell） | 否（需 `sshpass`；macOS 默认无、Windows 无） | 依赖 shell 与 sshpass | 否决 |
| Python + Paramiko | 否（需解释器 + 依赖包） | 是 | python3 + pip 包，部分 Linux 精简镜像无 python3 | 否决 |
| Node + ssh2 | 否 | 是 | node 运行时 | 否决 |
| 纯 SKILL.md 无脚本 | — | — | — | 否决：脱敏、审计、并发都无处实现 |

附带收益：现有 `redactor.go`（794 行）与 `sshclient/client.go`（348 行）连同各自的测试可直接复用，`mvdan.cc/sh` 与 `modelcontextprotocol/go-sdk` 两个依赖被移除，`gopkg.in/yaml.v3`、`golang.org/x/crypto`、`golang.org/x/term`、`golang.org/x/sys` 保留。

---

## 7. 代码去留映射

行数为当前实测值（非测试 / 测试）。

| 现有位置 | 行数 | 处置 | 说明 |
| --- | --- | --- | --- |
| `internal/vault/` | 650 / 1196 | **删除** | 主密码与加密 vault 整体放弃（D4） |
| `internal/broker/` | 1899 / 2558 | **删除** | 无 daemon、无 socket、无自定义分帧协议 |
| `internal/approval/` | 367 / 485 | **删除** | 审批下沉到宿主 Agent（D4） |
| `internal/mcpserver/` | 334 / 329 | **删除** | 只保留 skill 形态（D5） |
| `internal/policy/analyzer*.go` | 733 / 1537 | **删除** | 命令风险静态分析放弃（D4）；同时移除 `mvdan.cc/sh` 依赖 |
| `internal/policy/redactor.go` | 794 / — | **移植** → `internal/redact/` | 6 类脱敏规则原样保留，只去掉 `policy.Category` 交叉引用 |
| `internal/sshclient/client.go` | 348 / 499 | **移植** → `internal/ssh/` | 改为接受 `store.Server` 而非 `vault.ServerSecret`；私钥改为按路径读取 |
| `internal/audit/logger.go` | 1031 / 1462 | **重写**（约 120 行） | 去掉 fail-closed、跨进程 flock、轮转仲裁；单进程追加写即可 |
| `internal/config/` | 173 / 213 | **重写** → `internal/store/` | 数据模型从「config + vault 两文件」并成单文件 `servers.yaml` |
| `internal/paths/paths.go` | 81 / 142 | **重写** → `internal/platform/` | 保留 Unix 权限复核逻辑，新增 Windows DACL 分支 |
| `internal/app/` | 3011 / 1025 | **大幅重写** → `internal/cli/` | 保留：参数/环境变量凭据拦截、交互向导、指纹探测、私钥文件校验、i18n。删除：daemon 生命周期、lifecycle flock、approval、recovery、service、`agent.go` 的 MCP 配置逻辑 |
| `internal/app/agent.go` | 661 / 346 | **收缩** → `cli/skillinstall.go` | 只保留「拷贝 skill 目录 + `.aegis-managed` 标记 + 拒绝覆盖非托管目录」这套逻辑（约 150 行），删掉 6 客户端的 MCP CLI 编排 |
| `internal/opslog/` | 124 / 36 | **删除** | 结构化运行日志与 daemon 绑定，一次性 CLI 不需要 |
| `internal/model/` | 219 / 303 | **收缩** | 只留 `exec` 的请求/结果结构与错误码 |
| `internal/testssh/` | 296 / — | **保留** | 内存 SSH 测试服务器，三端集成测试仍需要 |
| `internal/e2e/` | — / 208 | **重写** | 端到端场景改为「CLI + testssh」，不再有 daemon 拉起流程 |
| `skills/embed.go` + `skills/aegis-ssh/` | 8 / — | **重构** → `skill/aegis-ssh/` | `SKILL.md` 重写；`agents/openai.yaml` 删除；`go:embed` 保留，用于 `skill install` |
| `examples/mcp/`（5 个文件） | — | **删除** | 无 MCP |
| `scripts/install.sh` | 166 | **重写** | 去掉 MCP 配置调用，新增 `install.ps1` |
| `docs/agent-usage*.md` | 334 | **重写** | 内容变为 skill 安装与使用 |
| `docs/operations*.md` | 236 | **大幅删减** | 生命周期、服务、审批、恢复章节全部作废 |
| `docs/server-setup*.md` | 432 | **修订** | 向导步骤基本可用，删掉主密码与 daemon 停机前置条件 |
| `SECURITY*.md` | 456 | **重写** | 威胁模型按 §4 重新定义 |
| `README*.md` | 456 | **重写** | 核心卖点按 §4 重写 |

**i18n 的处置：** 保留现有 `localize(lang, en, zh)` 机制用于**用户面**输出（交互向导、`doctor`、错误提示），Agent 面统一 JSON、不做本地化。语言配置从已删除的 `config.yaml` 迁到 `servers.yaml` 顶层 `language: auto | en | zh-CN`，缺省时按 `LC_ALL` / `LC_MESSAGES` / `LANG` 推断（Windows 上退回 `GetUserDefaultLocaleName`）。同时修掉现有实现的一个缺陷——`(*App).text()` 每次调用都重读配置文件，新实现在进程启动时解析一次并缓存。

---

## 8. 分阶段实施计划

每个阶段结束都必须能通过验收命令，未通过不进入下一阶段。阶段之间在 `refactor/skill` 分支上按 commit 切分。

### 阶段 0：冻结与归档

- 在 `main` 当前提交打 `v0.4.0` tag（若尚未打）并推送，确认 GitHub Release 资产完整。
- 建 `refactor/skill` 分支。
- 验收：`git show v0.4.0 --stat` 可见完整旧实现；`go test ./...` 在 tag 上通过。

### 阶段 1：平台底座

- 新建 `internal/platform`：路径解析、私有目录/文件创建与权限复核、原子写、无回显控制台读取、`~` 展开。三端各一份实现 + 共享测试。
- 验收：`go test ./internal/platform/...` 在 macOS、Linux、Windows 三端 CI 全绿；`GOOS=windows go build ./...` 通过。

### 阶段 2：数据层

- 新建 `internal/store`：`servers.yaml` 模型、加载校验（别名合法性、必填字段、`host_key` 非空、认证方式与字段匹配）、原子保存、`doctor` 用的权限自检 API。
- 验收：`go test ./internal/store/...`；手工构造 mode `0644` 的 `servers.yaml`，`doctor` 必须 fail。

### 阶段 3：执行层

- 移植 `internal/ssh`（含指纹常量时间比对、输出上限、私钥按路径读取 + 口令）与 `internal/redact`。
- 新增 `internal/audit`（约 120 行）与 `internal/fanout`。
- 验收：`go test -race ./internal/ssh/... ./internal/redact/... ./internal/fanout/...`；用 `internal/testssh` 覆盖密码认证、密钥认证、口令保护密钥、指纹不匹配四条路径。

### 阶段 4：CLI

- 新建 `internal/cli`：命令分发、Agent 面 `--json`、用户面向导、凭据参数/环境变量拦截、`skill install`。
- 验收：`go test ./internal/cli/...`；`aegis-ssh --help` 输出与 §5.3 表格逐条对齐；`aegis-ssh exec x --password p -- ls` 必须被拒绝。

### 阶段 5：Skill

- 写 `skill/aegis-ssh/SKILL.md` 与两份 `references/`。
- 装到本机 `~/.claude/skills/aegis-ssh`，真机验证：触发命中、`doctor` 分支、单机执行、多机执行、脱敏标记保留、错误路径不泄露连接信息。
- 验收：一次真实会话里，Agent 仅凭 `SKILL.md` 完成「在 prod 上看磁盘占用并总结」而没有读取 `servers.yaml`。

### 阶段 6：删除与文档

- 删除 §7 标记为「删除」的全部包与文件，`go mod tidy`。
- 重写 README / SECURITY / docs 四组文档（中英各一份）。
- 验收：`go vet ./...`、`go test -race ./...` 全绿；`rg -n 'vault|broker|approval|mcp' --glob '!docs/refactor-to-skill*'` 无残留引用。

### 阶段 7：发布

- `install.sh` + `install.ps1`；release 工作流交叉编译 6 目标并生成校验和。
- 验收：三端各跑一遍全新安装到 `server add` 到 Agent 执行成功的完整链路。

---

## 9. 测试策略

现有测试覆盖率很高（测试 10010 行 ≈ 非测试 10112 行的 0.99 倍），这个标准要守住。

- **单元测试**：`store` 的校验分支、`redact` 的 6 类规则与边界（跨块截断、不完整 PEM、IPv6）、`platform` 的权限设置与复核。
- **集成测试**：基于 `internal/testssh` 的内存 SSH 服务器，覆盖密码认证、密钥认证、带口令密钥、指纹不匹配、连接超时、输出超限截断、并发扇出。
- **端到端测试**：临时 HOME 下走「`server add`（脚本喂控制台输入）→ `doctor` → `exec` → 读审计日志」全链路。
- **三端 CI 矩阵**：`ci.yml` 改为 `macos-latest` / `ubuntu-latest` / `windows-latest` × `go test -race ./...` + `go vet ./...`；额外加 `GOOS=windows GOARCH=arm64 go build` 等 6 目标编译检查。
- **安全回归测试**（必须有，对应 §3.2 的三条风险）：
  - `doctor` 在文件权限被放宽时必须返回非零退出码——三端各一例。
  - `exec` 的 JSON 输出中不得出现 `host` / `port` / `user` / `password` / 私钥路径 / `host_key` 任何字段，用结构体字段白名单断言。
  - 凭据类命令行参数与 `AEGIS_SSH_*` 环境变量拦截，逐个参数名一例。

## 10. 迁移与发布

- **版本**：`v1.0.0`，在 Release Notes 中显式标注 breaking change 与安全模型变更。
- **数据迁移**：v0.4.0 的 `vault.enc` 是 Argon2id + XChaCha20-Poly1305 加密的，新二进制不再包含解密代码，**不提供自动迁移**。升级路径为：用旧二进制逐个 `aegis-ssh server show <alias> --reveal` 与 `server password <alias>` 导出，再用新二进制 `server add` 重新录入。文档需给出这段步骤并提醒旧 `~/.aegis-ssh/*.enc` 可在确认后手工删除。
- **卸载既有集成**：升级前需用旧二进制跑 `aegis-ssh agent unconfigure auto` 清掉 6 个客户端里的 MCP 配置，否则会留下指向已删除 `mcp` 子命令的死配置。这一步要写进 Release Notes 的第一条。
- **分发**：GitHub Release 提供 6 个校验和二进制；`install.sh`（macOS/Linux）与 `install.ps1`（Windows）负责下载、校验、放置到 `~/.local/bin` 或 `%LOCALAPPDATA%\Programs\aegis-ssh`，并调用 `aegis-ssh skill install`。安装器**不得**在无用户确认的情况下由 Agent 触发。

## 11. 待确认事项

以下四项未在需求确认中覆盖，需要你决定后我再补进文档：

| 编号 | 待确认 | 影响 |
| --- | --- | --- |
| Q1 | **Agent 平台范围。** 建议一等支持能加载 SKILL.md 的客户端（Claude Code / Codex / Gemini CLI / OpenClaw），拷同一份目录即可。Cursor 与 VS Code 在 v0.4.0 里是纯 MCP 集成，删掉 MCP 后它们**会失去支持** | 决定 `skill install` 的目标目录列表，以及 README 支持矩阵 |
| Q2 | **是否接受 §5.6 的平台原生加固进 v1.0。** 若接受，密码可从明文变为静态加密且仍无需主密码，代价是 Linux 行为不统一 | 直接影响 R1 的严重度 |
| Q3 | **是否保留双语文档。** 现有 8 份文档都是中英各一份，重写工作量翻倍 | 阶段 6 的工作量 |
| Q4 | **项目名与仓库路径是否沿用 `aegis-ssh` / `github.com/taotecode/aegis-ssh`。** 定位已变（§4），但改名会作废现有 star、Release 链接与安装脚本 URL | 模块路径、安装器 URL、文档全量替换 |

## 12. 不确定性与局限

| 结论 | 置信度 | 依据与说明 |
| --- | --- | --- |
| 现有代码规模、包结构、命令面、加密方案、脱敏类别、审计字段 | **高** | 直接读取仓库代码实测，行数由 `wc -l` 统计 |
| Go + `x/crypto/ssh` 是三端 + 双认证的唯一低成本选择 | **高** | 现有 `internal/sshclient` 已用该库实现两种认证；`sshpass` 在 macOS 默认缺失、Windows 无原生版本 |
| SKILL.md 的可移植字段基线为 `name` + `description`（+ `license`） | **中高** | 本机 `~/.claude/skills/` 下 30 余个已安装 skill 的实测样本一致；未逐字校验官方 frontmatter reference |
| 三级渐进披露机制 | **中高** | 与官方公开说明一致；未在本机验证「正文何时被读取」的确切时机 |
| Codex / Gemini CLI / OpenClaw 能加载同一份 SKILL.md | **中** | 存在共享的 Agent Skills 开放格式，但各客户端的 skills 目录位置与优先级规则不同，需实测（对应 Q1） |
| Cursor / VS Code 是否已支持 skill 加载 | **低** | 检索到的说法互相矛盾，未能验证。文档暂按「不支持」表述 |
| Windows DACL 与 `CONIN$` 方案可行 | **中** | 属标准 Win32 用法，但本仓库无任何 Windows 代码与 Windows CI，未做过原型验证。阶段 1 的验收就是为了先把这一条打实 |
| 各阶段工作量与行数估算 | **中** | 基于现有代码结构推算，未做逐函数拆解 |

无可靠来源、需要实测才能定论的项：Q1 中各客户端 skills 目录的确切路径与冲突优先级、Cursor/VS Code 的 skill 支持状况、Windows arm64 上 `x/crypto/ssh` 的实际表现。
