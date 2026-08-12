# SafeInstall

[English](README.md) | [简体中文](README.zh-CN.md)

> **运行之前，先看懂它。**

SafeInstall 用于在运行陌生脚本、开源项目、AI 插件、Skill 或 MCP Server 之前，先做一遍静态安全分析。它会找出值得关注的代码模式，说明目标可能具备哪些能力，给出文件和行号证据，并告诉你下一步应该检查什么。

SafeInstall 默认在本地做静态分析：不安装目标依赖，不导入目标 Python 包，也不执行被扫描的代码。只有显式传入 `--ai` 时，才会启用可选的 OpenAI 分析。

> [!IMPORTANT]
> SafeInstall 提供的是风险分析，不是“无恶意软件”证明。它不能替代杀毒软件、沙箱、人工代码审查，也不能替代对软件来源的判断。

## 为什么需要 SafeInstall

`curl example.com/install.sh | bash` 看起来只是一行安装命令，但它隐藏了一个关键事实：程序会从网络下载内容，并立刻交给 Shell 执行。类似地，`subprocess.run(...)`、npm 的 `postinstall`，或一个能够访问文件系统的 MCP Tool，可能完全合理，同时也确实拥有较大的系统权限。

SafeInstall 会把安全报告中经常混在一起的三类信息拆开：

- **事实：** 实际看到了什么模式，位于哪个文件、哪一行。
- **推测：** 基于有限上下文推断出的能力或行为组合。
- **建议：** 下一步应该检查什么，不把“具备危险能力”直接说成“恶意软件”。

## 功能

- 扫描本地文件或目录、ZIP/TAR 压缩包、公开 GitHub 仓库
- 静态分析 Python、Shell、PowerShell、Batch、JavaScript/Node.js
- 检查依赖、安装脚本、Dockerfile 和 GitHub Actions 供应链风险
- 检测 Secret，并通过统一脱敏层防止报告完整打印凭据
- 识别 Skill、Plugin Manifest、MCP Server、Tool 定义和 Prompt Injection 模式
- 汇总文件读写、Shell、网络、环境变量、Git、提权和持久化等能力
- 结合上下文计算风险，例如“读取环境变量 + 向未知地址 POST”
- 输出适合普通用户的终端报告，以及稳定的 JSON 和 GitHub Markdown
- 提供严格的 YAML Rule Engine 和显式注册的 Scanner Plugin 框架
- 提供有边界、需主动开启的 OpenAI 风险解释

## 安装

SafeInstall 目前尚未发布到 PyPI。请从可信的 GitHub 仓库克隆并安装：

```console
git clone https://github.com/wanhaoli376-lab/SafeInstall.git
cd SafeInstall
python -m pip install -e .
```

开发环境：

```console
python -m pip install -e ".[dev]"
```

可选 AI 功能使用独立依赖组：

```console
python -m pip install -e ".[ai]"
```

## 快速开始

```console
safeinstall --help
safeinstall scan ./unknown-project
safeinstall scan ./download.zip
safeinstall scan https://github.com/OWNER/REPOSITORY
safeinstall scan ./unknown-project --format json
safeinstall scan ./unknown-project --format markdown
```

这些命令都不会运行目标代码。扫描公开 GitHub 仓库时，SafeInstall 会把仓库浅克隆到临时目录，禁用 Git Hook 和 Git LFS Smudge，在限制范围内完成扫描后清理临时内容。

### 报告示例

```text
SafeInstall Report
Target: example/project
Overall Risk: HIGH

这个软件可能会：
[!] 在你的电脑上运行系统命令
[!] 读取环境变量
[!] 向外发送网络请求

主要原因：
1. 程序读取环境数据，并可能把数据发送到未知地址。
2. installer.py:18 存在启用 Shell 解释的子进程调用。

建议：
运行前先检查安装流程和网络目标地址。

本报告仅基于静态分析，以上发现不能证明项目具有恶意意图。
```

仓库内提供了两个可直接扫描的示例：

```console
safeinstall scan ./examples/safe-project
safeinstall scan ./examples/risky-project
```

`risky-project` 是惰性的安全测试样例，只包含固定的无害命令、保留域名、注释和测试字符串，不含破坏性命令或可工作的恶意载荷。

## 支持范围

| 状态 | 目标与分析能力 |
|---|---|
| 已支持 | 本地文件/目录、ZIP、TAR/TAR.GZ、公开 GitHub 仓库 |
| 已支持 | Python、Shell、PowerShell、Batch、JavaScript/Node.js |
| 已支持 | Python/npm Manifest、Lockfile、安装脚本、Dockerfile、GitHub Actions |
| 已支持 | Skill、Plugin Manifest、MCP 配置/Server、Prompt 类 Markdown |
| 实验性 | 外部 YAML 规则、可信的进程内 Scanner Plugin、可选 AI 摘要 |
| 计划中 | `.exe`、`.msi`、`.dmg`、`.pkg` 深度分析，以及 Go、Rust、APK、Office Macro |
| 计划中 | 隔离执行沙箱和图形界面；v0.1 不会运行目标代码，也不提供 GUI |

不支持或无法识别的内容可能会被跳过。报告没有发现风险，只代表在当前支持范围和资源限制内没有命中规则，并不能证明目标安全。

## 可选 AI 分析

```console
safeinstall scan ./project --ai
```

AI 模式只从进程环境读取 `OPENAI_API_KEY`，不会把 Key 写入示例配置、日志或报告。SafeInstall 会先完成本地扫描，再选取有限数量的 Finding 和 Prompt 文件片段，经过脱敏后发送给 OpenAI API。目标内容位于固定 Prompt 的用户数据部分，并始终被当作不可信数据，而不是系统指令。

如果代码不允许离开当前环境，请不要使用 `--ai`。AI 输出只用于解释，不能降低本地计算出的风险等级，也不是任何安全边界。更多信息见 [OpenAI API 维护说明](docs/openai-api-maintenance.md)和[安全模型](docs/security-model.md)。

## 规则与插件

声明式规则使用严格 Schema，包括 ID、名称、描述、严重程度、类别、语言、Pattern、解释、建议和能力。未知字段、重复 ID、不安全 YAML Tag、超限规则文件都会被拒绝。具体格式见[规则开发文档](docs/rule-development.md)。

Scanner Plugin 是受信任的 Python 代码，必须由调用方显式注册。SafeInstall 不会因为扫描目标中出现了插件代码就自动导入它。v0.1 不提供在线插件商店。具体边界见[插件开发文档](docs/plugin-development.md)。

## 开发

```console
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

安全测试覆盖 Archive Traversal、Zip Slip、Symlink Escape、Secret 脱敏、恶意文件名、Git URL 注入和 AI Prompt 隔离。

## 路线图

- **v0.1 alpha：** CLI、安全加载器、核心语言扫描、Secret、报告和示例
- **v0.2：** 更深入的 Node.js/PowerShell 上下文、Lockfile 和 GitHub Actions 分析
- **v0.3：** 更完整的 Skill/Plugin/MCP 语义，以及可选 AI 行为链复核
- **v0.4：** 文档化 Plugin SDK 和更丰富的社区规则包
- **v1.0：** 稳定的 Rule/Plugin API 与正式 CI 集成

当前 v0.1 代码已经提前实现了部分后续能力，但在对应里程碑完成之前，这些 API 仍视为实验性功能。

## 贡献与安全报告

欢迎贡献 Scanner、Rule、测试、文档、AI 安全检查和 MCP 分析。修改 Loader、Plugin 执行、AI 集成或 GitHub Workflow 之前，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

如果发现 SafeInstall 自身的安全漏洞，请不要公开创建 Issue，按照 [SECURITY.md](SECURITY.md) 的方式私下报告。参与项目即表示同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

项目使用 [MIT License](LICENSE)。
