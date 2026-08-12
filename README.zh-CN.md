# SafeInstall

[English](README.md) | [简体中文](README.zh-CN.md)

> **运行之前，先看懂它。**

SafeInstall 用于在运行陌生脚本、开源项目、AI 插件、Skill 或 MCP Server 之前，先做一遍静态安全分析。它会找出值得关注的代码模式，说明目标可能具备哪些能力，给出文件和行号证据，并告诉你下一步应该检查什么。

SafeInstall 默认在本地做静态分析：不安装目标依赖，不导入目标 Python 包，也不执行被扫描的代码。核心本地扫描不需要 OpenAI API Key、账号或网络连接。只有在 CLI 显式传入 `--ai`，或在桌面设置中主动开启时，才会启用可选 OpenAI 分析。

> [!IMPORTANT]
> SafeInstall 提供的是风险分析，不是“无恶意软件”证明。它不能替代杀毒软件、沙箱、人工代码审查，也不能替代对软件来源的判断。

![SafeInstall 桌面主页](docs/images/safeinstall-home.png)

## 下载

**SafeInstall v0.2.0-alpha.1 是面向公开测试的预发布版本，当前优先推荐 Windows x64。**

### Windows x64

前往 [v0.2.0-alpha.1 Release 页面](https://github.com/wanhaoli376-lab/SafeInstall/releases/tag/v0.2.0-alpha.1)
下载 `SafeInstall-Windows-x64.zip`，解压后双击 `SafeInstall/SafeInstall.exe`。把文件、文件夹或受支持的压缩包拖入窗口，再点击“开始安全检查”即可。

本地扫描不需要 Python、pip、Git、账号或 OpenAI API Key。当前 Alpha 二进制尚未签名，新项目也还没有足够的信誉积累，因此 Windows SmartScreen 可能提示风险。SafeInstall 不建议关闭 Microsoft Defender，也不建议永久关闭 SmartScreen。

### macOS（实验性）

Release 页面同时提供 `SafeInstall-macOS-unsigned.zip`。这个开发构建尚未签名，也没有经过 Apple Notarization，macOS Gatekeeper 可能显示警告。本次 Alpha 仍以 Windows 为优先测试平台。

可以使用 Release 中的 `SHA256SUMS.txt` 校验下载文件；`SBOM.json` 是发布元数据任务基于固定依赖生成的 Python 应用依赖 CycloneDX 清单，并不是两个平台 portable 二进制或操作系统组件的完整清单。

## 为什么需要 SafeInstall

`curl example.com/install.sh | bash` 看起来只是一行安装命令，但它隐藏了一个关键事实：程序会从网络下载内容，并立刻交给 Shell 执行。类似地，`subprocess.run(...)`、npm 的 `postinstall`，或一个能够访问文件系统的 MCP Tool，可能完全合理，同时也确实拥有较大的系统权限。

SafeInstall 会把安全报告中经常混在一起的三类信息拆开：

- **事实：** 实际看到了什么模式，位于哪个文件、哪一行。
- **推测：** 基于有限上下文推断出的能力或行为组合。
- **建议：** 下一步应该检查什么，不把“具备危险能力”直接说成“恶意软件”。

## 功能

- 扫描本地文件或目录、ZIP/TAR 压缩包、公开 GitHub 仓库
- 提供支持 English/简体中文、拖拽与后台扫描的实验性桌面界面
- 静态分析 Python、Shell、PowerShell、Batch、JavaScript/Node.js
- 检查依赖、安装脚本、Dockerfile 和 GitHub Actions 供应链风险
- 检测 Secret，并通过统一脱敏层防止报告完整打印凭据
- 识别 Skill、Plugin Manifest、MCP Server、Tool 定义和 Prompt Injection 模式
- 汇总文件读写、Shell、网络、环境变量、Git、提权和持久化等能力
- 结合上下文计算风险，例如“读取环境变量 + 向未知地址 POST”
- 输出适合普通用户的终端报告，以及稳定的 JSON 和 GitHub Markdown
- 提供严格的 YAML Rule Engine 和显式注册的 Scanner Plugin 框架
- 提供有边界、需主动开启的 OpenAI 风险解释

## 工作方式

SafeInstall 现在包含一个**实验性桌面界面**。用户可以选择或拖入文件、受支持的压缩包、文件夹，也可以粘贴公开 GitHub 仓库地址。

```text
文件 / 文件夹 / 压缩包 / GitHub URL
                    ↓
               SafeInstall
                    ↓
             风险概览 + 证据
```

本地目标只在你的电脑上分析，不需要账号、Telemetry、OpenAI 账号或 OpenAI API Key。AI 解释默认关闭。桌面界面通过 Worker Thread 调用与 CLI 相同的 `scan_target()`，不会另写扫描器，也不会削弱静态分析边界。

公开 Alpha 提供 Windows portable 构建和实验性的未签名 macOS 构建。平台状态与完整安全边界见[桌面与打包文档](docs/desktop.md)。

### 风险概览

![SafeInstall 风险概览](docs/images/safeinstall-result.png)

### 技术证据

![SafeInstall 技术详情](docs/images/safeinstall-technical-details.png)

## 开发者安装

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

从源码运行实验性桌面界面：

```console
python -m pip install -e ".[gui]"
safeinstall-gui
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

这些命令都不会运行目标代码。有 Git 时，SafeInstall 会浅克隆公开仓库，并禁用 Git Hook 和 Git LFS Smudge；没有 Git 时，它会从固定的 GitHub API/codeload 主机下载固定到 Commit 的 ZIP 快照，再交给同一套安全压缩包加载器。两种方式都只在受限临时目录中工作，扫描后清理。

GUI 的本地扫描可完全离线使用。扫描 GitHub URL 需要网络，但公开仓库不要求 Git、GitHub 账号或 API Token；仍受 GitHub 匿名 API 频率限制。

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
| 实验性 | 桌面 GUI、未签名的 Windows/macOS Alpha 构建、外部 YAML 规则、可信的进程内 Scanner Plugin、可选 AI 摘要 |
| 计划中 | `.exe`、`.msi`、`.dmg`、`.pkg` 深度分析，以及 Go、Rust、APK、Office Macro |
| 计划中 | 隔离执行沙箱、签名与 notarize 后的安装包、更新检查和二进制分析 |

不支持或无法识别的内容可能会被跳过。报告没有发现风险，只代表在当前支持范围和资源限制内没有命中规则，并不能证明目标安全。

桌面应用会直接拒绝已知不支持的安装包与二进制格式，不会误导用户说“已经分析 EXE”。架构为未来的 `BinaryScanner` 预留边界，但当前不会放置空实现。

## 可选 AI 分析

```console
safeinstall scan ./project --ai
```

AI 模式只从进程环境读取 `OPENAI_API_KEY`，不会把 Key 写入示例配置、日志或报告。SafeInstall 会先完成本地扫描，再选取有限数量的 Finding 和 Prompt 文件片段，经过脱敏后发送给 OpenAI API。目标内容位于固定 Prompt 的用户数据部分，并始终被当作不可信数据，而不是系统指令。

**SafeInstall 的核心本地安全扫描功能不需要 OpenAI API Key。** 只安装 GUI 依赖时也不会安装 OpenAI SDK。缺少 Key 或 SDK 时，桌面应用只会说明 AI 暂不可用，仍会继续完成本地扫描。

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

桌面开发与 portable 打包：

```console
python -m pip install -e ".[dev,gui,gui-test,packaging]"
python -m pytest tests/gui
python -m PyInstaller --noconfirm --clean packaging/safeinstall.spec
```

安全测试覆盖 Archive Traversal、Zip Slip、Symlink Escape、Secret 脱敏、恶意文件名、Git URL 注入和 AI Prompt 隔离。

## 路线图

- **v0.1 alpha：** CLI、安全加载器、核心语言扫描、Secret、报告和示例
- **v0.2 alpha：** 实验性桌面 GUI、拖拽、本地 Worker 扫描、双语结果、报告导出、公开 portable 构建、校验和与 CycloneDX SBOM
- **v0.3：** 更完整的 Skill/Plugin/MCP 语义，以及可选 AI 行为链复核
- **v0.4：** 文档化 Plugin SDK、更丰富的社区规则包与打包加固
- **v1.0：** 稳定的 Rule/Plugin API 与正式 CI 集成

当前 v0.2 alpha 代码已经提前实现了部分后续能力，但在对应里程碑完成之前，这些 API 仍视为实验性功能。

## 贡献与安全报告

欢迎贡献 Scanner、Rule、测试、文档、AI 安全检查和 MCP 分析。修改 Loader、Plugin 执行、AI 集成或 GitHub Workflow 之前，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

如果发现 SafeInstall 自身的安全漏洞，请不要公开创建 Issue，按照 [SECURITY.md](SECURITY.md) 的方式私下报告。参与项目即表示同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

Alpha 用户可以通过 [GitHub Issues](https://github.com/wanhaoli376-lab/SafeInstall/issues/new/choose) 提交经过脱敏的使用反馈。不要上传机密源码、凭据、私有扫描报告或未脱敏的 Secret。

项目使用 [MIT License](LICENSE)。
