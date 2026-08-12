"""Simplified Chinese desktop strings."""

STRINGS = {
    "app.title": "SafeInstall",
    "app.tagline": "运行之前，先看懂它。",
    "home.drop_title": "拖入文件、压缩包或文件夹",
    "home.drop_subtitle": "也可以点击下方按钮选择本地目标",
    "home.choose_file": "选择文件",
    "home.choose_folder": "选择文件夹",
    "home.github_label": "GitHub 仓库地址",
    "home.github_placeholder": "https://github.com/owner/repository",
    "home.github_notice": (
        "扫描 GitHub 仓库需要网络连接。SafeInstall 会把源代码下载到临时目录进行静态分析，"
        "不会运行其中的程序。"
    ),
    "home.scan": "开始安全检查",
    "home.local_first": "本地优先",
    "home.static": "静态分析",
    "home.no_account": "无需账号",
    "home.no_key": "无需 API Key",
    "home.file_filter": (
        "支持的目标 (*.py *.js *.jsx *.ts *.tsx *.sh *.bash *.zsh *.ps1 *.bat *.cmd "
        "*.zip *.tar *.gz *.md *.json *.toml *.yaml *.yml *.txt);;所有文件 (*)"
    ),
    "selection.ready": "准备扫描",
    "selection.name": "名称：",
    "selection.type": "类型：",
    "selection.location": "位置：",
    "selection.unsupported_binary": (
        "当前版本暂不支持深入分析可执行文件或安装包。请选择源代码项目、脚本、"
        "受支持的压缩包或 GitHub 仓库。"
    ),
    "selection.unsupported_file": "当前扫描器不支持这种文件格式。",
    "selection.invalid_github": "请输入公开 GitHub 仓库的 HTTPS 地址。",
    "selection.missing_target": "这个本地目标不存在。",
    "selection.invalid_target": "无法安全读取这个目标。",
    "target.file": "文件",
    "target.folder": "文件夹",
    "target.archive": "压缩包",
    "target.github": "GitHub 仓库",
    "target.unsupported": "不支持",
    "scanning.title": "正在分析…",
    "scanning.activity": (
        "SafeInstall 正在检查受支持的源文件、脚本、依赖和安全规则。文件发现完成后才会"
        "显示准确数量，不会伪造扫描百分比。"
    ),
    "scanning.boundary": "仅进行静态分析。SafeInstall 不会运行目标代码，也不会安装其依赖。",
    "github.confirm_title": "需要网络连接",
    "github.confirm_body": (
        "SafeInstall 会把这个公开仓库下载到临时目录进行静态分析，不会运行仓库中的程序，"
        "也不会安装依赖。是否继续？"
    ),
    "common.yes": "是",
    "common.no": "否",
    "common.back": "← 返回",
    "common.none": "无",
    "risk.low": "低风险",
    "risk.info": "信息",
    "risk.medium": "中等风险",
    "risk.high": "高风险",
    "risk.critical": "严重风险",
    "result.overall_risk": "总体风险",
    "result.may_do": "这个软件可能进行的操作",
    "result.why": "为什么需要注意",
    "result.capabilities": "软件能力",
    "result.top_findings": "主要发现",
    "result.recommendation": "建议",
    "result.capability": "能力",
    "result.observed": "是否发现",
    "result.finding": "发现",
    "result.location": "位置",
    "result.severity": "等级",
    "result.technical": "查看技术详情",
    "result.export": "导出报告",
    "result.no_findings": "未发现受支持的风险模式。",
    "result.no_high_impact_capability": "未发现受支持的高影响能力",
    "result.no_persistence": "未发现受支持的持久化模式",
    "result.no_secret_pattern": "未发现受支持的硬编码 Secret 模式",
    "result.no_workflow_permission_pattern": "未发现受支持的危险 GitHub Actions 权限模式",
    "result.stats": "扫描文件：{files}  ·  依赖：{dependencies}  ·  用时：{duration} 毫秒",
    "why.download_execute": (
        "下载内容可能在没有单独检查的情况下直接成为代码。这不证明项目具有恶意，但远端"
        "响应一旦变化，实际运行内容也可能变化。"
    ),
    "why.shell": (
        "系统命令会让软件在你的用户权限下获得较广的控制能力。这不证明项目是恶意的，"
        "但会放大程序出错或被攻陷后的影响。"
    ),
    "why.sensitive": "敏感文件和环境变量可能包含凭据或私人数据。授权前应检查数据会流向哪里。",
    "why.findings": "这些是有证据支持、但仍需结合上下文判断的风险信号，并不是恶意软件结论。",
    "why.quiet": (
        "静态分析可能看不到动态生成、加密、原生二进制或仅在运行时出现的行为。安静的报告"
        "也不能保证绝对安全。"
    ),
    "advice.low": "运行前仍应核实来源。低风险只表示未发现更强的受支持模式，不是安全保证。",
    "advice.medium": "运行前检查标出的文件和软件能力。",
    "advice.high": "除非你信任来源并已检查标出的高影响文件和安装步骤，否则不建议运行。",
    "advice.critical": "在关键行为被理解并由可信人员复核之前，不要运行这个目标。",
    "capability.filesystem_read": "读取文件",
    "capability.filesystem_write": "写入或修改文件",
    "capability.file_delete": "删除文件或目录",
    "capability.code_execution": "执行动态生成的代码",
    "capability.shell_execution": "执行系统命令",
    "capability.network_access": "访问网络",
    "capability.environment_read": "读取环境变量",
    "capability.git_operations": "执行 Git 操作",
    "capability.privilege_escalation": "请求提升权限",
    "capability.persistence": "创建启动项或持久化行为",
    "capability.download_execute": "下载并立即执行代码",
    "capability.sensitive_data_access": "访问敏感用户数据",
    "category.command_execution": "执行系统命令",
    "category.install_script": "安装脚本",
    "category.prompt_injection": "潜在 Prompt Injection 指令",
    "category.environment_access": "读取环境变量",
    "category.network_access": "对外网络请求",
    "category.network_upload": "可能向外发送数据",
    "category.supply_chain": "供应链风险",
    "category.ai_component": "AI 扩展组件",
    "category.ai_component_capability": "AI 扩展能力",
    "category.artifact_handling": "工作流 Artifact 处理",
    "category.command_injection": "外部输入可能影响系统命令",
    "category.destructive_file_operation": "破坏性文件操作",
    "category.download_and_execute": "下载后立即执行",
    "category.dynamic_code_execution": "动态代码执行",
    "category.filesystem_read": "读取文件",
    "category.filesystem_write": "写入文件",
    "category.git_operation": "Git 操作",
    "category.hidden_execution": "隐藏进程执行",
    "category.mcp_capability": "MCP Server 能力",
    "category.network_service_hint": "网络服务能力",
    "category.obfuscated_execution": "混淆的命令执行",
    "category.permission_change": "修改文件权限",
    "category.persistence": "持久化或启动项行为",
    "category.privilege_escalation": "请求提升权限",
    "category.remote_access": "访问远程系统",
    "category.remote_download": "下载远程文件",
    "category.secret_exposure": "硬编码 Secret 模式",
    "category.security_bypass": "绕过安全策略",
    "category.sensitive_data_access": "访问敏感数据",
    "category.sensitive_file": "敏感配置文件",
    "category.sensitive_filesystem_access": "访问敏感文件位置",
    "category.system_configuration": "修改系统配置",
    "category.third_party_action": "第三方 GitHub Action",
    "category.unsafe_deserialization": "不安全的反序列化能力",
    "category.workflow_permission": "GitHub Actions 权限",
    "category.workflow_privilege": "高权限 GitHub Actions 触发器",
    "result.ai_title": "可选 AI 解释",
    "result.ai_advisory": "仅供参考。AI 解释不能修改本地 Finding 或风险等级。",
    "result.ai_context": "已发送上下文：{findings}，{prompt_files}。",
    "result.ai_findings.one": "{count} 条脱敏 Finding",
    "result.ai_findings": "{count} 条脱敏 Finding",
    "result.ai_prompts.one": "{count} 个 Prompt 文件",
    "result.ai_prompts": "{count} 个 Prompt 文件",
    "result.ai_model": "模型：{model}",
    "technical.title": "技术详情",
    "technical.score": "风险引擎结果：{level} · 分数 {score}/100",
    "technical.omitted": "界面为避免资源占用省略了另外 {count} 条发现；请导出 JSON 查看完整报告。",
    "technical.rule": "规则 ID",
    "technical.severity": "等级",
    "technical.category": "类别",
    "technical.file": "文件",
    "technical.line": "行号",
    "technical.finding": "发现",
    "technical.basis": "判断依据",
    "technical.capabilities": "相关能力",
    "technical.fact": "发现的事实",
    "technical.assessment": "SafeInstall 的判断",
    "technical.advice": "建议",
    "technical.observed": "直接观察到的事实",
    "technical.inferred": "推测",
    "technical.evidence": "证据",
    "export.title": "导出 SafeInstall 报告",
    "export.markdown_filter": "Markdown 报告 (*.md)",
    "export.json_filter": "JSON 报告 (*.json)",
    "export.overwrite_title": "替换现有报告？",
    "export.overwrite_body": "这个文件已经存在。是否用当前报告替换它？",
    "export.failed_title": "无法导出报告",
    "export.failed_body": "SafeInstall 无法写入所选报告文件。",
    "export.success_title": "报告已导出",
    "export.success_body": "脱敏报告已保存到：\n{path}",
    "settings.title": "设置",
    "settings.language": "语言",
    "settings.ai_heading": "AI 分析",
    "settings.ai_checkbox": "启用可选 AI 解释",
    "settings.ai_status.off": "AI 分析已关闭，所有核心本地静态扫描功能仍然可用。",
    "settings.ai_status.missing_key": (
        "没有检测到 OpenAI API Key。AI 分析是可选功能，本地静态扫描仍可正常使用。"
        "如需主动开启，请在 SafeInstall 外设置 OPENAI_API_KEY 环境变量。"
    ),
    "settings.ai_status.missing_sdk": (
        "AI 支持尚未安装。请安装可选 AI 依赖后再启用；本地静态扫描仍可正常使用。"
    ),
    "settings.ai_status.available": "你启动扫描时会启用 AI 解释；本地规则仍会先完成分析。",
    "settings.local_heading": "本地扫描",
    "settings.local_privacy": (
        "SafeInstall 默认在这台电脑上分析本地目标。核心扫描不需要账号、遥测或 API Key。"
    ),
    "settings.ai_privacy": (
        "只有你明确启用 AI 分析后，经过筛选和脱敏的 Finding 上下文或有限 Prompt 片段才可能"
        "发送至 OpenAI API。SafeInstall 不会保存你的 API Key。"
    ),
    "about.version": "版本",
    "about.license": "许可证",
    "about.license_value": "MIT 许可证",
    "about.feedback": "问题反馈",
    "error.github.title": "无法读取该 GitHub 仓库",
    "error.github.message": (
        "仓库可能不存在或不是公开仓库，Git 可能不可用，或当前网络无法访问 GitHub。"
        "SafeInstall 没有运行仓库中的代码。"
    ),
    "error.archive.title": "无法读取该压缩包",
    "error.archive.message": (
        "文件可能已损坏、包含不受支持的结构，或超过安全解压限制。SafeInstall 没有把内容"
        "解压到临时工作区之外。"
    ),
    "error.limit.title": "该项目过大",
    "error.limit.message": (
        "项目超过了当前 SafeInstall 的扫描限制。这些限制用于防止不可信文件过度占用电脑资源。"
    ),
    "error.input.title": "无法读取这个目标",
    "error.input.message": (
        "无法安全读取该路径或文件。请确认目标仍存在，并且是受支持的普通文件、压缩包或文件夹。"
    ),
    "error.ai.title": "可选 AI 分析不可用",
    "error.ai.message": "可选 AI 解释未能运行。关闭 AI 后，所有本地静态扫描功能仍可继续使用。",
    "error.generic.title": "无法完成扫描",
    "error.generic.message": (
        "SafeInstall 已安全停止，没有运行目标代码。你可以查看下方技术详情，或尝试其他目标。"
    ),
    "error.details": "查看技术详情",
    "error.back": "返回主页",
    "nav.home": "主页",
    "nav.settings": "设置",
    "nav.about": "关于",
}
