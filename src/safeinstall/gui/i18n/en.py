"""English desktop strings."""

STRINGS = {
    "app.title": "SafeInstall",
    "app.tagline": "Understand software before you run it.",
    "home.drop_title": "Drop a file, archive, or folder here",
    "home.drop_subtitle": "or choose a local target below",
    "home.choose_file": "Choose File",
    "home.choose_folder": "Choose Folder",
    "home.github_label": "GitHub repository URL",
    "home.github_placeholder": "https://github.com/owner/repository",
    "home.github_notice": (
        "GitHub scans require a network connection. SafeInstall downloads source code to a "
        "temporary folder for static analysis and does not run it."
    ),
    "home.scan": "Start Safety Check",
    "home.local_first": "Local-first",
    "home.static": "Static analysis",
    "home.no_account": "No account required",
    "home.no_key": "No API key required",
    "home.file_filter": (
        "Supported targets (*.py *.js *.jsx *.ts *.tsx *.sh *.bash *.zsh *.ps1 *.bat "
        "*.cmd *.zip *.tar *.gz *.md *.json *.toml *.yaml *.yml *.txt);;All files (*)"
    ),
    "selection.ready": "Ready to scan",
    "selection.name": "Name:",
    "selection.type": "Type:",
    "selection.location": "Location:",
    "selection.unsupported_binary": (
        "This version does not deeply analyze executable or installer binaries. Choose a "
        "source project, script, supported archive, or GitHub repository instead."
    ),
    "selection.unsupported_file": "This file format is not supported by the current scanners.",
    "selection.invalid_github": "Enter a public HTTPS GitHub repository URL.",
    "selection.missing_target": "This local target does not exist.",
    "selection.invalid_target": "This target cannot be read safely.",
    "target.file": "File",
    "target.folder": "Folder",
    "target.archive": "Archive",
    "target.github": "GitHub repository",
    "target.unsupported": "Unsupported",
    "scanning.title": "Analyzing…",
    "scanning.activity": (
        "SafeInstall is checking supported source files, scripts, dependencies, and security "
        "rules. Exact file counts are shown when discovery finishes."
    ),
    "scanning.boundary": (
        "Static analysis only. SafeInstall does not run target code or install its dependencies."
    ),
    "github.confirm_title": "Network connection required",
    "github.confirm_body": (
        "SafeInstall will download this public repository into a temporary folder for static "
        "analysis. It will not run repository programs or install dependencies. Continue?"
    ),
    "common.yes": "YES",
    "common.no": "NO",
    "common.back": "← Back",
    "common.none": "None",
    "risk.low": "Low risk",
    "risk.info": "Information",
    "risk.medium": "Medium risk",
    "risk.high": "High risk",
    "risk.critical": "Critical risk",
    "result.overall_risk": "Overall risk",
    "result.may_do": "What this software may do",
    "result.why": "Why this matters",
    "result.capabilities": "Software capabilities",
    "result.top_findings": "Top findings",
    "result.recommendation": "Recommendation",
    "result.capability": "Capability",
    "result.observed": "Observed",
    "result.finding": "Finding",
    "result.location": "Location",
    "result.severity": "Severity",
    "result.technical": "Technical Details",
    "result.export": "Export Report",
    "result.no_findings": "No supported risk pattern was found.",
    "result.no_high_impact_capability": "No supported high-impact capability was observed",
    "result.no_persistence": "No supported persistence pattern was found",
    "result.no_secret_pattern": "No supported hard-coded secret pattern was found",
    "result.no_workflow_permission_pattern": (
        "No supported dangerous GitHub Actions permission pattern was found"
    ),
    "result.stats": (
        "Files scanned: {files}  ·  Dependencies: {dependencies}  ·  Scan time: {duration} ms"
    ),
    "why.download_execute": (
        "Downloaded content can become code without a separate inspection step. This does not "
        "prove malicious intent, but a changed remote response could change what runs."
    ),
    "why.shell": (
        "System commands give software broad control under your user account. This does not "
        "prove the project is malicious, but it increases the impact of a mistake or compromise."
    ),
    "why.sensitive": (
        "Sensitive files and environment values may contain credentials or private data. Review "
        "where that data goes before granting access."
    ),
    "why.findings": (
        "These are evidence-backed risk signals that need context. They are not a malware verdict."
    ),
    "why.quiet": (
        "Static analysis can miss generated, encrypted, native, or runtime-only behavior. A quiet "
        "report cannot guarantee safety."
    ),
    "advice.low": (
        "Verify the source before running it. A low result means no stronger supported pattern was "
        "found; it is not a guarantee of safety."
    ),
    "advice.medium": "Review the highlighted files and capabilities before running this target.",
    "advice.high": (
        "Do not run this target unless you trust its source and have reviewed the highlighted "
        "high-impact files and installation steps."
    ),
    "advice.critical": (
        "Do not run this target until the critical behavior is understood and reviewed by someone "
        "you trust."
    ),
    "capability.filesystem_read": "Read files",
    "capability.filesystem_write": "Write or modify files",
    "capability.file_delete": "Delete files or directories",
    "capability.code_execution": "Run dynamically generated code",
    "capability.shell_execution": "Run system commands",
    "capability.network_access": "Access the network",
    "capability.environment_read": "Read environment variables",
    "capability.git_operations": "Use Git operations",
    "capability.privilege_escalation": "Request elevated privileges",
    "capability.persistence": "Create startup or persistent behavior",
    "capability.download_execute": "Download and immediately execute code",
    "capability.sensitive_data_access": "Access sensitive user data",
    "category.command_execution": "System command execution",
    "category.install_script": "Installation script",
    "category.prompt_injection": "Potential prompt-injection instruction",
    "category.environment_access": "Environment variable access",
    "category.network_access": "Outbound network request",
    "category.network_upload": "Potential outbound data upload",
    "category.supply_chain": "Supply-chain risk",
    "category.ai_component": "AI extension component",
    "category.ai_component_capability": "AI extension capability",
    "category.artifact_handling": "Workflow artifact handling",
    "category.command_injection": "Input may influence a command",
    "category.destructive_file_operation": "Destructive file operation",
    "category.download_and_execute": "Download and immediate execution",
    "category.dynamic_code_execution": "Dynamic code execution",
    "category.filesystem_read": "File read access",
    "category.filesystem_write": "File write access",
    "category.git_operation": "Git operation",
    "category.hidden_execution": "Hidden process execution",
    "category.mcp_capability": "MCP server capability",
    "category.network_service_hint": "Network service capability",
    "category.obfuscated_execution": "Obfuscated command execution",
    "category.permission_change": "File permission change",
    "category.persistence": "Persistent or startup behavior",
    "category.privilege_escalation": "Elevated privilege request",
    "category.remote_access": "Remote system access",
    "category.remote_download": "Remote file download",
    "category.secret_exposure": "Hard-coded secret pattern",
    "category.security_bypass": "Security policy bypass",
    "category.sensitive_data_access": "Sensitive data access",
    "category.sensitive_file": "Sensitive configuration file",
    "category.sensitive_filesystem_access": "Sensitive filesystem access",
    "category.system_configuration": "System configuration change",
    "category.third_party_action": "Third-party GitHub Action",
    "category.unsafe_deserialization": "Unsafe deserialization capability",
    "category.workflow_permission": "GitHub Actions permission",
    "category.workflow_privilege": "Privileged GitHub Actions trigger",
    "result.ai_title": "Optional AI explanation",
    "result.ai_advisory": (
        "Advisory only. This explanation cannot change the local findings or risk level."
    ),
    "result.ai_context": "Sent context: {findings} and {prompt_files}.",
    "result.ai_findings.one": "{count} redacted finding",
    "result.ai_findings": "{count} redacted findings",
    "result.ai_prompts.one": "{count} prompt file",
    "result.ai_prompts": "{count} prompt files",
    "result.ai_model": "Model: {model}",
    "technical.title": "Technical Details",
    "technical.score": "Engine result: {level} · score {score}/100",
    "technical.omitted": (
        "{count} additional findings are omitted from this bounded UI view. Export JSON to review "
        "the complete report."
    ),
    "technical.rule": "Rule ID",
    "technical.severity": "Severity",
    "technical.category": "Category",
    "technical.file": "File",
    "technical.line": "Line",
    "technical.finding": "Finding",
    "technical.basis": "Basis",
    "technical.capabilities": "Capabilities",
    "technical.fact": "Observed evidence",
    "technical.assessment": "SafeInstall's assessment",
    "technical.advice": "Advice",
    "technical.observed": "Observed fact",
    "technical.inferred": "Inference",
    "technical.evidence": "Evidence",
    "export.title": "Export SafeInstall report",
    "export.markdown_filter": "Markdown report (*.md)",
    "export.json_filter": "JSON report (*.json)",
    "export.overwrite_title": "Replace existing report?",
    "export.overwrite_body": "This file already exists. Replace it with the current report?",
    "export.failed_title": "Could not export report",
    "export.failed_body": "SafeInstall could not write the selected report file.",
    "export.success_title": "Report exported",
    "export.success_body": "The redacted report was saved to:\n{path}",
    "settings.title": "Settings",
    "settings.language": "Language",
    "settings.ai_heading": "AI Analysis",
    "settings.ai_checkbox": "Enable optional AI explanation",
    "settings.ai_status.off": (
        "AI analysis is off. All core local static scanning features remain available."
    ),
    "settings.ai_status.missing_key": (
        "No OpenAI API key was detected. AI analysis is optional; local static scanning still "
        "works normally. Set OPENAI_API_KEY outside SafeInstall if you want to opt in."
    ),
    "settings.ai_status.missing_sdk": (
        "AI support is not installed. Install the optional AI package to enable this feature. "
        "Local static scanning still works normally."
    ),
    "settings.ai_status.available": (
        "AI explanation is enabled for scans you start. Local findings are produced first."
    ),
    "settings.local_heading": "Local Scan",
    "settings.local_privacy": (
        "SafeInstall analyzes local targets on this computer. It does not require an account, "
        "telemetry, or an API key for core scanning."
    ),
    "settings.ai_privacy": (
        "If you explicitly enable AI analysis, selected and redacted finding context or bounded "
        "prompt excerpts may be sent to the OpenAI API. SafeInstall does not store your API key."
    ),
    "about.version": "Version",
    "about.license": "License",
    "about.license_value": "MIT License",
    "about.feedback": "Feedback",
    "error.github.title": "Could not read this GitHub repository",
    "error.github.message": (
        "The repository may not exist or be public, Git may be unavailable, or this computer may "
        "not currently be able to reach GitHub. No repository code was run."
    ),
    "error.archive.title": "Could not read this archive",
    "error.archive.message": (
        "The archive may be damaged, use an unsupported structure, or violate a safe extraction "
        "limit. SafeInstall did not extract it outside the temporary workspace."
    ),
    "error.limit.title": "This target is too large",
    "error.limit.message": (
        "The project exceeded a current SafeInstall scan limit. The limit protects your computer "
        "from untrusted files that consume excessive resources."
    ),
    "error.input.title": "Could not read this target",
    "error.input.message": (
        "The path or file could not be read safely. Check that it still exists and is a supported "
        "regular file, archive, or folder."
    ),
    "error.ai.title": "Optional AI analysis is unavailable",
    "error.ai.message": (
        "The optional AI explanation could not run. Turn AI off to continue using every local "
        "static scanning feature."
    ),
    "error.generic.title": "The scan could not be completed",
    "error.generic.message": (
        "SafeInstall stopped safely without running target code. You can review the technical "
        "detail below or try another target."
    ),
    "error.details": "View technical details",
    "error.back": "Back to Home",
    "nav.home": "Home",
    "nav.settings": "Settings",
    "nav.about": "About",
}
