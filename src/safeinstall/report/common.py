"""Plain-language labels and recommendations shared by report formats."""

from __future__ import annotations

from safeinstall.models import Capability, ScanReport, Severity

CAPABILITY_LABELS = {
    Capability.FILESYSTEM_READ: "Read files",
    Capability.FILESYSTEM_WRITE: "Write or modify files",
    Capability.FILE_DELETE: "Delete files or directories",
    Capability.CODE_EXECUTION: "Run dynamically generated code",
    Capability.SHELL_EXECUTION: "Run system commands",
    Capability.NETWORK_ACCESS: "Access the network",
    Capability.ENVIRONMENT_READ: "Read environment variables",
    Capability.GIT_OPERATIONS: "Run Git operations",
    Capability.PRIVILEGE_ESCALATION: "Request elevated privileges",
    Capability.PERSISTENCE: "Create persistent or startup behavior",
    Capability.DOWNLOAD_EXECUTE: "Download and immediately execute code",
    Capability.SENSITIVE_DATA_ACCESS: "Access sensitive user data",
}

SEVERITY_STYLE = {
    Severity.INFO: "cyan",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def recommendation_for(report: ScanReport) -> str:
    level = report.risk.level
    if level is Severity.CRITICAL:
        return (
            "Do not run this target until the critical behavior is understood, contained, and "
            "reviewed by someone you trust."
        )
    if level is Severity.HIGH:
        return (
            "Do not run this target unless you trust its source and have reviewed the high-impact "
            "files and installation steps listed below."
        )
    if level is Severity.MEDIUM:
        return (
            "Review the highlighted files and capabilities before running or installing the target."
        )
    if level is Severity.LOW:
        return (
            "The scan found limited risk indicators. Review them and verify the source before "
            "running."
        )
    return (
        "No supported risk pattern was found. This is not proof of safety; verify the source "
        "and use normal endpoint protection."
    )


def why_this_matters(report: ScanReport) -> str:
    capabilities = set(report.risk.capabilities.observed)
    if Capability.DOWNLOAD_EXECUTE in capabilities:
        return (
            "Downloaded content can become code without a separate inspection step. A changed "
            "remote response could therefore change what runs on your computer."
        )
    if Capability.SHELL_EXECUTION in capabilities:
        return (
            "System commands give software broad control under your user account. This does not "
            "prove malicious intent, but it increases the impact of a mistake or compromise."
        )
    if Capability.SENSITIVE_DATA_ACCESS in capabilities:
        return (
            "Sensitive files and environment values may contain credentials or private data. "
            "Review where that data goes before granting access."
        )
    if report.findings:
        return (
            "These findings describe capabilities and supply-chain choices that deserve context. "
            "They are risk signals, not a malware verdict."
        )
    return (
        "Static analysis can miss generated, encrypted, native, or runtime-only behavior. A quiet "
        "report therefore cannot guarantee safety."
    )


def location(path: str, line: int | None) -> str:
    return f"{path}:{line}" if line is not None else path
