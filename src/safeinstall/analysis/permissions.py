"""Cross-language inference for references to sensitive filesystem locations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from safeinstall.models import (
    Capability,
    Evidence,
    Finding,
    FindingConfidence,
    Severity,
    SourceFile,
)
from safeinstall.redaction import redact_text


@dataclass(frozen=True, slots=True)
class _SensitivePath:
    path_class: str
    pattern: re.Pattern[str]
    severity: Severity


_USER_ROOT = r"(?:~[\\/]|\$HOME[\\/]|\$\{HOME\}[\\/]|%USERPROFILE%[\\/])?"
_SENSITIVE_PATHS = (
    _SensitivePath(
        "ssh",
        re.compile(rf"(?i)(?<![\w]){_USER_ROOT}\.ssh(?:[\\/]|(?![\w]))"),
        Severity.MEDIUM,
    ),
    _SensitivePath(
        "aws",
        re.compile(rf"(?i)(?<![\w]){_USER_ROOT}\.aws(?:[\\/]|(?![\w]))"),
        Severity.MEDIUM,
    ),
    _SensitivePath(
        "browser",
        re.compile(
            r"(?i)(?:Google[\\/]Chrome[\\/]User Data|Mozilla[\\/]Firefox|"
            r"Firefox[\\/]Profiles|Library[\\/]Application Support[\\/]Google[\\/]Chrome)"
        ),
        Severity.MEDIUM,
    ),
    _SensitivePath(
        "system",
        re.compile(r"(?i)(?:^|[\s'\"(])(?:/etc/|(?:[A-Z]:)?[\\/]Windows[\\/]System32[\\/])"),
        Severity.MEDIUM,
    ),
    _SensitivePath(
        "environment_file",
        re.compile(r"(?i)(?<![\w])\.env(?:\.[A-Za-z0-9_.-]+)?(?![\w])"),
        Severity.MEDIUM,
    ),
    _SensitivePath(
        "user_config",
        re.compile(rf"(?i)(?<![\w]){_USER_ROOT}\.config(?:[\\/]|(?![\w]))"),
        Severity.LOW,
    ),
    _SensitivePath(
        "home",
        re.compile(r"(?i)(?:~[\\/]|\$HOME(?:[\\/]|\b)|\$\{HOME\}[\\/]|%USERPROFILE%[\\/])"),
        Severity.LOW,
    ),
)

_CODE_LANGUAGES = {"batch", "github-actions", "javascript", "powershell", "shell"}
_AI_COMPONENT_NAMES = {"mcp.json", "plugin.json", "skill.md"}
MAX_FINDINGS_PER_FILE = 1_000


class SensitivePathScanner:
    """Report path references as bounded inference, not proof that a read occurs."""

    def supports(self, source: SourceFile) -> bool:
        if source.language in _CODE_LANGUAGES:
            return True
        path = PurePosixPath(source.path.replace("\\", "/"))
        parts = {part.casefold() for part in path.parts[:-1]}
        return path.name.casefold() in _AI_COMPONENT_NAMES or bool(
            parts & {"plugins", "prompts", "skills"}
        )

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        if not self.supports(source):
            return ()
        findings: list[Finding] = []
        for line_number, line in enumerate(source.content.splitlines(), start=1):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            if _is_comment_only(line, source.language):
                continue
            for sensitive in _SENSITIVE_PATHS:
                if sensitive.pattern.search(line) is None:
                    continue
                findings.append(_finding(source, line_number, line, sensitive))
                break
        return tuple(findings)


def _is_comment_only(line: str, language: str) -> bool:
    stripped = line.lstrip()
    if language in {"powershell", "shell"}:
        return stripped.startswith("#")
    if language == "javascript":
        return stripped.startswith(("//", "/*", "*"))
    if language == "batch":
        lowered = stripped.casefold()
        return lowered.startswith("::") or lowered.startswith("rem ")
    return False


def _finding(
    source: SourceFile,
    line_number: int,
    line: str,
    sensitive: _SensitivePath,
) -> Finding:
    return Finding(
        rule_id="SI-FS-002",
        name="Sensitive filesystem path reference",
        description=(f"The source references a {sensitive.path_class.replace('_', ' ')} location."),
        severity=sensitive.severity,
        category="sensitive_filesystem_access",
        language=source.language,
        explanation=(
            "This location may contain credentials, private user data, or system configuration. "
            "A text reference alone does not prove the program reads or misuses it."
        ),
        recommendation=(
            "Review the surrounding operation, why this path is needed, and where any data goes."
        ),
        evidence=(
            Evidence(
                path=source.path,
                line=line_number,
                snippet=redact_text(line.strip())[:500],
            ),
        ),
        capabilities=(Capability.FILESYSTEM_READ, Capability.SENSITIVE_DATA_ACCESS),
        confidence=FindingConfidence.INFERRED,
        metadata={"path_class": sensitive.path_class},
    )
