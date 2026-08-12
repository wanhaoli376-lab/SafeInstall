"""Detection of likely embedded credentials with immediate evidence redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass

from safeinstall.models import Evidence, Finding, Severity, SourceFile
from safeinstall.redaction import redact_text

MAX_FINDINGS_PER_FILE = 1_000


@dataclass(frozen=True)
class _SecretPattern:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity


_PATTERNS = (
    _SecretPattern(
        "SI-SEC-001",
        "Possible OpenAI API key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
        Severity.HIGH,
    ),
    _SecretPattern(
        "SI-SEC-002",
        "Possible GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        Severity.HIGH,
    ),
    _SecretPattern(
        "SI-SEC-003",
        "Possible AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        Severity.HIGH,
    ),
    _SecretPattern(
        "SI-SEC-004",
        "Private key material",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    _SecretPattern(
        "SI-SEC-005",
        "Possible bearer token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        Severity.HIGH,
    ),
    _SecretPattern(
        "SI-SEC-006",
        "Password-like assignment",
        re.compile(
            r"(?P<quote>['\"]?)\b(?=[A-Za-z_][A-Za-z0-9_]*\b)"
            r"(?=[A-Za-z0-9_]*(?:password|passwd|pwd|token|secret|api_key|access_key))"
            r"[A-Za-z_][A-Za-z0-9_]*\b(?P=quote)\s*[:=]",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
    ),
)


class SecretScanner:
    """Find credential-shaped text but never return the complete matched value."""

    def supports(self, source: SourceFile) -> bool:
        return True

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        filename = source.path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if filename == ".env" or filename.startswith(".env."):
            findings.append(
                Finding(
                    rule_id="SI-SEC-007",
                    name="Environment file present",
                    description="An environment file may contain runtime credentials or settings.",
                    severity=Severity.MEDIUM,
                    category="sensitive_file",
                    language=source.language,
                    explanation=(
                        "Environment files commonly hold secrets. File presence does not mean the "
                        "contents are exposed, so SafeInstall does not include those contents here."
                    ),
                    recommendation=(
                        "Confirm the file is excluded from version control and contains no live "
                        "credentials before sharing the project."
                    ),
                    evidence=(Evidence(path=source.path),),
                )
            )
        for line_number, line in enumerate(source.content.splitlines(), start=1):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            for secret_pattern in _PATTERNS:
                if secret_pattern.pattern.search(line) is None:
                    continue
                findings.append(_finding(secret_pattern, source, line_number, line))
                break
        return tuple(findings)


def _finding(
    secret_pattern: _SecretPattern,
    source: SourceFile,
    line_number: int,
    line: str,
) -> Finding:
    return Finding(
        rule_id=secret_pattern.rule_id,
        name=secret_pattern.name,
        description="A value in this file resembles a credential or secret.",
        severity=secret_pattern.severity,
        category="secret_exposure",
        language=source.language,
        explanation=(
            "If this is a real credential, anyone who can read the file may be able to use it. "
            "SafeInstall has removed the complete value from this report."
        ),
        recommendation=(
            "Revoke exposed credentials, remove them from version history, and load secrets from "
            "a protected environment or secret manager."
        ),
        evidence=(
            Evidence(
                path=source.path,
                line=line_number,
                snippet=redact_text(line.strip())[:500],
            ),
        ),
    )
