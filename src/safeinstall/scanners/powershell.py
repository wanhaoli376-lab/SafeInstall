"""Declarative scanner for PowerShell scripts."""

from __future__ import annotations

from safeinstall.models import Evidence, Finding, SourceFile
from safeinstall.redaction import redact_text
from safeinstall.rules.builtin_loader import load_builtin_rules
from safeinstall.rules.engine import RuleEngine
from safeinstall.rules.registry import RuleRegistry

_RULE_ORDER = {
    "SI-PS-001": 1,
    "SI-PS-002": 2,
    "SI-PS-003": 3,
    "SI-PS-004": 4,
    "SI-PS-005": 5,
    "SI-PS-006": 6,
    "SI-PS-007": 7,
}


class PowerShellScanner:
    """Inspect PowerShell as text without invoking the PowerShell parser or runtime."""

    def __init__(self) -> None:
        self._engine = RuleEngine(RuleRegistry(load_builtin_rules("powershell")))

    def supports(self, source: SourceFile) -> bool:
        return source.language == "powershell"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        masked = _mask_powershell_comments_and_strings(source.content)
        findings = list(self._engine.scan_text(masked, path=source.path, language="powershell"))
        argument_text = _mask_powershell_comments(source.content)
        argument_findings = self._engine.scan_text(
            argument_text, path=source.path, language="powershell"
        )
        existing = {(finding.rule_id, finding.evidence[0].line) for finding in findings}
        for finding in argument_findings:
            key = (finding.rule_id, finding.evidence[0].line)
            if finding.rule_id in {"SI-PS-005", "SI-PS-006", "SI-PS-007"} and key not in existing:
                findings.append(finding)
                existing.add(key)
        restored = tuple(_restore_evidence(source, finding) for finding in findings)
        return tuple(
            sorted(
                restored,
                key=lambda finding: (
                    finding.evidence[0].line or 0,
                    _RULE_ORDER.get(finding.rule_id, 999),
                ),
            )
        )


def _restore_evidence(source: SourceFile, finding: Finding) -> Finding:
    evidence = finding.evidence[0]
    line = evidence.line or 1
    return finding.model_copy(
        update={
            "evidence": (
                Evidence(
                    path=evidence.path,
                    line=line,
                    snippet=redact_text(source.line(line).strip())[:500],
                ),
            )
        }
    )


def _mask_powershell_comments_and_strings(text: str) -> str:
    output = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "<" and next_char == "#":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == "#":
                output[index] = " "
                state = "line_comment"
            elif char == "'":
                output[index] = " "
                state = "single"
            elif char == '"':
                output[index] = " "
                state = "double"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "#" and next_char == ">":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        elif state == "single":
            output[index] = " " if char != "\n" else char
            if char == "'":
                if next_char == "'":
                    output[index + 1] = " "
                    index += 2
                    continue
                state = "code"
        elif state == "double":
            output[index] = " " if char != "\n" else char
            if char == "`" and next_char:
                if next_char != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            if char == '"':
                state = "code"
        index += 1
    return "".join(output)


def _mask_powershell_comments(text: str) -> str:
    """Mask comments but retain quoted process arguments for policy/visibility flags."""

    output = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "<" and next_char == "#":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == "#":
                output[index] = " "
                state = "line_comment"
            elif char == "'":
                state = "single"
            elif char == '"':
                state = "double"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "#" and next_char == ">":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        elif state == "single":
            if char == "'":
                if next_char == "'":
                    index += 2
                    continue
                state = "code"
        elif state == "double":
            if char == "`" and next_char:
                index += 2
                continue
            if char == '"':
                state = "code"
        index += 1
    return "".join(output)
