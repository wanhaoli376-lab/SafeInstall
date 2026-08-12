"""Declarative scanner for Windows batch scripts."""

from __future__ import annotations

from safeinstall.models import Evidence, Finding, SourceFile
from safeinstall.redaction import redact_text
from safeinstall.rules.builtin_loader import load_builtin_rules
from safeinstall.rules.engine import RuleEngine
from safeinstall.rules.registry import RuleRegistry


class BatchScanner:
    """Inspect batch command text without invoking cmd.exe."""

    def __init__(self) -> None:
        self._engine = RuleEngine(RuleRegistry(load_builtin_rules("batch")))

    def supports(self, source: SourceFile) -> bool:
        return source.language == "batch"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        analyzable = "\n".join(
            "" if _is_comment(line) else line for line in source.content.splitlines()
        )
        findings = self._engine.scan_text(analyzable, path=source.path, language="batch")
        restored = tuple(_restore_evidence(source, finding) for finding in findings)
        return tuple(
            sorted(
                restored,
                key=lambda finding: (finding.evidence[0].line or 0, finding.rule_id),
            )
        )


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("::") or stripped.casefold().startswith("rem ")


def _restore_evidence(source: SourceFile, finding: Finding) -> Finding:
    line = finding.evidence[0].line or 1
    return finding.model_copy(
        update={
            "evidence": (
                Evidence(
                    path=source.path,
                    line=line,
                    snippet=redact_text(source.line(line).strip())[:500],
                ),
            )
        }
    )
