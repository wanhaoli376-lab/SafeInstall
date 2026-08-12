"""Declarative scanner for POSIX shell scripts."""

from __future__ import annotations

from safeinstall.models import Finding, SourceFile
from safeinstall.rules.builtin_loader import load_builtin_rules
from safeinstall.rules.engine import RuleEngine
from safeinstall.rules.registry import RuleRegistry


class ShellScanner:
    """Detect shell capabilities without running or sourcing the script."""

    def __init__(self) -> None:
        self._engine = RuleEngine(RuleRegistry(load_builtin_rules("shell")))

    def supports(self, source: SourceFile) -> bool:
        return source.language == "shell"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        analyzable = "\n".join(
            "" if line.lstrip().startswith("#") else line for line in source.content.splitlines()
        )
        findings = self._engine.scan_text(analyzable, path=source.path, language="shell")

        combined_lines = {
            finding.evidence[0].line
            for finding in findings
            if finding.rule_id in {"SI-SH-001", "SI-SH-002"}
        }
        return tuple(
            finding
            for finding in findings
            if not (finding.rule_id == "SI-SH-006" and finding.evidence[0].line in combined_lines)
        )
