"""Execution engine for validated, data-only pattern rules."""

from __future__ import annotations

import re

from safeinstall.models import Evidence, Finding
from safeinstall.redaction import redact_text
from safeinstall.rules.registry import RuleRegistry

MAX_SCANNED_LINE_CHARS = 20_000
MAX_FINDINGS_PER_RULE = 100


class RuleEngine:
    """Apply registered rules and return bounded, source-backed findings."""

    def __init__(self, registry: RuleRegistry) -> None:
        self._registry = registry
        self._patterns = {rule.id: re.compile(rule.pattern) for rule in registry.all()}

    def scan_text(self, content: str, *, path: str, language: str) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule in self._registry.for_language(language):
            pattern = self._patterns[rule.id]
            emitted = 0
            for line_number, original_line in enumerate(lines, start=1):
                line = original_line[:MAX_SCANNED_LINE_CHARS]
                if pattern.search(line) is None:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        name=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        category=rule.category,
                        language=rule.language,
                        explanation=rule.explanation,
                        recommendation=rule.recommendation,
                        capabilities=rule.capabilities,
                        evidence=(
                            Evidence(
                                path=path,
                                line=line_number,
                                snippet=redact_text(line.strip())[:500],
                            ),
                        ),
                    )
                )
                emitted += 1
                if emitted >= MAX_FINDINGS_PER_RULE:
                    break

        return tuple(findings)
