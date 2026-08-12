"""Context-limited prompt-injection indicators for AI extension files."""

from __future__ import annotations

from pathlib import PurePosixPath

from safeinstall.models import Finding, FindingConfidence, SourceFile
from safeinstall.rules.builtin_loader import load_builtin_rules
from safeinstall.rules.engine import RuleEngine
from safeinstall.rules.registry import RuleRegistry

_PROMPT_FILENAMES = {
    "agent.md",
    "instructions.md",
    "mcp.json",
    "plugin.json",
    "skill.md",
    "system.md",
    "system_prompt.md",
}


class PromptInjectionScanner:
    """Treat prompt-like target text as evidence, never as control instructions."""

    def __init__(self) -> None:
        self._engine = RuleEngine(RuleRegistry(load_builtin_rules("prompts")))

    def supports(self, source: SourceFile) -> bool:
        path = PurePosixPath(source.path.replace("\\", "/"))
        name = path.name.casefold()
        parts = {part.casefold() for part in path.parts[:-1]}
        return name in _PROMPT_FILENAMES or "prompt" in name or bool(parts & {"prompts", "skills"})

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        if not self.supports(source):
            return ()
        findings = self._engine.scan_text(
            source.content,
            path=source.path,
            language="prompt",
        )
        inferred = tuple(
            finding.model_copy(update={"confidence": FindingConfidence.INFERRED})
            for finding in findings
        )
        return tuple(
            sorted(
                inferred,
                key=lambda finding: (finding.evidence[0].line or 0, finding.rule_id),
            )
        )
