"""In-memory registry for validated declarative rules."""

from __future__ import annotations

from collections.abc import Iterable

from safeinstall.exceptions import RuleLoadError
from safeinstall.rules.models import RuleDefinition


class RuleRegistry:
    """Index unique rules while keeping registration details private."""

    def __init__(self, rules: Iterable[RuleDefinition] = ()) -> None:
        self._rules_by_id: dict[str, RuleDefinition] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: RuleDefinition) -> None:
        if rule.id in self._rules_by_id:
            raise RuleLoadError(f"Duplicate rule id: {rule.id}")
        self._rules_by_id[rule.id] = rule

    def all(self) -> tuple[RuleDefinition, ...]:
        return tuple(self._rules_by_id.values())

    def for_language(self, language: str) -> tuple[RuleDefinition, ...]:
        return tuple(rule for rule in self._rules_by_id.values() if rule.language == language)
