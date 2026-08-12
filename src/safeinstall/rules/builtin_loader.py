"""Read built-in rule resources through the same safe schema as community rules."""

from __future__ import annotations

from functools import cache
from importlib.resources import files

from safeinstall.rules.loader import load_rule_text
from safeinstall.rules.models import RuleDefinition


@cache
def load_builtin_rules(language: str) -> tuple[RuleDefinition, ...]:
    resource = files("safeinstall.rules.builtin").joinpath(f"{language}.yml")
    text = resource.read_text(encoding="utf-8")
    return load_rule_text(text, source=f"builtin:{language}")
