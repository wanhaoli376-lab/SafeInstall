"""Declarative rule loading and registration."""

from safeinstall.rules.models import RuleDefinition
from safeinstall.rules.registry import RuleRegistry

__all__ = ["RuleDefinition", "RuleRegistry"]
