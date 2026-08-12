"""Schema for community-contributed declarative rules."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from safeinstall.models import Capability, CategoryName, LanguageName, RuleId, Severity
from safeinstall.rules.regex_safety import UnsafeRegexError, validate_regex_structure


class RuleDefinition(BaseModel):
    """A validated, data-only regular-expression scanning rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: RuleId
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=2_000)
    severity: Severity
    category: CategoryName
    language: LanguageName
    pattern: str = Field(min_length=1, max_length=1_000)
    explanation: str = Field(min_length=1, max_length=4_000)
    recommendation: str = Field(min_length=1, max_length=4_000)
    capabilities: tuple[Capability, ...] = ()

    @field_validator("pattern")
    @classmethod
    def pattern_must_compile(cls, value: str) -> str:
        try:
            re.compile(value)
            validate_regex_structure(value)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc
        except UnsafeRegexError as exc:
            raise ValueError(f"unsafe regular expression: {exc}") from exc
        return value
