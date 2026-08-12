"""Safe, bounded loading for data-only YAML rule files."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from safeinstall.exceptions import ParseLimitError, RuleLoadError
from safeinstall.rules.models import RuleDefinition
from safeinstall.safe_parsing import load_basic_yaml

MAX_RULE_FILE_BYTES = 1_000_000


def load_rule_file(
    path: Path, *, max_bytes: int = MAX_RULE_FILE_BYTES
) -> tuple[RuleDefinition, ...]:
    """Load one YAML file without constructing Python objects from YAML tags."""

    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise RuleLoadError(f"Rule file exceeds {max_bytes} bytes: {path}")
        text = path.read_text(encoding="utf-8")
        return load_rule_text(text, source=str(path))
    except RuleLoadError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleLoadError(f"Could not load rule file {path}: {exc}") from exc


def load_rule_text(text: str, *, source: str = "<memory>") -> tuple[RuleDefinition, ...]:
    """Validate YAML rule text while keeping YAML tags inert."""

    try:
        raw = load_basic_yaml(text)
        items = _normalize_document(raw)
        return tuple(RuleDefinition.model_validate(item) for item in items)
    except RuleLoadError:
        raise
    except (ParseLimitError, ValidationError, TypeError) as exc:
        raise RuleLoadError(f"Could not load rule file {source}: {exc}") from exc


def _normalize_document(raw: Any) -> list[Mapping[str, Any]]:
    if isinstance(raw, Mapping):
        return [raw]
    if isinstance(raw, list) and raw and all(isinstance(item, Mapping) for item in raw):
        return raw
    raise RuleLoadError("A rule file must contain one rule mapping or a non-empty list of rules.")
