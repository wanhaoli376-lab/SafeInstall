"""Resource-bounded parsers for untrusted data files."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml

from safeinstall.exceptions import ParseLimitError


def load_basic_yaml(
    text: str,
    *,
    max_aliases: int = 50,
    max_nodes: int = 50_000,
    max_depth: int = 100,
) -> Any:
    """Parse YAML into strings, lists, and mappings without typed constructors."""

    aliases = 0
    tokens = 0
    try:
        for token in yaml.scan(text, Loader=yaml.BaseLoader):
            tokens += 1
            if isinstance(token, yaml.tokens.TagToken):
                raise ParseLimitError("YAML tags are not allowed.")
            if isinstance(token, yaml.tokens.AliasToken):
                aliases += 1
            if aliases > max_aliases or tokens > max_nodes * 4:
                raise ParseLimitError("YAML token or alias limit exceeded.")
        data = yaml.load(text, Loader=yaml.BaseLoader)  # noqa: S506 - BaseLoader has no object tags
    except ParseLimitError:
        raise
    except yaml.YAMLError as exc:
        raise ParseLimitError(f"Invalid YAML data: {exc}") from exc

    stack: list[tuple[Any, int]] = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ParseLimitError("YAML structure limit exceeded.")
        if isinstance(value, Mapping):
            stack.extend((key, depth + 1) for key in value)
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif value is not None and not isinstance(value, str):
            raise ParseLimitError("YAML contains an unsupported value type.")
    return data
