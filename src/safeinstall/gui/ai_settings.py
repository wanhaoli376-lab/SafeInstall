"""Dependency-light checks for the explicitly optional AI explanation feature."""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Callable
from enum import StrEnum
from importlib.machinery import ModuleSpec


class AIAvailability(StrEnum):
    AVAILABLE = "available"
    MISSING_KEY = "missing_key"
    MISSING_SDK = "missing_sdk"


ModuleFinder = Callable[[str], ModuleSpec | None]


def check_ai_availability(
    *,
    module_finder: ModuleFinder = importlib.util.find_spec,
) -> AIAvailability:
    """Check opt-in prerequisites without importing the OpenAI SDK or reading target data."""

    if not os.environ.get("OPENAI_API_KEY"):
        return AIAvailability.MISSING_KEY
    if module_finder("openai") is None:
        return AIAvailability.MISSING_SDK
    return AIAvailability.AVAILABLE
