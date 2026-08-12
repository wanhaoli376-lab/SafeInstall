"""Qt-independent models used by the desktop presentation layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TargetType(StrEnum):
    FILE = "file"
    FOLDER = "folder"
    ARCHIVE = "archive"
    GITHUB = "github"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class TargetSelection:
    """A locally validated scan choice; classification never reads file contents."""

    target: str
    display_name: str
    kind: TargetType
    location: str
    supported: bool
    reason: str | None = None
