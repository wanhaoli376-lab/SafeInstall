"""Shared models and interface for target loaders."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from safeinstall.models import TargetKind


@dataclass(frozen=True, slots=True)
class LoadedTarget:
    """A target root that remains valid for the loader context lifetime."""

    root: Path
    source: str
    kind: TargetKind
    selected_files: tuple[Path, ...] | None = None
    metadata: dict[str, str] = field(default_factory=dict)


class TargetLoader(Protocol):
    """Loader seam for local, archive, and remote target adapters."""

    def supports(self, target: str) -> bool:
        """Return whether the loader recognizes this input."""

    def open(self, target: str | Path) -> AbstractContextManager[LoadedTarget]:
        """Expose a safe workspace for the lifetime of a context manager."""
