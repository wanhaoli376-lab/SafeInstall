"""Shared scanner interface."""

from __future__ import annotations

from typing import Protocol

from safeinstall.models import Finding, SourceFile


class Scanner(Protocol):
    """Static scanner seam used by built-ins and future plugins."""

    def supports(self, source: SourceFile) -> bool:
        """Return whether this scanner understands the source file."""

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        """Inspect source as untrusted data and never execute it."""
