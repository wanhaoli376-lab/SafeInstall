"""Public interface for SafeInstall scanner plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from safeinstall.models import Finding, SourceFile


class ScannerPlugin(ABC):
    """A scanner extension explicitly registered by a trusted caller.

    Importing a Python plugin executes that plugin's module-level code. SafeInstall therefore does
    not auto-discover or import plugins from a scanned target.
    """

    name: ClassVar[str]

    @abstractmethod
    def supports(self, source: SourceFile) -> bool:
        """Return whether this plugin understands the source file."""

    @abstractmethod
    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        """Return evidence-backed findings without executing target content."""
