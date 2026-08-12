"""Background adapters that keep core scans off the Qt UI thread."""

from __future__ import annotations

from typing import Protocol

from PySide6.QtCore import QObject, Signal, Slot

from safeinstall.core import scan_target
from safeinstall.models import ScanReport


class ScannerCallable(Protocol):
    def __call__(self, target: str, *, ai: bool = False) -> ScanReport: ...


class ScanWorker(QObject):
    """Run exactly one public-API scan and return its result as Qt data."""

    completed = Signal(object)
    failed = Signal(object)

    def __init__(
        self,
        target: str,
        *,
        ai: bool = False,
        scanner: ScannerCallable = scan_target,
    ) -> None:
        super().__init__()
        self._target = target
        self._ai = ai
        self._scanner = scanner

    @Slot()
    def run(self) -> None:
        try:
            report = self._scanner(self._target, ai=self._ai)
        except Exception as exc:  # Qt boundary: present errors without a console traceback
            self.failed.emit(exc)
        else:
            self.completed.emit(report)
