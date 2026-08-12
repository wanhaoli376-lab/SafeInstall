"""Reusable Qt widgets for the SafeInstall desktop interface."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QMimeData, Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout

from safeinstall.gui.i18n import Catalog


class DropZone(QFrame):
    """Accept exactly one local file or folder and emit it without scanning."""

    target_dropped = Signal(str)

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.setObjectName("DropZone")
        self.setMinimumHeight(190)
        self.setAcceptDrops(True)

        self.title = QLabel()
        self.title.setObjectName("DropTitle")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle = QLabel()
        self.subtitle.setObjectName("Muted")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 40, 24, 40)
        layout.setSpacing(10)
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        self.retranslate()

    @staticmethod
    def local_path_from_mime(mime: QMimeData) -> str | None:
        urls = mime.urls() if mime.hasUrls() else []
        if len(urls) != 1 or not urls[0].isLocalFile():
            return None
        path = urls[0].toLocalFile()
        return str(Path(path)) if path else None

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 - Qt API
        if self.local_path_from_mime(event.mimeData()) is not None:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 - Qt API
        path = self.local_path_from_mime(event.mimeData())
        if path is None:
            event.ignore()
            return
        event.acceptProposedAction()
        self.target_dropped.emit(path)

    def retranslate(self) -> None:
        self.title.setText(self.catalog.text("home.drop_title"))
        self.subtitle.setText(self.catalog.text("home.drop_subtitle"))
