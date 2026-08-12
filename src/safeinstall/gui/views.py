"""Top-level pages for the desktop interface."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from safeinstall.gui.i18n import Catalog
from safeinstall.gui.models import TargetSelection
from safeinstall.gui.widgets import DropZone
from safeinstall.redaction import redact_text


class HomeView(QWidget):
    """Simple local/GitHub target selection page."""

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog

        self.title = QLabel()
        self.title.setObjectName("Title")
        self.tagline = QLabel()
        self.tagline.setObjectName("Tagline")
        self.drop_zone = DropZone(catalog)
        self.choose_file_button = QPushButton()
        self.choose_folder_button = QPushButton()
        self.github_label = QLabel()
        self.github_input = QLineEdit()
        self.github_notice = QLabel()
        self.github_notice.setObjectName("Muted")
        self.github_notice.setWordWrap(True)
        self.scan_button = QPushButton()
        self.scan_button.setObjectName("PrimaryButton")
        self.scan_button.setEnabled(False)

        self.selection_card = QFrame()
        self.selection_card.setObjectName("SelectionCard")
        self.selection_card.setVisible(False)
        selection_form = QFormLayout(self.selection_card)
        self.selection_status = QLabel()
        self.selection_status.setObjectName("ReadyStatus")
        self.selection_name = QLabel()
        self.selection_kind = QLabel()
        self.selection_location = QLabel()
        for label in (self.selection_name, self.selection_kind, self.selection_location):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
        selection_form.addRow(self.selection_status)
        self.selection_name_heading = QLabel()
        self.selection_kind_heading = QLabel()
        self.selection_location_heading = QLabel()
        selection_form.addRow(self.selection_name_heading, self.selection_name)
        selection_form.addRow(self.selection_kind_heading, self.selection_kind)
        selection_form.addRow(self.selection_location_heading, self.selection_location)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.choose_file_button)
        buttons.addWidget(self.choose_folder_button)
        buttons.addStretch()

        promises = QHBoxLayout()
        self.promise_labels = [QLabel() for _ in range(4)]
        for label in self.promise_labels:
            label.setObjectName("Muted")
            promises.addWidget(label)
        promises.addStretch()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(72, 44, 72, 52)
        layout.setSpacing(16)
        layout.addWidget(self.title)
        layout.addWidget(self.tagline)
        layout.addSpacing(8)
        layout.addWidget(self.drop_zone)
        layout.addLayout(buttons)
        layout.addWidget(self.selection_card)
        layout.addSpacing(8)
        layout.addWidget(self.github_label)
        layout.addWidget(self.github_input)
        layout.addWidget(self.github_notice)
        layout.addWidget(self.scan_button, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch()
        layout.addLayout(promises)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.retranslate()

    def show_selection(self, selection: TargetSelection | None) -> None:
        self.selection_card.setVisible(selection is not None)
        if selection is None:
            self.scan_button.setEnabled(False)
            return
        status_key = "selection.ready" if selection.supported else f"selection.{selection.reason}"
        self.selection_status.setText(self.catalog.text(status_key))
        self.selection_status.setProperty("unsupported", not selection.supported)
        self.selection_status.style().unpolish(self.selection_status)
        self.selection_status.style().polish(self.selection_status)
        self.selection_name.setText(redact_text(selection.display_name))
        self.selection_kind.setText(self.catalog.text(f"target.{selection.kind.value}"))
        self.selection_location.setText(redact_text(selection.location))
        self.scan_button.setEnabled(selection.supported)

    def retranslate(self) -> None:
        self.title.setText(self.catalog.text("app.title"))
        self.tagline.setText(self.catalog.text("app.tagline"))
        self.drop_zone.retranslate()
        self.choose_file_button.setText(self.catalog.text("home.choose_file"))
        self.choose_folder_button.setText(self.catalog.text("home.choose_folder"))
        self.github_label.setText(self.catalog.text("home.github_label"))
        self.github_input.setPlaceholderText(self.catalog.text("home.github_placeholder"))
        self.github_notice.setText(self.catalog.text("home.github_notice"))
        self.scan_button.setText(self.catalog.text("home.scan"))
        self.selection_name_heading.setText(self.catalog.text("selection.name"))
        self.selection_kind_heading.setText(self.catalog.text("selection.type"))
        self.selection_location_heading.setText(self.catalog.text("selection.location"))
        keys = ("home.local_first", "home.static", "home.no_account", "home.no_key")
        for label, key in zip(self.promise_labels, keys, strict=True):
            label.setText(f"✓ {self.catalog.text(key)}")


class ScanningView(QWidget):
    """Honest indeterminate progress page for a scan with no granular core progress."""

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.title = QLabel()
        self.title.setObjectName("Title")
        self.target = QLabel()
        self.target.setTextFormat(Qt.TextFormat.PlainText)
        self.target.setWordWrap(True)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.activity = QLabel()
        self.activity.setObjectName("Muted")
        self.activity.setWordWrap(True)
        self.boundary = QLabel()
        self.boundary.setObjectName("PrivacyNotice")
        self.boundary.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(120, 110, 120, 110)
        layout.setSpacing(20)
        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.target)
        layout.addWidget(self.progress)
        layout.addWidget(self.activity)
        layout.addWidget(self.boundary)
        layout.addStretch()
        self.retranslate()

    def set_target(self, display_name: str) -> None:
        self.target.setText(redact_text(display_name))

    def retranslate(self) -> None:
        self.title.setText(self.catalog.text("scanning.title"))
        self.activity.setText(self.catalog.text("scanning.activity"))
        self.boundary.setText(self.catalog.text("scanning.boundary"))
