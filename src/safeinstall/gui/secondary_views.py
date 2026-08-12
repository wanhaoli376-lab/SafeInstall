"""Settings, About, and friendly error pages."""

from __future__ import annotations

from PySide6.QtCore import QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from safeinstall import __version__
from safeinstall.gui.ai_settings import AIAvailability
from safeinstall.gui.error_presentation import ErrorPresentation
from safeinstall.gui.i18n import Catalog


class SettingsView(QWidget):
    language_changed = Signal(str)
    ai_toggled = Signal(bool)

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self._ai_availability: AIAvailability | None = None
        self.title = QLabel()
        self.title.setObjectName("Title")
        self.language_label = QLabel()
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("简体中文", "zh_CN")
        self.ai_heading = QLabel()
        self.ai_heading.setObjectName("SectionTitle")
        self.ai_checkbox = QCheckBox()
        self.ai_status = QLabel()
        self.ai_status.setObjectName("StatusNotice")
        self.ai_status.setWordWrap(True)
        self.local_heading = QLabel()
        self.local_heading.setObjectName("SectionTitle")
        self.local_privacy = QLabel()
        self.local_privacy.setWordWrap(True)
        self.ai_privacy = QLabel()
        self.ai_privacy.setObjectName("PrivacyNotice")
        self.ai_privacy.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(90, 58, 90, 58)
        layout.setSpacing(16)
        layout.addWidget(self.title)
        layout.addWidget(self.language_label)
        layout.addWidget(self.language_combo)
        layout.addWidget(self.ai_heading)
        layout.addWidget(self.ai_checkbox)
        layout.addWidget(self.ai_status)
        layout.addWidget(self.local_heading)
        layout.addWidget(self.local_privacy)
        layout.addWidget(self.ai_privacy)
        layout.addStretch()

        self.language_combo.currentIndexChanged.connect(self._emit_language)
        self.ai_checkbox.toggled.connect(self.ai_toggled)
        self.set_ai_availability(None)
        self.retranslate()

    def _emit_language(self, index: int) -> None:
        locale = self.language_combo.itemData(index)
        if isinstance(locale, str):
            self.language_changed.emit(locale)

    def set_ai_availability(self, availability: AIAvailability | None) -> None:
        self._ai_availability = availability
        key = "off" if availability is None else availability.value
        self.ai_status.setText(self.catalog.text(f"settings.ai_status.{key}"))

    def set_ai_checked(self, checked: bool) -> None:
        blocker = QSignalBlocker(self.ai_checkbox)
        self.ai_checkbox.setChecked(checked)
        del blocker

    def retranslate(self) -> None:
        self.title.setText(self.catalog.text("settings.title"))
        self.language_label.setText(self.catalog.text("settings.language"))
        self.ai_heading.setText(self.catalog.text("settings.ai_heading"))
        self.ai_checkbox.setText(self.catalog.text("settings.ai_checkbox"))
        self.local_heading.setText(self.catalog.text("settings.local_heading"))
        self.local_privacy.setText(self.catalog.text("settings.local_privacy"))
        self.ai_privacy.setText(self.catalog.text("settings.ai_privacy"))
        index = self.language_combo.findData(self.catalog.locale)
        if index >= 0:
            blocker = QSignalBlocker(self.language_combo)
            self.language_combo.setCurrentIndex(index)
            del blocker
        self.set_ai_availability(self._ai_availability)


class AboutView(QWidget):
    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.title = QLabel("SafeInstall")
        self.title.setObjectName("Title")
        self.tagline = QLabel()
        self.tagline.setObjectName("Tagline")
        form_container = QFrame()
        form_container.setObjectName("DetailsCard")
        form = QFormLayout(form_container)
        self.version_heading = QLabel()
        self.version_value = self._plain(__version__)
        self.license_heading = QLabel()
        self.license_value = self._plain()
        self.github_heading = QLabel("GitHub")
        self.github_value = QLabel(
            '<a href="https://github.com/wanhaoli376-lab/SafeInstall">'
            "wanhaoli376-lab/SafeInstall</a>"
        )
        self.github_value.setOpenExternalLinks(True)
        self.feedback_heading = QLabel()
        self.feedback_value = QLabel(
            '<a href="https://github.com/wanhaoli376-lab/SafeInstall/issues/new/choose">'
            "GitHub Issues</a>"
        )
        self.feedback_value.setOpenExternalLinks(True)
        form.addRow(self.version_heading, self.version_value)
        form.addRow(self.license_heading, self.license_value)
        form.addRow(self.github_heading, self.github_value)
        form.addRow(self.feedback_heading, self.feedback_value)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(120, 90, 120, 90)
        layout.setSpacing(16)
        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.tagline)
        layout.addWidget(form_container)
        layout.addStretch()
        self.retranslate()

    @staticmethod
    def _plain(text: str = "") -> QLabel:
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        return label

    def retranslate(self) -> None:
        self.tagline.setText(self.catalog.text("app.tagline"))
        self.version_heading.setText(self.catalog.text("about.version"))
        self.license_heading.setText(self.catalog.text("about.license"))
        self.license_value.setText(self.catalog.text("about.license_value"))
        self.feedback_heading.setText(self.catalog.text("about.feedback"))


class ErrorView(QWidget):
    back_requested = Signal()

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.title = QLabel()
        self.title.setObjectName("Title")
        self.message = QLabel()
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.details_button = QPushButton()
        self.details = QLabel()
        self.details.setObjectName("DetailsCard")
        self.details.setTextFormat(Qt.TextFormat.PlainText)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setWordWrap(True)
        self.details.hide()
        self.back_button = QPushButton()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(120, 100, 120, 100)
        layout.setSpacing(18)
        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.message)
        layout.addWidget(self.details_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.details)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        self.details_button.clicked.connect(self._toggle_details)
        self.back_button.clicked.connect(self.back_requested)
        self.retranslate()

    def set_error(self, error: ErrorPresentation) -> None:
        self.title.setText(error.title)
        self.message.setText(error.message)
        self.details.setText(error.technical_detail)
        self.details.hide()

    def _toggle_details(self) -> None:
        self.details.setVisible(not self.details.isVisible())

    def retranslate(self) -> None:
        self.details_button.setText(self.catalog.text("error.details"))
        self.back_button.setText(self.catalog.text("error.back"))
