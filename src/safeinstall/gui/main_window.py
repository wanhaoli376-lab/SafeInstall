"""Main desktop window; all scans will enter through ``scan_target``."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from safeinstall.core import scan_target
from safeinstall.gui.ai_settings import AIAvailability, check_ai_availability
from safeinstall.gui.error_presentation import present_error
from safeinstall.gui.exporting import ReportFormat, export_report, normalized_export_path
from safeinstall.gui.i18n import Catalog
from safeinstall.gui.models import TargetSelection
from safeinstall.gui.result_view import ResultView
from safeinstall.gui.secondary_views import AboutView, ErrorView, SettingsView
from safeinstall.gui.targeting import classify_target
from safeinstall.gui.technical_view import TechnicalDetailsView
from safeinstall.gui.views import HomeView, ScanningView
from safeinstall.gui.workers import ScannerCallable, ScanWorker
from safeinstall.models import ScanReport
from safeinstall.redaction import redact_text


class MainWindow(QMainWindow):
    """SafeInstall desktop shell with no startup account, key, or network checks."""

    scan_completed = Signal(object)
    scan_failed = Signal(object)

    def __init__(
        self,
        *,
        locale: str = "en",
        scanner: ScannerCallable = scan_target,
        ai_checker: Callable[[], AIAvailability] = check_ai_availability,
    ) -> None:
        super().__init__()
        self._scanner = scanner
        self._ai_checker = ai_checker
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        self._pending_report: ScanReport | None = None
        self._pending_error: Exception | None = None
        self._last_error: Exception | None = None
        self.last_report: ScanReport | None = None
        self.ai_enabled = False
        self.catalog = Catalog(locale)
        self.setWindowTitle(self.catalog.text("app.title"))
        self.setMinimumSize(900, 640)
        self.resize(1080, 760)

        root = QWidget()
        root.setObjectName("AppRoot")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        header = QFrame()
        header.setObjectName("Header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 12, 24, 12)
        self.brand_label = QLabel("SafeInstall")
        self.brand_label.setObjectName("Brand")
        self.home_button = QPushButton()
        self.home_button.setObjectName("NavButton")
        self.settings_button = QPushButton()
        self.settings_button.setObjectName("NavButton")
        self.about_button = QPushButton()
        self.about_button.setObjectName("NavButton")
        header_layout.addWidget(self.brand_label)
        header_layout.addStretch()
        header_layout.addWidget(self.home_button)
        header_layout.addWidget(self.settings_button)
        header_layout.addWidget(self.about_button)
        root_layout.addWidget(header)
        self.pages = QStackedWidget()
        self.home_view = HomeView(self.catalog)
        self.scanning_view = ScanningView(self.catalog)
        self.result_view = ResultView(self.catalog)
        self.technical_view = TechnicalDetailsView(self.catalog)
        self.settings_view = SettingsView(self.catalog)
        self.about_view = AboutView(self.catalog)
        self.error_view = ErrorView(self.catalog)
        self.current_selection: TargetSelection | None = None
        self.pages.addWidget(self.home_view)
        self.pages.addWidget(self.scanning_view)
        self.pages.addWidget(self.result_view)
        self.pages.addWidget(self.technical_view)
        self.pages.addWidget(self.settings_view)
        self.pages.addWidget(self.about_view)
        self.pages.addWidget(self.error_view)
        root_layout.addWidget(self.pages)
        self.setCentralWidget(root)

        self.home_view.choose_file_button.clicked.connect(self._choose_file)
        self.home_view.choose_folder_button.clicked.connect(self._choose_folder)
        self.home_view.drop_zone.target_dropped.connect(self.select_target)
        self.home_view.github_input.textEdited.connect(self._github_edited)
        self.home_view.scan_button.clicked.connect(self.start_scan)
        self.result_view.back_requested.connect(self._back_home)
        self.result_view.technical_requested.connect(self._show_technical)
        self.result_view.export_requested.connect(self._export_report)
        self.technical_view.back_requested.connect(self._show_result)
        self.settings_view.language_changed.connect(self.set_locale)
        self.settings_view.ai_toggled.connect(self._set_ai_enabled)
        self.error_view.back_requested.connect(self._back_home)
        self.home_button.clicked.connect(self._back_home)
        self.settings_button.clicked.connect(self._show_settings)
        self.about_button.clicked.connect(self._show_about)
        self._retranslate_navigation()

    def _choose_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            self.catalog.text("home.choose_file"),
            "",
            self.catalog.text("home.file_filter"),
        )
        if filename:
            self.select_target(filename)

    def _choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, self.catalog.text("home.choose_folder"))
        if folder:
            self.select_target(folder)

    def select_target(self, target: str) -> None:
        """Prepare one target for an explicit scan-button action."""

        self.current_selection = classify_target(target)
        if self.current_selection.kind.value != "github" and self.home_view.github_input.text():
            self.home_view.github_input.clear()
        self.home_view.show_selection(self.current_selection)

    def _github_edited(self, value: str) -> None:
        self.current_selection = classify_target(value) if value.strip() else None
        self.home_view.show_selection(self.current_selection)

    def start_scan(self) -> None:
        """Start a prepared scan in a worker thread after any network disclosure."""

        selection = self.current_selection
        if selection is None or not selection.supported or self._scan_thread is not None:
            return
        if selection.kind.value == "github":
            answer = QMessageBox.question(
                self,
                self.catalog.text("github.confirm_title"),
                self.catalog.text("github.confirm_body"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer is not QMessageBox.StandardButton.Yes:
                return

        self._pending_report = None
        self._pending_error = None
        self.home_view.scan_button.setEnabled(False)
        self.scanning_view.set_target(selection.display_name)
        self.pages.setCurrentWidget(self.scanning_view)
        self._set_navigation_enabled(False)

        thread = QThread(self)
        worker = ScanWorker(
            selection.target,
            ai=self.ai_enabled,
            scanner=self._scanner,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._receive_report)
        worker.failed.connect(self._receive_error)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(self._scan_finished)
        thread.finished.connect(thread.deleteLater)
        self._scan_thread = thread
        self._scan_worker = worker
        thread.start()

    def _receive_report(self, report: object) -> None:
        if isinstance(report, ScanReport):
            self._pending_report = report
        else:
            self._pending_error = TypeError("Scanner returned an invalid report.")

    def _receive_error(self, error: object) -> None:
        self._pending_error = error if isinstance(error, Exception) else RuntimeError(str(error))

    def _scan_finished(self) -> None:
        report = self._pending_report
        error = self._pending_error
        self._scan_thread = None
        self._scan_worker = None
        self._pending_report = None
        self._pending_error = None
        if report is not None:
            self.last_report = report
            self.result_view.set_report(report)
            self.pages.setCurrentWidget(self.result_view)
            self._set_navigation_enabled(True)
            self.scan_completed.emit(report)
            return
        failure = error or RuntimeError("Scan stopped without a result.")
        self._last_error = failure
        self.error_view.set_error(present_error(failure, self.catalog))
        self.pages.setCurrentWidget(self.error_view)
        self._set_navigation_enabled(True)
        self.home_view.scan_button.setEnabled(
            self.current_selection is not None and self.current_selection.supported
        )
        self.scan_failed.emit(failure)

    def _back_home(self) -> None:
        self.pages.setCurrentWidget(self.home_view)
        self.home_view.scan_button.setEnabled(
            self.current_selection is not None and self.current_selection.supported
        )

    def _show_technical(self) -> None:
        if self.last_report is None:
            return
        self.technical_view.set_report(self.last_report)
        self.pages.setCurrentWidget(self.technical_view)

    def _show_result(self) -> None:
        if self.last_report is not None:
            self.pages.setCurrentWidget(self.result_view)

    def _show_settings(self) -> None:
        if self._scan_thread is None:
            self.pages.setCurrentWidget(self.settings_view)

    def _show_about(self) -> None:
        if self._scan_thread is None:
            self.pages.setCurrentWidget(self.about_view)

    def set_locale(self, locale: str) -> None:
        self.catalog.switch(locale)
        self.setWindowTitle(self.catalog.text("app.title"))
        self._retranslate_navigation()
        for view in (
            self.home_view,
            self.scanning_view,
            self.result_view,
            self.technical_view,
            self.settings_view,
            self.about_view,
            self.error_view,
        ):
            view.retranslate()
        if self.current_selection is not None:
            self.home_view.show_selection(self.current_selection)
        if self._last_error is not None:
            self.error_view.set_error(present_error(self._last_error, self.catalog))

    def _retranslate_navigation(self) -> None:
        self.home_button.setText(self.catalog.text("nav.home"))
        self.settings_button.setText(self.catalog.text("nav.settings"))
        self.about_button.setText(self.catalog.text("nav.about"))

    def _set_navigation_enabled(self, enabled: bool) -> None:
        self.home_button.setEnabled(enabled)
        self.settings_button.setEnabled(enabled)
        self.about_button.setEnabled(enabled)

    def _set_ai_enabled(self, requested: bool) -> None:
        if not requested:
            self.ai_enabled = False
            self.settings_view.set_ai_availability(None)
            return
        availability = self._ai_checker()
        self.settings_view.set_ai_availability(availability)
        self.ai_enabled = availability is AIAvailability.AVAILABLE
        if not self.ai_enabled:
            self.settings_view.set_ai_checked(False)

    def _export_report(self) -> None:
        report = self.last_report
        if report is None:
            return
        markdown_filter = self.catalog.text("export.markdown_filter")
        json_filter = self.catalog.text("export.json_filter")
        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            self.catalog.text("export.title"),
            "safeinstall-report.md",
            f"{markdown_filter};;{json_filter}",
            markdown_filter,
        )
        if not filename:
            return
        report_format = (
            ReportFormat.JSON
            if filename.casefold().endswith(".json") or selected_filter == json_filter
            else ReportFormat.MARKDOWN
        )
        destination = str(normalized_export_path(filename, report_format))

        path_exists = False
        with suppress(OSError):
            path_exists = Path(destination).expanduser().exists()
        if path_exists:
            answer = QMessageBox.question(
                self,
                self.catalog.text("export.overwrite_title"),
                self.catalog.text("export.overwrite_body"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer is not QMessageBox.StandardButton.Yes:
                return
        try:
            exported = export_report(
                report,
                destination,
                report_format,
                overwrite=path_exists,
            )
        except (OSError, ValueError) as exc:
            dialog = QMessageBox(self)
            dialog.setIcon(QMessageBox.Icon.Critical)
            dialog.setWindowTitle(self.catalog.text("export.failed_title"))
            dialog.setText(self.catalog.text("export.failed_body"))
            dialog.setDetailedText(redact_text(str(exc))[:2_000])
            dialog.exec()
            return
        QMessageBox.information(
            self,
            self.catalog.text("export.success_title"),
            self.catalog.text("export.success_body", path=str(exported)),
        )

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        if self._scan_thread is not None and self._scan_thread.isRunning():
            event.ignore()
            return
        super().closeEvent(event)
