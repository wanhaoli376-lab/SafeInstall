"""Qt application bootstrap for the optional SafeInstall desktop interface."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import cast

from PySide6.QtCore import QLocale, QTimer
from PySide6.QtWidgets import QApplication

from safeinstall.gui.main_window import MainWindow
from safeinstall.gui.styles import APPLICATION_STYLE


def create_application(argv: Sequence[str] | None = None) -> QApplication:
    """Return the process QApplication without reading API keys or using the network."""

    existing = QApplication.instance()
    if existing is not None:
        return cast(QApplication, existing)
    application = QApplication(list(argv) if argv is not None else sys.argv)
    application.setApplicationName("SafeInstall")
    application.setOrganizationName("SafeInstall")
    application.setStyle("Fusion")
    application.setStyleSheet(APPLICATION_STYLE)
    return application


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else list(sys.argv)
    smoke_test = "--smoke-test" in arguments
    arguments = [argument for argument in arguments if argument != "--smoke-test"]
    smoke_target = _take_option(arguments, "--smoke-scan")
    application = create_application(arguments)
    window = MainWindow(locale=QLocale.system().name())
    window.show()
    if smoke_test:
        application.processEvents()
        window.close()
        application.processEvents()
        return 0
    if smoke_target is not None:
        window.select_target(smoke_target)
        selection = window.current_selection
        if selection is None or not selection.supported:
            window.close()
            return 4

        timeout = QTimer(window)
        timeout.setSingleShot(True)
        timeout.setInterval(60_000)

        def complete(report: object) -> None:
            timeout.stop()
            files_scanned = getattr(getattr(report, "target", None), "files_scanned", 0)
            application.exit(0 if files_scanned > 0 else 5)

        def failed(_error: object) -> None:
            timeout.stop()
            application.exit(3)

        window.scan_completed.connect(complete)
        window.scan_failed.connect(failed)
        timeout.timeout.connect(lambda: application.exit(124))
        timeout.start()
        window.start_scan()
        return application.exec()
    return application.exec()


def _take_option(arguments: list[str], option: str) -> str | None:
    if option not in arguments:
        return None
    index = arguments.index(option)
    if index + 1 >= len(arguments):
        return ""
    value = arguments[index + 1]
    del arguments[index : index + 2]
    return value


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
