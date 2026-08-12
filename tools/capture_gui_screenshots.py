"""Capture documentation screenshots from the real GUI and scan core."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QScrollArea, QWidget  # noqa: E402

from safeinstall.core import scan_target  # noqa: E402 - Qt mode must be set first
from safeinstall.gui.app import create_application  # noqa: E402
from safeinstall.gui.main_window import MainWindow  # noqa: E402


def _save_window(window: MainWindow, path: Path) -> None:
    window.repaint()
    application = create_application()
    application.processEvents()
    if not window.grab().save(str(path), "PNG"):
        raise RuntimeError(f"Could not save GUI screenshot: {path}")


def _save_scroll_content(view: QWidget, path: Path, *, width: int = 1160) -> None:
    """Capture a real scroll page at its full content height.

    Documentation needs to show the whole result, including the sections that a user
    normally reaches by scrolling.  Capturing the live content widget preserves the
    actual controls, styles, and report data without composing a mock image.
    """

    scroll = view.findChild(QScrollArea)
    if scroll is None or scroll.widget() is None:
        raise RuntimeError(f"Could not find scroll content for GUI screenshot: {path}")
    content = scroll.widget()
    scroll.setWidgetResizable(False)
    content.resize(width, content.layout().sizeHint().height())
    application = create_application()
    application.processEvents()
    if not content.grab().save(str(path), "PNG"):
        raise RuntimeError(f"Could not save GUI screenshot: {path}")
    scroll.setWidgetResizable(True)


def main() -> int:
    root = Path(__file__).parents[1]
    output = root / "docs" / "images"
    output.mkdir(parents=True, exist_ok=True)

    application = create_application(["safeinstall-screenshot"])
    window = MainWindow(locale="en")
    window.resize(1280, 960)
    window.show()
    application.processEvents()

    _save_window(window, output / "safeinstall-home.png")

    report = scan_target(str(root / "examples" / "risky-project"), ai=False)
    window.last_report = report
    window.result_view.set_report(report)
    window.pages.setCurrentWidget(window.result_view)
    _save_scroll_content(window.result_view, output / "safeinstall-result.png")

    window.technical_view.set_report(report)
    window.pages.setCurrentWidget(window.technical_view)
    _save_scroll_content(
        window.technical_view,
        output / "safeinstall-technical-details.png",
    )

    window.close()
    application.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
