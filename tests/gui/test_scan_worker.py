import os
import threading
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import Qt, QThread

from safeinstall.core import scan_target
from safeinstall.gui.ai_settings import AIAvailability
from safeinstall.gui.app import create_application
from safeinstall.gui.main_window import MainWindow
from safeinstall.models import ScanReport


def test_local_scan_without_api_key_runs_outside_ui_thread(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: object,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    project = Path(__file__).parents[2] / "examples" / "safe-project"
    worker_threads: list[QThread] = []
    ai_values: list[bool] = []

    def recording_scanner(target: str, *, ai: bool = False) -> ScanReport:
        worker_threads.append(QThread.currentThread())
        ai_values.append(ai)
        return scan_target(target, ai=ai)

    application = create_application([])
    window = MainWindow(scanner=recording_scanner)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.select_target(str(project))

    with qtbot.waitSignal(window.scan_completed, timeout=10_000) as signal:  # type: ignore[attr-defined]
        qtbot.mouseClick(  # type: ignore[attr-defined]
            window.home_view.scan_button, Qt.MouseButton.LeftButton
        )

    report = signal.args[0]
    assert isinstance(report, ScanReport)
    assert report.target.files_scanned > 0
    assert worker_threads == [worker_threads[0]]
    assert worker_threads[0] is not application.thread()
    assert ai_values == [False]
    assert window.last_report is report
    assert window.pages.currentWidget() is window.result_view
    assert window.result_view.risk_label.text() == "LOW · Low risk"
    assert window.home_button.isEnabled()
    assert window.settings_button.isEnabled()
    assert window.about_button.isEnabled()


def test_scan_failure_is_returned_as_data_not_traceback(
    tmp_path: Path,
    qtbot: object,
) -> None:
    target = tmp_path / "fixture.py"
    target.write_text("# inert", encoding="utf-8")

    def failing_scanner(_target: str, *, ai: bool = False) -> Any:
        del ai
        raise ValueError("bounded failure")

    window = MainWindow(scanner=failing_scanner)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.select_target(str(target))

    with qtbot.waitSignal(window.scan_failed, timeout=5_000) as signal:  # type: ignore[attr-defined]
        qtbot.mouseClick(  # type: ignore[attr-defined]
            window.home_view.scan_button, Qt.MouseButton.LeftButton
        )

    assert isinstance(signal.args[0], ValueError)
    assert window.home_view.scan_button.isEnabled()
    assert window.pages.currentWidget() is window.error_view
    assert "Traceback" not in window.error_view.details.text()


def test_local_scan_does_not_call_optional_ai_client_when_sdk_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: object,
) -> None:
    from safeinstall.analysis import ai_analysis

    monkeypatch.setattr(
        ai_analysis,
        "_client_from_environment",
        lambda: pytest.fail("optional AI client must not be created"),
    )
    project = Path(__file__).parents[2] / "examples" / "safe-project"
    window = MainWindow(ai_checker=lambda: AIAvailability.MISSING_SDK)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.settings_view.ai_checkbox.click()
    window.select_target(str(project))

    with qtbot.waitSignal(window.scan_completed, timeout=10_000):  # type: ignore[attr-defined]
        window.home_view.scan_button.click()

    assert not window.ai_enabled
    assert window.last_report is not None
    assert window.last_report.ai_analysis is None


def test_navigation_is_locked_while_scan_thread_is_running(qtbot: object) -> None:
    project = Path(__file__).parents[2] / "examples" / "safe-project"
    started = threading.Event()
    release = threading.Event()

    def blocking_scanner(target: str, *, ai: bool = False) -> ScanReport:
        del ai
        started.set()
        if not release.wait(timeout=5):
            raise TimeoutError("test did not release worker")
        return scan_target(target)

    window = MainWindow(scanner=blocking_scanner)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.select_target(str(project))
    window.home_view.scan_button.click()
    qtbot.waitUntil(started.is_set, timeout=2_000)  # type: ignore[attr-defined]

    assert not window.home_button.isEnabled()
    assert not window.settings_button.isEnabled()
    assert not window.about_button.isEnabled()

    with qtbot.waitSignal(window.scan_completed, timeout=10_000):  # type: ignore[attr-defined]
        release.set()

    assert window.home_button.isEnabled()
