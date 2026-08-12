import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from safeinstall.gui.app import create_application
from safeinstall.gui.main_window import MainWindow


def test_gui_starts_without_api_key(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: object,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    create_application([])
    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    assert window.windowTitle() == "SafeInstall"
    assert window.home_view.choose_file_button.text() == "Choose File"
    assert window.home_view.choose_folder_button.text() == "Choose Folder"
    assert window.home_view.github_input.placeholderText() == "https://github.com/owner/repository"
    assert not window.home_view.scan_button.isEnabled()
