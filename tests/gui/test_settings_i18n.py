import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from safeinstall.gui.ai_settings import AIAvailability, check_ai_availability
from safeinstall.gui.main_window import MainWindow


def test_ai_availability_distinguishes_missing_key_and_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert check_ai_availability() is AIAvailability.MISSING_KEY

    monkeypatch.setenv("OPENAI_API_KEY", "inert-test-value")
    assert check_ai_availability(module_finder=lambda _name: None) is AIAvailability.MISSING_SDK


def test_ai_is_off_by_default_and_missing_key_is_friendly(qtbot: object) -> None:
    window = MainWindow(ai_checker=lambda: AIAvailability.MISSING_KEY)
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    assert not window.ai_enabled
    assert not window.settings_view.ai_checkbox.isChecked()

    window.settings_view.ai_checkbox.click()

    assert not window.ai_enabled
    assert not window.settings_view.ai_checkbox.isChecked()
    assert "No OpenAI API key" in window.settings_view.ai_status.text()


def test_language_can_switch_without_restarting(qtbot: object) -> None:
    window = MainWindow(locale="en")
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    window.set_locale("zh_CN")

    assert window.home_view.choose_file_button.text() == "选择文件"
    assert window.settings_button.text() == "设置"
    assert window.about_view.license_value.text() == "MIT 许可证"


def test_about_page_uses_repository_version_and_license(qtbot: object) -> None:
    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    assert window.about_view.version_value.text().startswith("0.")
    assert "wanhaoli376-lab/SafeInstall" in window.about_view.github_value.text()
    assert "issues/new/choose" in window.about_view.feedback_value.text()
    assert window.about_view.feedback_heading.text() == "Feedback"
    assert window.about_view.license_value.text() == "MIT License"

    window.set_locale("zh_CN")

    assert window.about_view.feedback_heading.text() == "问题反馈"


def test_home_selection_field_labels_retranslate(qtbot: object) -> None:
    window = MainWindow(locale="en")
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    window.set_locale("zh_CN")

    assert window.home_view.selection_name_heading.text() == "名称："
    assert window.home_view.selection_kind_heading.text() == "类型："
    assert window.home_view.selection_location_heading.text() == "位置："
