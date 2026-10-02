from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QFileDialog, QMessageBox

from safeinstall.core import scan_target
from safeinstall.gui.exporting import ReportFormat, export_report, normalized_export_path
from safeinstall.gui.main_window import MainWindow


def test_export_reuses_json_and_markdown_renderers(tmp_path: Path) -> None:
    project = Path(__file__).parents[2] / "examples" / "risky-project"
    report = scan_target(project)
    json_path = tmp_path / "safeinstall-report.json"
    markdown_path = tmp_path / "safeinstall-report.md"

    export_report(report, json_path, ReportFormat.JSON)
    export_report(report, markdown_path, ReportFormat.MARKDOWN)

    assert '"schema_version": "1.1"' in json_path.read_text(encoding="utf-8")
    assert "# SafeInstall Report" in markdown_path.read_text(encoding="utf-8")
    assert "SI-PY-001" in markdown_path.read_text(encoding="utf-8")


def test_export_does_not_overwrite_without_explicit_confirmation(tmp_path: Path) -> None:
    project = Path(__file__).parents[2] / "examples" / "safe-project"
    report = scan_target(project)
    destination = tmp_path / "existing.json"
    destination.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        export_report(report, destination, ReportFormat.JSON)

    assert destination.read_text(encoding="utf-8") == "keep me"


def test_switching_export_filter_replaces_the_default_suffix(tmp_path: Path) -> None:
    markdown_default = tmp_path / "safeinstall-report.md"

    assert normalized_export_path(markdown_default, ReportFormat.JSON) == (
        tmp_path / "safeinstall-report.json"
    )
    assert normalized_export_path(tmp_path / "safeinstall-report.json", ReportFormat.MARKDOWN) == (
        tmp_path / "safeinstall-report.md"
    )


def test_export_keeps_detected_secret_redacted(tmp_path: Path) -> None:
    project = tmp_path / "target"
    project.mkdir()
    secret = "".join(("sk-proj-", "abcdefghijklmnopqrstuvwxyz1234567890"))
    (project / ".env").write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
    report = scan_target(project)
    output = tmp_path / "report.json"

    export_report(report, output, ReportFormat.JSON)

    rendered = output.read_text(encoding="utf-8")
    assert secret not in rendered
    assert "sk-****...7890" in rendered


def test_result_page_exports_selected_markdown_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: object,
) -> None:
    report = scan_target(Path(__file__).parents[2] / "examples" / "safe-project")
    destination = tmp_path / "desktop-report.md"
    notices: list[str] = []
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(destination), "Markdown report (*.md)"),
    )
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda _parent, _title, message: notices.append(message),
    )
    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.last_report = report
    window.result_view.set_report(report)

    window.result_view.export_button.click()

    assert destination.is_file()
    assert "# SafeInstall Report" in destination.read_text(encoding="utf-8")
    assert notices


def test_result_page_replaces_markdown_default_when_json_filter_is_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: object,
) -> None:
    report = scan_target(Path(__file__).parents[2] / "examples" / "safe-project")
    dialog_default = tmp_path / "safeinstall-report.md"
    expected = tmp_path / "safeinstall-report.json"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(dialog_default), "JSON report (*.json)"),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *_args, **_kwargs: None)
    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.last_report = report
    window.result_view.set_report(report)

    window.result_view.export_button.click()

    assert expected.is_file()
    assert not (tmp_path / "safeinstall-report.md.json").exists()
