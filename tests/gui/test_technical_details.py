from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from safeinstall.core import scan_target
from safeinstall.gui.i18n import Catalog
from safeinstall.gui.technical_view import TechnicalDetailsView


def test_technical_details_separate_fact_inference_and_advice(qtbot: object) -> None:
    project = Path(__file__).parents[2] / "examples" / "risky-project"
    report = scan_target(project)
    view = TechnicalDetailsView(Catalog("en"))
    qtbot.addWidget(view)  # type: ignore[attr-defined]

    view.set_report(report)

    assert view.rule_value.text() == "SI-PY-001"
    assert view.file_value.text() == "capabilities.py"
    assert view.line_value.text() == "13"
    assert "subprocess.run" in view.fact_value.text()
    assert "operating system shell" in view.inference_value.text()
    assert "shell=True" in view.advice_value.text()
    assert view.basis_value.text() == "Observed fact"


def test_inferred_finding_is_labeled_as_inference(qtbot: object) -> None:
    project = Path(__file__).parents[2] / "examples" / "risky-project"
    report = scan_target(project)
    view = TechnicalDetailsView(Catalog("en"))
    qtbot.addWidget(view)  # type: ignore[attr-defined]
    view.set_report(report)

    inferred_row = next(
        index
        for index, finding in enumerate(report.findings)
        if finding.confidence.value == "inferred"
    )
    view.finding_table.selectRow(inferred_row)
    view.show_finding(inferred_row)

    assert view.basis_value.text() == "Inference"
    assert view.fact_heading.text() == "Observed evidence"
    assert view.inference_heading.text() == "SafeInstall's assessment"
    assert view.advice_heading.text() == "Advice"


def test_partial_technical_report_keeps_coverage_visible_when_language_changes(
    tmp_path: Path, qtbot: object
) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "broken.sh").write_bytes(b"\x81fixture")
    catalog = Catalog("en")
    view = TechnicalDetailsView(catalog)
    qtbot.addWidget(view)  # type: ignore[attr-defined]
    view.set_report(scan_target(tmp_path))

    assert not view.coverage_notice.isHidden()
    assert "broken.sh" in view.coverage_notice.text()
    assert "scanned files only" in view.score.text().lower()

    catalog.switch("zh_CN")
    view.retranslate()
    assert "扫描不完整" in view.score.text()
    assert "无法按受支持的 UTF-8" in view.coverage_notice.text()
