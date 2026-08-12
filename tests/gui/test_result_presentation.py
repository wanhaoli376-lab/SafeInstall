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
