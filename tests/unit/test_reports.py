import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from safeinstall.core import scan_target
from safeinstall.models import (
    Capability,
    CapabilitySummary,
    Evidence,
    Finding,
    RiskAssessment,
    ScanCoverage,
    ScanReport,
    Severity,
    SkippedPath,
    SkipReason,
    TargetKind,
    TargetSummary,
)
from safeinstall.report.json_report import render_json
from safeinstall.report.markdown import render_markdown
from safeinstall.report.terminal import render_terminal

_OPENAI_KEY_FIXTURE = "".join(("sk-", "abcdefghijklmnopqrstuvwxyz123456"))


def _report() -> ScanReport:
    finding = Finding(
        rule_id="SI-PY-001",
        name="Shell command execution",
        description="A subprocess call enables shell interpretation.",
        severity=Severity.HIGH,
        category="command_execution",
        language="python",
        explanation="This program can ask the operating system shell to interpret a command.",
        recommendation="Review how the command is constructed.",
        evidence=(
            Evidence(
                path="demo.py",
                line=4,
                snippet="subprocess.run(command, shell=True)",
            ),
        ),
        capabilities=(Capability.SHELL_EXECUTION,),
    )
    capabilities = CapabilitySummary(observed=(Capability.SHELL_EXECUTION,))
    return ScanReport(
        safeinstall_version="0.1.0a0",
        target=TargetSummary(
            source="./example",
            display_name="example",
            kind=TargetKind.LOCAL,
            files_scanned=1,
            scan_started_at=datetime(2026, 8, 12, tzinfo=UTC),
            scan_duration_ms=12,
        ),
        risk=RiskAssessment(
            level=Severity.HIGH,
            score=60,
            primary_reasons=("HIGH: Shell command execution.",),
            capabilities=capabilities,
        ),
        findings=(finding,),
        analysis_scope=("The target was not executed.",),
        disclaimer="SafeInstall does not guarantee that software is safe.",
    )


def test_json_report_has_stable_machine_readable_fields() -> None:
    data = json.loads(render_json(_report()))

    assert data["schema_version"] == "1.1"
    assert data["risk"]["level"] == "high"
    assert data["findings"][0]["evidence"][0] == {
        "path": "demo.py",
        "line": 4,
        "end_line": None,
        "snippet": "subprocess.run(command, shell=True)",
    }


def test_markdown_and_terminal_reports_explain_risk_and_capabilities() -> None:
    report = _report()
    markdown = render_markdown(report)
    console = Console(record=True, width=100, color_system=None)

    render_terminal(report, console=console)
    terminal = console.export_text()

    for rendered in (markdown, terminal):
        assert "Overall Risk" in rendered
        assert "HIGH" in rendered
        assert "Run system commands" in rendered
        assert "demo.py:4" in rendered
        assert "does not guarantee" in rendered


def test_reports_redact_secrets_and_markdown_keeps_evidence_as_code() -> None:
    secret = _OPENAI_KEY_FIXTURE
    report = _report()
    evidence = Evidence(
        path="bad`](/unexpected).py",
        line=4,
        snippet=f"```\n[open](https://example.invalid)\nOPENAI_API_KEY={secret}",
    )
    finding = report.findings[0].model_copy(update={"evidence": (evidence,)})
    report = report.model_copy(update={"findings": (finding,)})

    json_output = render_json(report)
    markdown = render_markdown(report)

    assert secret not in json_output
    assert secret not in markdown
    assert "<code>bad`](/unexpected).py:4</code>" in markdown
    assert "    [open](https://example.invalid)" in markdown


def test_partial_reports_do_not_present_zero_score_as_overall_risk(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "broken.sh").write_bytes(b"\x81fixture")
    report = scan_target(tmp_path)
    console = Console(record=True, width=120, color_system=None)

    render_terminal(report, console=console)
    markdown = render_markdown(report)
    terminal = console.export_text()

    for output in (markdown, terminal):
        assert "Scan incomplete" in output
        assert "broken.sh" in output
        assert "cannot be decoded as supported" in output
        assert "Overall Risk" not in output
        assert "scanned files only" in output
        assert "UNKNOWN" in output

    data = json.loads(render_json(report))
    assert data["coverage"]["status"] == "partial"
    assert data["coverage"]["skipped_count"] == 1


def test_skipped_paths_are_redacted_and_rendered_as_data() -> None:
    path = f"{_OPENAI_KEY_FIXTURE}/[red]<tag>|.sh"
    coverage = ScanCoverage(
        status="partial",
        skipped_count=1,
        skipped_paths=(SkippedPath(path=path, reason=SkipReason.UNREADABLE),),
    )
    report = _report().model_copy(update={"coverage": coverage})
    console = Console(record=True, width=160, color_system=None)

    render_terminal(report, console=console)
    markdown = render_markdown(report)
    terminal = console.export_text()

    for output in (render_json(report), markdown, terminal):
        assert _OPENAI_KEY_FIXTURE not in output
        assert "sk-****...3456" in output
    assert "[red]<tag>|.sh" in terminal
    assert "[red]&lt;tag&gt;&#124;.sh" in markdown
