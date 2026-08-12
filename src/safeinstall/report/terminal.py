"""Human-readable Rich terminal report renderer."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from safeinstall.models import Capability, FindingConfidence, ScanReport
from safeinstall.redaction import redact_text
from safeinstall.report.common import (
    CAPABILITY_LABELS,
    SEVERITY_STYLE,
    location,
    recommendation_for,
    why_this_matters,
)

MAX_TERMINAL_FINDINGS = 100
MAX_TERMINAL_DEPENDENCIES = 100


def render_terminal(report: ScanReport, *, console: Console | None = None) -> None:
    output = console or Console()
    risk = Text(report.risk.level.value.upper(), style=SEVERITY_STYLE[report.risk.level])
    heading = Text("SafeInstall Report\n", style="bold")
    heading.append(f"{redact_text(report.target.display_name)}\n")
    heading.append("Static analysis only — target code was not executed.", style="dim")
    output.print(Panel(heading, border_style="blue"))
    output.print("Overall Risk: ", risk, f"  Score: {report.risk.score}/100")
    output.print()

    output.print("[bold]What this software may do[/bold]")
    if report.risk.capabilities.observed:
        for capability in report.risk.capabilities.observed:
            output.print(f"  [yellow]⚠[/yellow] {escape(CAPABILITY_LABELS[capability])}")
    else:
        output.print("  No supported high-impact capability was observed.", style="green")

    output.print()
    output.print("[bold]Why this matters[/bold]")
    output.print(escape(redact_text(why_this_matters(report))))
    if report.risk.primary_reasons:
        output.print()
        output.print("[bold]Primary reasons[/bold]")
        for index, reason in enumerate(report.risk.primary_reasons, start=1):
            output.print(f"  {index}. {escape(redact_text(reason))}")

    output.print()
    output.print(Panel(escape(redact_text(recommendation_for(report))), title="Recommendation"))

    capabilities = Table(title="Capabilities", show_lines=False)
    capabilities.add_column("Capability")
    capabilities.add_column("Observed", justify="center")
    for capability in Capability:
        observed = report.risk.capabilities.enabled(capability)
        capabilities.add_row(
            CAPABILITY_LABELS[capability],
            "[bold red]YES[/bold red]" if observed else "[dim]NO[/dim]",
        )
    output.print(capabilities)

    details = Table(title="Technical Details", show_lines=True)
    details.add_column("Severity", no_wrap=True)
    details.add_column("Basis", no_wrap=True)
    details.add_column("Rule", no_wrap=True)
    details.add_column("Location")
    details.add_column("Finding")
    for finding in report.findings[:MAX_TERMINAL_FINDINGS]:
        evidence = finding.evidence[0]
        basis = "Fact" if finding.confidence is FindingConfidence.OBSERVED else "Inference"
        details.add_row(
            Text(
                finding.severity.value.upper(),
                style=SEVERITY_STYLE[finding.severity],
            ),
            basis,
            finding.rule_id,
            Text(redact_text(location(evidence.path, evidence.line))),
            Text(redact_text(finding.name)),
        )
    if report.findings:
        output.print(details)
        if len(report.findings) > MAX_TERMINAL_FINDINGS:
            output.print(
                f"[dim]{len(report.findings) - MAX_TERMINAL_FINDINGS} additional findings "
                "are available with --format json.[/dim]"
            )
    else:
        output.print(Panel("No supported risk pattern was found.", title="Technical Details"))

    if report.dependencies:
        dependency_table = Table(title="Dependencies")
        dependency_table.add_column("Ecosystem")
        dependency_table.add_column("Name")
        dependency_table.add_column("Specifier")
        dependency_table.add_column("Pinned")
        for dependency in report.dependencies[:MAX_TERMINAL_DEPENDENCIES]:
            dependency_table.add_row(
                Text(redact_text(dependency.ecosystem)),
                Text(redact_text(dependency.name)),
                Text(redact_text(dependency.specifier)),
                "YES" if dependency.pinned else "NO",
            )
        output.print(dependency_table)
        if len(report.dependencies) > MAX_TERMINAL_DEPENDENCIES:
            output.print(
                f"[dim]{len(report.dependencies) - MAX_TERMINAL_DEPENDENCIES} additional "
                "dependencies are available with --format json.[/dim]"
            )

    if report.ai_analysis is not None:
        ai_lines = [redact_text(report.ai_analysis.summary)]
        ai_lines.extend(f"• {redact_text(item)}" for item in report.ai_analysis.top_risks)
        ai_lines.extend(
            f"• Review: {redact_text(item)}" for item in report.ai_analysis.review_notes
        )
        ai_lines.append(
            f"Sent {report.ai_analysis.sent_findings} redacted findings and "
            f"{report.ai_analysis.sent_prompt_files} bounded prompt files."
        )
        output.print(Panel(Text("\n".join(ai_lines)), title="Optional AI Analysis"))

    output.print()
    output.print(escape(redact_text(report.disclaimer)), style="dim")
