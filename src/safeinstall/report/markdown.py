"""GitHub-ready Markdown report renderer."""

from __future__ import annotations

import html
import re

from safeinstall.models import Capability, FindingConfidence, ScanReport
from safeinstall.redaction import redact_text
from safeinstall.report.common import (
    CAPABILITY_LABELS,
    location,
    recommendation_for,
    why_this_matters,
)

MAX_MARKDOWN_FINDINGS = 500
MAX_MARKDOWN_DETAILS = 100
MAX_MARKDOWN_DEPENDENCIES = 500


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# SafeInstall Report",
        "",
        f"**Target:** {_code(report.target.display_name)}  ",
        f"**Target type:** {_code(report.target.kind.value)}  ",
        f"**Files scanned:** {report.target.files_scanned}  ",
        f"**Scan time:** {_code(report.target.scan_started_at.isoformat())}  ",
        "**Analysis mode:** Static analysis; target code was not executed.",
        "",
        "## Overall Risk",
        "",
        f"**{report.risk.level.value.upper()}** (score {report.risk.score}/100)",
        "",
        "## What this software may do",
        "",
    ]
    enabled = report.risk.capabilities.observed
    if enabled:
        lines.extend(f"- ⚠️ {CAPABILITY_LABELS[item]}" for item in enabled)
    else:
        lines.append("- No supported high-impact capability was observed.")

    lines.extend(["", "## Why this matters", "", why_this_matters(report)])
    if report.risk.primary_reasons:
        lines.extend(["", "### Primary reasons", ""])
        lines.extend(
            f"{index}. {_plain(reason)}"
            for index, reason in enumerate(report.risk.primary_reasons, start=1)
        )
    lines.extend(
        [
            "",
            "## Recommendation",
            "",
            recommendation_for(report),
            "",
            "## Capabilities",
            "",
            "| Capability | Observed |",
            "|---|---:|",
        ]
    )
    lines.extend(
        f"| {_table(CAPABILITY_LABELS[item])} | "
        f"{'YES' if report.risk.capabilities.enabled(item) else 'NO'} |"
        for item in Capability
    )

    lines.extend(["", "## Technical Details", ""])
    if not report.findings:
        lines.append("No supported risk pattern was found.")
    else:
        shown_findings = report.findings[:MAX_MARKDOWN_FINDINGS]
        lines.extend(
            [
                "| Severity | Basis | Rule | Location | Finding |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in shown_findings:
            evidence = finding.evidence[0]
            basis = "Observed" if finding.confidence is FindingConfidence.OBSERVED else "Inferred"
            lines.append(
                f"| {finding.severity.value.upper()} | {basis} | {_code(finding.rule_id)} | "
                f"{_code(location(evidence.path, evidence.line))} | "
                f"{_table(finding.name)} |"
            )
        if len(report.findings) > len(shown_findings):
            lines.extend(
                [
                    "",
                    f"_{len(report.findings) - len(shown_findings)} additional findings are "
                    "available in the JSON report._",
                ]
            )
        for finding in report.findings[:MAX_MARKDOWN_DETAILS]:
            evidence = finding.evidence[0]
            lines.extend(
                [
                    "",
                    f"### {finding.rule_id}: {_plain(finding.name)}",
                    "",
                    f"- **Severity:** {finding.severity.value.upper()}",
                    f"- **Evidence:** {_code(location(evidence.path, evidence.line))}",
                    f"- **Basis:** {finding.confidence.value}",
                    f"- **What was observed:** {_plain(finding.description)}",
                    f"- **Why it matters:** {_plain(finding.explanation)}",
                    f"- **Recommendation:** {_plain(finding.recommendation)}",
                ]
            )
            if evidence.snippet:
                lines.append("")
                lines.extend(f"    {line}" for line in redact_text(evidence.snippet).splitlines())

    if report.dependencies:
        lines.extend(
            [
                "",
                "## Dependencies",
                "",
                "| Ecosystem | Name | Specifier | Pinned | Source |",
                "|---|---|---|---:|---|",
            ]
        )
        shown_dependencies = report.dependencies[:MAX_MARKDOWN_DEPENDENCIES]
        for dependency in shown_dependencies:
            lines.append(
                f"| {_table(dependency.ecosystem)} | {_table(dependency.name)} | "
                f"{_code(dependency.specifier)} | "
                f"{'YES' if dependency.pinned else 'NO'} | "
                f"{_code(dependency.source_file)} |"
            )
        if len(report.dependencies) > len(shown_dependencies):
            lines.extend(
                [
                    "",
                    f"_{len(report.dependencies) - len(shown_dependencies)} additional "
                    "dependencies are available in the JSON report._",
                ]
            )

    if report.ai_analysis is not None:
        lines.extend(
            [
                "",
                "## Optional AI Analysis",
                "",
                f"**Model:** {_code(report.ai_analysis.model)}",
                "",
                _plain(report.ai_analysis.summary),
            ]
        )
        if report.ai_analysis.top_risks:
            lines.extend(["", "### AI-selected review priorities", ""])
            lines.extend(f"- {_plain(item)}" for item in report.ai_analysis.top_risks)
        if report.ai_analysis.review_notes:
            lines.extend(["", "### AI review notes", ""])
            lines.extend(f"- {_plain(item)}" for item in report.ai_analysis.review_notes)
        lines.extend(
            [
                "",
                f"Sent {report.ai_analysis.sent_findings} redacted findings and "
                f"{report.ai_analysis.sent_prompt_files} bounded prompt files to the API.",
            ]
        )

    lines.extend(["", "## Scope and limitations", ""])
    lines.extend(f"- {redact_text(item)}" for item in report.analysis_scope)
    lines.extend(["", f"> {redact_text(report.disclaimer)}", ""])
    return "\n".join(lines)


def _table(value: str) -> str:
    return _plain(value)


def _code(value: str) -> str:
    clean = redact_text(value).replace("\r", " ").replace("\n", " ")
    return f"<code>{html.escape(clean, quote=False)}</code>"


def _plain(value: str) -> str:
    clean = html.escape(redact_text(value), quote=False).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*{}\[\]<>()#+!|_+-])", r"\\\1", clean)
