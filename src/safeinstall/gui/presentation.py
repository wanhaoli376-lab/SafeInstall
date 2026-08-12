"""Translate stable scan reports into an ordinary-user desktop view."""

from __future__ import annotations

from dataclasses import dataclass

from safeinstall.gui.i18n import Catalog
from safeinstall.models import Capability, ScanReport, Severity
from safeinstall.redaction import redact_text
from safeinstall.report.common import location

BUILTIN_FINDING_CATEGORIES = frozenset(
    {
        "ai_component",
        "ai_component_capability",
        "artifact_handling",
        "command_execution",
        "command_injection",
        "destructive_file_operation",
        "download_and_execute",
        "dynamic_code_execution",
        "environment_access",
        "filesystem_read",
        "filesystem_write",
        "git_operation",
        "hidden_execution",
        "install_script",
        "mcp_capability",
        "network_access",
        "network_service_hint",
        "network_upload",
        "obfuscated_execution",
        "permission_change",
        "persistence",
        "privilege_escalation",
        "prompt_injection",
        "remote_access",
        "remote_download",
        "secret_exposure",
        "security_bypass",
        "sensitive_data_access",
        "sensitive_file",
        "sensitive_filesystem_access",
        "supply_chain",
        "system_configuration",
        "third_party_action",
        "unsafe_deserialization",
        "workflow_permission",
        "workflow_privilege",
    }
)


@dataclass(frozen=True, slots=True)
class CapabilityItem:
    capability: Capability
    label: str
    observed: bool
    value: str


@dataclass(frozen=True, slots=True)
class TopFinding:
    rule_id: str
    name: str
    technical_name: str
    severity: Severity
    severity_label: str
    location: str


@dataclass(frozen=True, slots=True)
class AIPresentation:
    model: str
    summary: str
    top_risks: tuple[str, ...]
    review_notes: tuple[str, ...]
    sent_context: str


@dataclass(frozen=True, slots=True)
class ResultPresentation:
    target_name: str
    risk_level: Severity
    risk_label: str
    capabilities: tuple[CapabilityItem, ...]
    behaviors: tuple[str, ...]
    bounded_checks: tuple[str, ...]
    top_findings: tuple[TopFinding, ...]
    why: str
    recommendation: str
    files_scanned: int
    dependencies: int
    duration_ms: int
    ai: AIPresentation | None


def present_report(report: ScanReport, catalog: Catalog) -> ResultPresentation:
    """Build localized overview text while preserving the technical report unchanged."""

    display_level = Severity.LOW if report.risk.level is Severity.INFO else report.risk.level
    observed = set(report.risk.capabilities.observed)
    capabilities = tuple(
        CapabilityItem(
            capability=capability,
            label=catalog.text(f"capability.{capability.value}"),
            observed=capability in observed,
            value=catalog.text("common.yes" if capability in observed else "common.no"),
        )
        for capability in Capability
    )
    behaviors = tuple(item.label for item in capabilities if item.observed)
    if not behaviors:
        behaviors = (catalog.text("result.no_high_impact_capability"),)

    finding_categories = {finding.category for finding in report.findings}
    bounded_checks: list[str] = []
    if Capability.PERSISTENCE not in observed:
        bounded_checks.append(catalog.text("result.no_persistence"))
    if "secret_exposure" not in finding_categories:
        bounded_checks.append(catalog.text("result.no_secret_pattern"))
    if not finding_categories.intersection({"workflow_permission", "workflow_privilege"}):
        bounded_checks.append(catalog.text("result.no_workflow_permission_pattern"))

    top_findings = tuple(
        TopFinding(
            rule_id=finding.rule_id,
            name=catalog.text(f"category.{finding.category}")
            if catalog.has(f"category.{finding.category}")
            else redact_text(finding.name),
            technical_name=redact_text(finding.name),
            severity=finding.severity,
            severity_label=catalog.text(f"risk.{finding.severity.value}"),
            location=redact_text(location(finding.evidence[0].path, finding.evidence[0].line)),
        )
        for finding in report.findings[:5]
    )
    return ResultPresentation(
        target_name=redact_text(report.target.display_name),
        risk_level=display_level,
        risk_label=(
            f"{display_level.value.upper()} · {catalog.text(f'risk.{display_level.value}')}"
        ),
        capabilities=capabilities,
        behaviors=behaviors,
        bounded_checks=tuple(bounded_checks),
        top_findings=top_findings,
        why=_why(report, catalog),
        recommendation=catalog.text(f"advice.{display_level.value}"),
        files_scanned=report.target.files_scanned,
        dependencies=len(report.dependencies),
        duration_ms=report.target.scan_duration_ms,
        ai=_present_ai(report, catalog),
    )


def _present_ai(report: ScanReport, catalog: Catalog) -> AIPresentation | None:
    analysis = report.ai_analysis
    if analysis is None:
        return None
    findings_key = "result.ai_findings.one" if analysis.sent_findings == 1 else "result.ai_findings"
    prompts_key = (
        "result.ai_prompts.one" if analysis.sent_prompt_files == 1 else "result.ai_prompts"
    )
    return AIPresentation(
        model=redact_text(analysis.model),
        summary=redact_text(analysis.summary),
        top_risks=tuple(redact_text(item) for item in analysis.top_risks),
        review_notes=tuple(redact_text(item) for item in analysis.review_notes),
        sent_context=catalog.text(
            "result.ai_context",
            findings=catalog.text(findings_key, count=analysis.sent_findings),
            prompt_files=catalog.text(prompts_key, count=analysis.sent_prompt_files),
        ),
    )


def _why(report: ScanReport, catalog: Catalog) -> str:
    capabilities = set(report.risk.capabilities.observed)
    if Capability.DOWNLOAD_EXECUTE in capabilities:
        key = "why.download_execute"
    elif Capability.SHELL_EXECUTION in capabilities:
        key = "why.shell"
    elif Capability.SENSITIVE_DATA_ACCESS in capabilities:
        key = "why.sensitive"
    elif report.findings:
        key = "why.findings"
    else:
        key = "why.quiet"
    return catalog.text(key)
