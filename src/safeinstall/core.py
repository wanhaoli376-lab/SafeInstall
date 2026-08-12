"""Public scan orchestration seam."""

from __future__ import annotations

import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TypeVar
from urllib.parse import urlsplit

from safeinstall import __version__
from safeinstall.analysis.ai_analysis import OpenAIAnalyzer
from safeinstall.analysis.behavior import PythonBehaviorScanner
from safeinstall.analysis.permissions import SensitivePathScanner
from safeinstall.config import ScanConfig
from safeinstall.constants import ANALYSIS_SCOPE, DISCLAIMER
from safeinstall.exceptions import InputError
from safeinstall.loaders.archive import ArchiveLoader
from safeinstall.loaders.base import LoadedTarget, TargetLoader
from safeinstall.loaders.discovery import FileDiscoverer
from safeinstall.loaders.github import GitHubLoader
from safeinstall.loaders.local import LocalLoader
from safeinstall.models import (
    AIAnalysisResult,
    DependencyRecord,
    Finding,
    ScanReport,
    SourceFile,
    TargetKind,
    TargetSummary,
)
from safeinstall.plugins.registry import PluginRegistry
from safeinstall.redaction import redact_text
from safeinstall.risk.engine import RiskEngine
from safeinstall.risk.scoring import SEVERITY_RANK
from safeinstall.scanners.ai_components import AIComponentScanner
from safeinstall.scanners.base import Scanner
from safeinstall.scanners.batch import BatchScanner
from safeinstall.scanners.dependencies import DependencyScanner
from safeinstall.scanners.github_actions import GitHubActionsScanner
from safeinstall.scanners.javascript import JavaScriptScanner
from safeinstall.scanners.powershell import PowerShellScanner
from safeinstall.scanners.prompt_injection import PromptInjectionScanner
from safeinstall.scanners.python import PythonScanner
from safeinstall.scanners.secrets import SecretScanner
from safeinstall.scanners.shell import ShellScanner
from safeinstall.scanners.supply_chain import SupplyChainScanner

MAX_TOTAL_FINDINGS = 10_000
MAX_TOTAL_DEPENDENCIES = 50_000
T = TypeVar("T")


class AIAnalyzer(Protocol):
    def analyze(
        self,
        findings: Iterable[Finding],
        *,
        prompt_sources: Iterable[SourceFile] = (),
    ) -> AIAnalysisResult:
        """Return optional explanatory analysis for redacted local evidence."""


def scan_target(
    target: str | Path,
    *,
    ai: bool = False,
    ai_model: str | None = None,
    plugin_registry: PluginRegistry | None = None,
    ai_analyzer: AIAnalyzer | None = None,
) -> ScanReport:
    """Statically analyze a local path, archive, or public GitHub repository.

    Target code is never executed or imported. AI analysis occurs only when ``ai=True``.
    """

    config_values: dict[str, object] = {"ai": ai}
    if ai_model is not None:
        config_values["ai_model"] = ai_model
    config = ScanConfig.model_validate(config_values)
    started_at = datetime.now(UTC)
    started_clock = time.perf_counter()
    target_text = str(target)
    loader = _select_loader(target_text)
    discoverer = FileDiscoverer()

    with loader.open(target) as loaded:
        sources = discoverer.discover(loaded)
        target_identity = _target_identity(loaded, sources, started_at)

    findings, dependencies = _scan_sources(
        sources,
        plugin_registry=plugin_registry or PluginRegistry(),
    )
    risk = RiskEngine().assess(findings)
    ai_result = None
    if config.ai:
        analyzer = ai_analyzer or OpenAIAnalyzer(model=config.ai_model)
        prompt_scanner = PromptInjectionScanner()
        prompt_sources = tuple(source for source in sources if prompt_scanner.supports(source))
        ai_result = analyzer.analyze(findings, prompt_sources=prompt_sources)

    duration_ms = max(0, round((time.perf_counter() - started_clock) * 1000))
    summary = target_identity.model_copy(update={"scan_duration_ms": duration_ms})
    return ScanReport(
        safeinstall_version=__version__,
        target=summary,
        risk=risk,
        findings=findings,
        dependencies=dependencies,
        ai_analysis=ai_result,
        analysis_scope=ANALYSIS_SCOPE,
        disclaimer=DISCLAIMER,
    )


def _select_loader(target: str) -> TargetLoader:
    try:
        parsed = urlsplit(target)
    except ValueError as exc:
        raise InputError("Target is not a valid local path or URL.") from exc
    if parsed.scheme.casefold() in {"http", "https"}:
        return GitHubLoader()
    if parsed.scheme and len(parsed.scheme) > 1:
        raise InputError("Only local paths and public HTTPS GitHub URLs are supported.")
    path = Path(target).expanduser()
    if path.is_file() and ArchiveLoader().supports(path.name):
        return ArchiveLoader()
    return LocalLoader()


def _scan_sources(
    sources: tuple[SourceFile, ...],
    *,
    plugin_registry: PluginRegistry,
) -> tuple[tuple[Finding, ...], tuple[DependencyRecord, ...]]:
    scanners: tuple[Scanner, ...] = (
        SecretScanner(),
        PythonScanner(),
        PythonBehaviorScanner(),
        SensitivePathScanner(),
        ShellScanner(),
        JavaScriptScanner(),
        PowerShellScanner(),
        BatchScanner(),
        GitHubActionsScanner(),
        PromptInjectionScanner(),
        AIComponentScanner(),
        SupplyChainScanner(),
    )
    dependency_scanner = DependencyScanner()
    findings: list[Finding] = []
    dependencies: list[DependencyRecord] = []
    for source in sources:
        for scanner in scanners:
            if scanner.supports(source):
                _extend_bounded(
                    findings,
                    scanner.scan(source),
                    limit=MAX_TOTAL_FINDINGS,
                    label="findings",
                )
        if dependency_scanner.supports(source):
            manifest = dependency_scanner.analyze(source)
            _extend_bounded(
                findings,
                manifest.findings,
                limit=MAX_TOTAL_FINDINGS,
                label="findings",
            )
            _extend_bounded(
                dependencies,
                manifest.dependencies,
                limit=MAX_TOTAL_DEPENDENCIES,
                label="dependencies",
            )
        _extend_bounded(
            findings,
            plugin_registry.scan(source),
            limit=MAX_TOTAL_FINDINGS,
            label="findings",
        )

    unique_findings = {
        (
            finding.rule_id,
            finding.evidence[0].path,
            finding.evidence[0].line,
            finding.name,
        ): finding
        for finding in findings
    }
    ordered_findings = tuple(
        sorted(
            unique_findings.values(),
            key=lambda finding: (
                -SEVERITY_RANK[finding.severity],
                finding.evidence[0].path.casefold(),
                finding.evidence[0].line or 0,
                finding.rule_id,
            ),
        )
    )
    ordered_dependencies = tuple(
        sorted(
            dependencies,
            key=lambda item: (
                item.ecosystem,
                item.name.casefold(),
                item.source_file,
                item.scope,
            ),
        )
    )
    return ordered_findings, ordered_dependencies


def _extend_bounded(
    destination: list[T],
    values: Iterable[T],
    *,
    limit: int,
    label: str,
) -> None:
    for value in values:
        if len(destination) >= limit:
            raise InputError(f"Target produced more {label} than the configured limit.")
        destination.append(value)


def _target_identity(
    loaded: LoadedTarget,
    sources: tuple[SourceFile, ...],
    started_at: datetime,
) -> TargetSummary:
    metadata = {key: redact_text(value) for key, value in loaded.metadata.items()}
    if loaded.kind is TargetKind.GITHUB:
        display_name = metadata.get("repository", loaded.source)
    else:
        display_name = Path(loaded.source).name or loaded.source
    return TargetSummary(
        source=redact_text(loaded.source),
        display_name=redact_text(display_name),
        kind=loaded.kind,
        files_scanned=len(sources),
        scan_started_at=started_at,
        scan_duration_ms=0,
        metadata=metadata,
    )
