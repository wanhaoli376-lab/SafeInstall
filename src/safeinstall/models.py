"""Shared, serializable models for findings and scan reports."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MAX_RECORDED_SKIPS = 100

RuleId = Annotated[
    str,
    StringConstraints(pattern=r"^SI-[A-Z0-9]+(?:-[A-Z0-9]+)+$", min_length=7, max_length=64),
]
CategoryName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_]*$", min_length=2, max_length=64),
]
LanguageName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_-]*$", min_length=1, max_length=32),
]


class Severity(StrEnum):
    """Normalized severity labels used by rules, findings, and reports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Capability(StrEnum):
    """Observable abilities a target may exercise if it is run."""

    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    FILE_DELETE = "file_delete"
    CODE_EXECUTION = "code_execution"
    SHELL_EXECUTION = "shell_execution"
    NETWORK_ACCESS = "network_access"
    ENVIRONMENT_READ = "environment_read"
    GIT_OPERATIONS = "git_operations"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DOWNLOAD_EXECUTE = "download_execute"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"


class FindingConfidence(StrEnum):
    """Distinguishes directly observed facts from contextual inference."""

    OBSERVED = "observed"
    INFERRED = "inferred"


class TargetKind(StrEnum):
    """Origin type used in reports and loader selection."""

    LOCAL = "local"
    ARCHIVE = "archive"
    GITHUB = "github"


class SourceFile(BaseModel):
    """An untrusted text file presented to scanners without executing it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4096)
    language: LanguageName
    content: str = Field(repr=False)

    def line(self, number: int) -> str:
        lines = self.content.splitlines()
        if 1 <= number <= len(lines):
            return lines[number - 1]
        return ""


class Evidence(BaseModel):
    """A source location supporting a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4096)
    line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = Field(default=None, max_length=500)


class Finding(BaseModel):
    """A fact or bounded inference produced by a scanner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: RuleId
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=2_000)
    severity: Severity
    category: CategoryName
    language: LanguageName
    explanation: str = Field(min_length=1, max_length=4_000)
    recommendation: str = Field(min_length=1, max_length=4_000)
    evidence: tuple[Evidence, ...] = Field(min_length=1)
    capabilities: tuple[Capability, ...] = ()
    confidence: FindingConfidence = FindingConfidence.OBSERVED
    metadata: dict[str, Any] = Field(default_factory=dict)


class CapabilitySummary(BaseModel):
    """Stable capability view derived from evidence-backed findings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed: tuple[Capability, ...] = ()

    def enabled(self, capability: Capability) -> bool:
        return capability in self.observed

    def as_mapping(self) -> dict[str, bool]:
        return {capability.value: self.enabled(capability) for capability in Capability}


class RiskAssessment(BaseModel):
    """Explainable overall risk computed from findings and behavior combinations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    level: Severity
    score: int = Field(ge=0, le=100)
    primary_reasons: tuple[str, ...] = Field(max_length=5)
    capabilities: CapabilitySummary


class DependencyRecord(BaseModel):
    """A dependency declared by a supported package manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=512)
    specifier: str = Field(min_length=1, max_length=2_000)
    ecosystem: str = Field(min_length=1, max_length=32)
    scope: str = Field(min_length=1, max_length=64)
    source_file: str = Field(min_length=1, max_length=4096)
    pinned: bool
    source_type: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=32)


class ManifestAnalysis(BaseModel):
    """Dependencies and evidence-backed risks from one manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dependencies: tuple[DependencyRecord, ...] = ()
    findings: tuple[Finding, ...] = ()


class AIAnalysisResult(BaseModel):
    """Optional model-generated explanation, never used as a security boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=4_000)
    top_risks: tuple[str, ...] = Field(max_length=5)
    review_notes: tuple[str, ...] = Field(max_length=10)
    sent_findings: int = Field(ge=0, le=20)
    sent_prompt_files: int = Field(ge=0, le=3)


class TargetSummary(BaseModel):
    """Stable target identity and scan timing for reports."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(min_length=1, max_length=4096)
    display_name: str = Field(min_length=1, max_length=512)
    kind: TargetKind
    files_scanned: int = Field(ge=0)
    scan_started_at: datetime
    scan_duration_ms: int = Field(ge=0)
    metadata: dict[str, str] = Field(default_factory=dict)


class SkipReason(StrEnum):
    """Stable reasons why a supported path could not be inspected."""

    FILE_TOO_LARGE = "file_too_large"
    UNDECODABLE_TEXT = "undecodable_text"
    UNREADABLE = "unreadable"
    UNSAFE_PATH = "unsafe_path"


class SkippedPath(BaseModel):
    """A relative file or directory omitted from supported-source analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4096)
    reason: SkipReason


class ScanCoverage(BaseModel):
    """Coverage of supported paths outside configured directory exclusions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["complete", "partial"] = "complete"
    skipped_count: int = Field(default=0, ge=0)
    skipped_paths: tuple[SkippedPath, ...] = Field(default=(), max_length=MAX_RECORDED_SKIPS)

    @model_validator(mode="after")
    def consistent_status(self) -> Self:
        if (self.status == "partial") != (self.skipped_count > 0):
            raise ValueError("Coverage status must agree with the skipped path count.")
        if len(self.skipped_paths) != min(self.skipped_count, MAX_RECORDED_SKIPS):
            raise ValueError("Coverage must include bounded details for skipped paths.")
        return self


class ScanReport(BaseModel):
    """Complete, serializable result returned by the public scan interface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.1"
    safeinstall_version: str
    target: TargetSummary
    risk: RiskAssessment
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    findings: tuple[Finding, ...] = ()
    dependencies: tuple[DependencyRecord, ...] = ()
    ai_analysis: AIAnalysisResult | None = None
    analysis_scope: tuple[str, ...] = ()
    disclaimer: str
