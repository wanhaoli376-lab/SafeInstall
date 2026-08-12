"""Structured static analysis for GitHub Actions workflows."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from safeinstall.exceptions import ParseLimitError
from safeinstall.models import Capability, Evidence, Finding, Severity, SourceFile
from safeinstall.redaction import redact_text
from safeinstall.safe_parsing import load_basic_yaml

MAX_FINDINGS_PER_FILE = 1_000


@dataclass(frozen=True, slots=True)
class _WorkflowRisk:
    line: int
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: str
    explanation: str
    recommendation: str
    capabilities: tuple[Capability, ...] = ()
    metadata: dict[str, str] | None = None


class GitHubActionsScanner:
    """Analyze workflow data without running actions, expressions, or shell steps."""

    def supports(self, source: SourceFile) -> bool:
        return source.language == "github-actions"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            document = load_basic_yaml(source.content)
        except ParseLimitError:
            return ()
        if not isinstance(document, Mapping):
            return ()

        risks: list[_WorkflowRisk] = []
        triggers = document.get("on")
        if triggers == "pull_request_target" or (
            isinstance(triggers, Mapping) and "pull_request_target" in triggers
        ):
            risks.append(
                _risk(
                    source,
                    "pull_request_target",
                    rule_id="SI-GHA-001",
                    name="Privileged pull request trigger",
                    description="The workflow uses pull_request_target.",
                    severity=Severity.HIGH,
                    category="workflow_privilege",
                    explanation=(
                        "This trigger runs in the base repository context and can access more "
                        "privileges than a normal pull_request workflow."
                    ),
                    recommendation=(
                        "Do not check out or execute untrusted pull request code in this workflow."
                    ),
                    capabilities=(Capability.PRIVILEGE_ESCALATION,),
                )
            )

        for mapping in _all_mappings(document):
            if len(risks) >= MAX_FINDINGS_PER_FILE:
                break
            permissions = mapping.get("permissions")
            if permissions == "write-all":
                risks.append(
                    _risk(
                        source,
                        "permissions: write-all",
                        rule_id="SI-GHA-002",
                        name="Workflow grants write-all permissions",
                        description=(
                            "The workflow grants write access to all available token scopes."
                        ),
                        severity=Severity.HIGH,
                        category="workflow_permission",
                        explanation=(
                            "A compromised step could use the workflow token to modify repository "
                            "resources across several scopes."
                        ),
                        recommendation=(
                            "Grant only the specific read or write scopes each job needs."
                        ),
                        capabilities=(Capability.PRIVILEGE_ESCALATION,),
                    )
                )

            uses = mapping.get("uses")
            if isinstance(uses, str):
                risks.extend(_analyze_action_reference(source, uses))

            run = mapping.get("run")
            if isinstance(run, str):
                risks.append(
                    _risk(
                        source,
                        "run:",
                        value_hint=run,
                        rule_id="SI-GHA-009",
                        name="Workflow shell step",
                        description="The workflow executes a shell command step.",
                        severity=Severity.INFO,
                        category="command_execution",
                        explanation=(
                            "Workflow run steps execute commands on a runner. This is normal, "
                            "but the command and any values inserted into it are part of the "
                            "workflow trust boundary."
                        ),
                        recommendation=(
                            "Review the command, its inputs, and the permissions available to "
                            "the job."
                        ),
                        capabilities=(Capability.SHELL_EXECUTION,),
                    )
                )
                if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:bash|sh)\b", run):
                    risks.append(
                        _risk(
                            source,
                            "run:",
                            value_hint=run,
                            rule_id="SI-GHA-005",
                            name="Workflow downloads and executes a script",
                            description=(
                                "A workflow shell step pipes a network download to a shell."
                            ),
                            severity=Severity.HIGH,
                            category="download_and_execute",
                            explanation=(
                                "The downloaded response is executed immediately, so a changed or "
                                "compromised server response can become workflow code."
                            ),
                            recommendation=(
                                "Pin, download, verify, and then execute a reviewed script."
                            ),
                            capabilities=(
                                Capability.NETWORK_ACCESS,
                                Capability.DOWNLOAD_EXECUTE,
                                Capability.SHELL_EXECUTION,
                            ),
                        )
                    )
                if re.search(r"\$\{\{\s*github\.event\.pull_request\.", run):
                    risks.append(
                        _risk(
                            source,
                            "run:",
                            value_hint=run,
                            rule_id="SI-GHA-006",
                            name="Untrusted pull request data in shell step",
                            description="A shell command directly embeds pull request event data.",
                            severity=Severity.HIGH,
                            category="command_injection",
                            explanation=(
                                "Pull request fields can be controlled by a contributor. Embedding "
                                "them directly in shell text may let special characters change the "
                                "command."
                            ),
                            recommendation=(
                                "Pass untrusted values through an environment variable and "
                                "quote them for the selected shell."
                            ),
                            capabilities=(Capability.SHELL_EXECUTION,),
                        )
                    )

        for value in _all_strings(document):
            if len(risks) >= MAX_FINDINGS_PER_FILE:
                break
            if re.search(r"\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}", value):
                risks.append(
                    _risk(
                        source,
                        "secrets.",
                        value_hint=value,
                        rule_id="SI-GHA-007",
                        name="Workflow secret access",
                        description="The workflow reads a repository or organization secret.",
                        severity=Severity.MEDIUM,
                        category="sensitive_data_access",
                        explanation=(
                            "Secret access is common in deployment workflows. Every step "
                            "receiving a secret becomes part of the trust boundary."
                        ),
                        recommendation=(
                            "Limit secret exposure to pinned, trusted steps that need it."
                        ),
                        capabilities=(Capability.SENSITIVE_DATA_ACCESS,),
                    )
                )

        unique = {
            (risk.rule_id, risk.line, tuple(sorted((risk.metadata or {}).items()))): risk
            for risk in risks
        }
        ordered = sorted(unique.values(), key=lambda risk: (risk.line, risk.rule_id))[
            :MAX_FINDINGS_PER_FILE
        ]
        return tuple(_to_finding(source, risk) for risk in ordered)


def _analyze_action_reference(source: SourceFile, uses: str) -> list[_WorkflowRisk]:
    if uses.startswith(("./", "docker://")) or "@" not in uses:
        return []
    action, reference = uses.rsplit("@", 1)
    owner = action.split("/", 1)[0].casefold()
    risks: list[_WorkflowRisk] = []
    if owner not in {"actions", "github"}:
        risks.append(
            _risk(
                source,
                "uses:",
                value_hint=uses,
                rule_id="SI-GHA-003",
                name="Third-party GitHub Action",
                description=f"The workflow uses the third-party action {action}.",
                severity=Severity.INFO,
                category="third_party_action",
                explanation=(
                    "Third-party actions execute code in the workflow. This is expected in many "
                    "projects, but the action becomes part of the supply chain."
                ),
                recommendation="Review the action source, publisher, and requested permissions.",
                metadata={"action": action, "reference": reference},
            )
        )
    if re.fullmatch(r"[0-9a-fA-F]{40}", reference) is None:
        risks.append(
            _risk(
                source,
                "uses:",
                value_hint=uses,
                rule_id="SI-GHA-004",
                name="GitHub Action is not commit-pinned",
                description=f"{uses} uses a tag or branch instead of a full commit hash.",
                severity=Severity.MEDIUM,
                category="supply_chain",
                explanation=(
                    "A tag or branch can point to different code later. This is a "
                    "supply-chain risk, not automatically a vulnerability."
                ),
                recommendation="Pin the action to a reviewed 40-character commit hash.",
                metadata={"action": action, "reference": reference},
            )
        )
    artifact_operation = {
        "actions/download-artifact": ("download", Capability.FILESYSTEM_WRITE),
        "actions/upload-artifact": ("upload", Capability.FILESYSTEM_READ),
    }.get(action.casefold())
    if artifact_operation is not None:
        operation, capability = artifact_operation
        risks.append(
            _risk(
                source,
                "uses:",
                value_hint=uses,
                rule_id="SI-GHA-008",
                name=f"Workflow artifact {operation}",
                description=f"The workflow uses the official artifact {operation} action.",
                severity=Severity.INFO,
                category="artifact_handling",
                explanation=(
                    "Artifacts move files between jobs or workflow runs. Their contents and "
                    "origin need review before another step trusts or executes them."
                ),
                recommendation=(
                    "Constrain artifact names and paths, preserve provenance, and do not execute "
                    "untrusted artifact content."
                ),
                capabilities=(capability,),
                metadata={"action": action, "reference": reference, "operation": operation},
            )
        )
    return risks


def _risk(
    source: SourceFile,
    needle: str,
    *,
    value_hint: str | None = None,
    **values: object,
) -> _WorkflowRisk:
    line = _find_line(source.content, needle, value_hint=value_hint)
    return _WorkflowRisk(line=line, **values)  # type: ignore[arg-type]


def _find_line(content: str, needle: str, *, value_hint: str | None = None) -> int:
    hint_lines = (value_hint or "").strip().splitlines()
    hint = hint_lines[0][:80] if hint_lines else ""
    lines = content.splitlines()
    if hint:
        for number, line in enumerate(lines, start=1):
            if hint in line:
                return number
    for number, line in enumerate(lines, start=1):
        if needle in line:
            return number
    return 1


def _all_mappings(value: Any) -> Iterator[Mapping[str, Any]]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            yield current
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _all_strings(value: Any) -> Iterator[str]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _to_finding(source: SourceFile, risk: _WorkflowRisk) -> Finding:
    return Finding(
        rule_id=risk.rule_id,
        name=risk.name,
        description=risk.description,
        severity=risk.severity,
        category=risk.category,
        language="github-actions",
        explanation=risk.explanation,
        recommendation=risk.recommendation,
        evidence=(
            Evidence(
                path=source.path,
                line=risk.line,
                snippet=redact_text(source.line(risk.line).strip())[:500],
            ),
        ),
        capabilities=risk.capabilities,
        metadata=risk.metadata or {},
    )
