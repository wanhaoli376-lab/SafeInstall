"""Risk scoring based on severity, distinct capabilities, and behavior chains."""

from __future__ import annotations

from collections.abc import Iterable

from safeinstall.models import (
    Capability,
    CapabilitySummary,
    Finding,
    RiskAssessment,
    Severity,
)
from safeinstall.risk.scoring import BASE_SCORE, SEVERITY_RANK, level_for_score


class RiskEngine:
    """Turn findings into a bounded score with plain-language reasons."""

    def assess(self, findings: Iterable[Finding]) -> RiskAssessment:
        finding_list = tuple(findings)
        observed = tuple(
            capability
            for capability in Capability
            if any(capability in finding.capabilities for finding in finding_list)
        )
        summary = CapabilitySummary(observed=observed)
        if not finding_list:
            return RiskAssessment(
                level=Severity.INFO,
                score=0,
                primary_reasons=(),
                capabilities=summary,
            )

        highest = max(finding_list, key=lambda item: SEVERITY_RANK[item.severity]).severity
        categories = {finding.category for finding in finding_list}
        score = BASE_SCORE[highest]
        score += min(15, max(0, len(categories) - 1) * 3)
        score += min(10, len(observed) * 2)

        reasons: list[str] = []
        score = self._apply_behavior_chains(finding_list, summary, score, reasons)
        reasons.extend(self._top_finding_reasons(finding_list))

        return RiskAssessment(
            level=level_for_score(min(100, score)),
            score=min(100, score),
            primary_reasons=tuple(dict.fromkeys(reasons))[:5],
            capabilities=summary,
        )

    def _apply_behavior_chains(
        self,
        findings: tuple[Finding, ...],
        summary: CapabilitySummary,
        score: int,
        reasons: list[str],
    ) -> int:
        unknown_post = any(
            str(finding.metadata.get("method", "")).upper() == "POST"
            and finding.metadata.get("destination") == "unknown"
            for finding in findings
        )
        if (
            summary.enabled(Capability.ENVIRONMENT_READ)
            and summary.enabled(Capability.NETWORK_ACCESS)
            and unknown_post
        ):
            score = max(55, score + 25)
            reasons.append(
                "Environment data is read and data can be sent to an unknown network destination."
            )

        if summary.enabled(Capability.DOWNLOAD_EXECUTE):
            # The concrete download-and-execute finding is already HIGH. Keep the
            # project at least HIGH without counting the same behavior twice.
            score = max(55, score)
            reasons.append("Downloaded content can be executed without a separate review step.")

        if _has_distinct_capability_evidence(
            findings,
            Capability.PRIVILEGE_ESCALATION,
            Capability.PERSISTENCE,
        ):
            score = max(65, score + 15)
            reasons.append("The software may combine elevated privileges with persistent changes.")

        return score

    def _top_finding_reasons(self, findings: tuple[Finding, ...]) -> list[str]:
        ordered = sorted(
            findings,
            key=lambda finding: (
                SEVERITY_RANK[finding.severity],
                finding.name.casefold(),
            ),
            reverse=True,
        )
        reasons: list[str] = []
        for finding in ordered:
            reason = f"{finding.severity.value.upper()}: {finding.name}."
            if reason not in reasons:
                reasons.append(reason)
        return reasons


def _has_distinct_capability_evidence(
    findings: tuple[Finding, ...],
    first: Capability,
    second: Capability,
) -> bool:
    first_evidence = {
        (finding.rule_id, finding.evidence[0].path, finding.evidence[0].line)
        for finding in findings
        if first in finding.capabilities
    }
    second_evidence = {
        (finding.rule_id, finding.evidence[0].path, finding.evidence[0].line)
        for finding in findings
        if second in finding.capabilities
    }
    return any(left != right for left in first_evidence for right in second_evidence)
