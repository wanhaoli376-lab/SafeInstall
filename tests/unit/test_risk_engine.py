from safeinstall.models import Capability, Evidence, Finding, Severity
from safeinstall.risk.engine import RiskEngine


def _finding(
    *, rule_id: str, name: str, category: str, capability: Capability, line: int
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name=name,
        description=f"Observed {name.lower()}.",
        severity=Severity.LOW,
        category=category,
        language="python",
        explanation="This capability is not necessarily malicious on its own.",
        recommendation="Review how this behavior is used.",
        evidence=(Evidence(path="app.py", line=line, snippet=name),),
        capabilities=(capability,),
    )


def test_risk_engine_escalates_environment_read_plus_unknown_post() -> None:
    findings = (
        _finding(
            rule_id="SI-PY-020",
            name="Environment variable read",
            category="environment_access",
            capability=Capability.ENVIRONMENT_READ,
            line=4,
        ),
        _finding(
            rule_id="SI-PY-021",
            name="HTTP POST to unknown domain",
            category="network_access",
            capability=Capability.NETWORK_ACCESS,
            line=8,
        ).model_copy(update={"metadata": {"method": "POST", "destination": "unknown"}}),
    )

    assessment = RiskEngine().assess(findings)

    assert assessment.level is Severity.HIGH
    assert assessment.capabilities.enabled(Capability.ENVIRONMENT_READ)
    assert assessment.capabilities.enabled(Capability.NETWORK_ACCESS)
    assert any(
        "environment" in reason.lower() and "network" in reason.lower()
        for reason in assessment.primary_reasons
    )


def test_repeated_low_findings_do_not_become_high_by_count_alone() -> None:
    findings = tuple(
        _finding(
            rule_id="SI-PY-030",
            name="Network capability",
            category="network_access",
            capability=Capability.NETWORK_ACCESS,
            line=line,
        )
        for line in range(1, 11)
    )

    assessment = RiskEngine().assess(findings)

    assert assessment.level is Severity.LOW
    assert assessment.score < 20
