import pytest
from pydantic import ValidationError

from safeinstall.models import Capability, Severity
from safeinstall.rules.engine import RuleEngine
from safeinstall.rules.models import RuleDefinition
from safeinstall.rules.registry import RuleRegistry


def test_rule_engine_reports_matching_line_as_observed_evidence() -> None:
    rule = RuleDefinition(
        id="SI-PY-001",
        name="Unsafe shell execution",
        description="Detects shell=True in Python source.",
        severity=Severity.HIGH,
        category="command_execution",
        language="python",
        pattern=r"shell\s*=\s*True",
        explanation="The shell will interpret this command.",
        recommendation="Verify that no untrusted value reaches the command.",
        capabilities=(Capability.SHELL_EXECUTION,),
    )
    engine = RuleEngine(RuleRegistry([rule]))

    findings = engine.scan_text(
        "from subprocess import run\nrun('echo example', shell=True)\n",
        path="installer.py",
        language="python",
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SI-PY-001"
    assert findings[0].evidence[0].path == "installer.py"
    assert findings[0].evidence[0].line == 2
    assert findings[0].evidence[0].snippet == "run('echo example', shell=True)"


@pytest.mark.parametrize(
    "pattern",
    (
        r"(a+)+$",
        r"(a|aa)+$",
        r"(a)\1",
        r"a*a*",
    ),
)
def test_rule_definition_rejects_backtracking_prone_patterns(pattern: str) -> None:
    with pytest.raises(ValidationError, match="unsafe regular expression"):
        RuleDefinition(
            id="SI-PY-099",
            name="Unsafe fixture",
            description="A deliberately unsafe regular-expression fixture.",
            severity=Severity.LOW,
            category="test_fixture",
            language="python",
            pattern=pattern,
            explanation="This fixture must be rejected before scanning.",
            recommendation="Use a bounded pattern.",
        )
