from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.scanners.python import PythonScanner


def test_python_scanner_distinguishes_shell_true_from_plain_subprocess() -> None:
    source = SourceFile(
        path="tools/install.py",
        language="python",
        content=(
            "import subprocess\n"
            'example = "subprocess.run(cmd, shell=True)"\n'
            "subprocess.run(['git', 'status'])\n"
            "subprocess.run(user_command, shell=True)\n"
        ),
    )

    findings = PythonScanner().scan(source)

    assert [(finding.rule_id, finding.severity) for finding in findings] == [
        ("SI-PY-002", Severity.MEDIUM),
        ("SI-PY-001", Severity.HIGH),
    ]
    assert findings[1].evidence[0].line == 4
    assert Capability.SHELL_EXECUTION in findings[1].capabilities


def test_python_scanner_detects_shell_and_dynamic_code_calls_through_aliases() -> None:
    source = SourceFile(
        path="runner.py",
        language="python",
        content=(
            "import os as operating_system\n"
            "from builtins import eval as evaluate\n"
            "operating_system.system(command)\n"
            "evaluate(expression)\n"
            "exec(source_text)\n"
            "compile(source_text, '<input>', 'exec')\n"
        ),
    )

    findings = PythonScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-PY-003",
        "SI-PY-004",
        "SI-PY-004",
        "SI-PY-004",
    ]
    assert all(finding.confidence.value == "observed" for finding in findings)


def test_python_scanner_flags_unsafe_deserialization_but_not_safe_yaml_loader() -> None:
    source = SourceFile(
        path="decode.py",
        language="python",
        content=(
            "import pickle\n"
            "import yaml\n"
            "pickle.loads(payload)\n"
            "yaml.load(document)\n"
            "yaml.load(document, Loader=yaml.SafeLoader)\n"
            "yaml.safe_load(document)\n"
        ),
    )

    findings = PythonScanner().scan(source)

    assert [finding.rule_id for finding in findings] == ["SI-PY-005", "SI-PY-006"]
    assert [finding.evidence[0].line for finding in findings] == [3, 4]
