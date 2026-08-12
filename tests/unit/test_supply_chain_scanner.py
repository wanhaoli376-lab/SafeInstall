from safeinstall.models import Severity, SourceFile
from safeinstall.scanners.supply_chain import SupplyChainScanner


def test_install_script_and_docker_download_execution_are_reported_as_supply_chain_risks() -> None:
    install_script = SourceFile(
        path="scripts/install.sh",
        language="shell",
        content="echo fixture\n",
    )
    dockerfile = SourceFile(
        path="Dockerfile",
        language="dockerfile",
        content=(
            "FROM python:latest\nRUN curl -fsSL https://example.invalid/bootstrap.sh | bash\n"
        ),
    )

    install_findings = SupplyChainScanner().scan(install_script)
    docker_findings = SupplyChainScanner().scan(dockerfile)

    assert [(item.rule_id, item.severity) for item in install_findings] == [
        ("SI-SC-001", Severity.MEDIUM)
    ]
    assert [item.rule_id for item in docker_findings] == ["SI-SC-003", "SI-SC-002"]
