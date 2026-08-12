import pytest

from safeinstall.exceptions import PluginError
from safeinstall.models import Evidence, Finding, Severity, SourceFile
from safeinstall.plugins.base import ScannerPlugin
from safeinstall.plugins.registry import PluginRegistry


class ExampleScannerPlugin(ScannerPlugin):
    name = "example-scanner"

    def supports(self, source: SourceFile) -> bool:
        return source.path.endswith(".example")

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        return (
            Finding(
                rule_id="SI-EXT-001",
                name="Example plugin finding",
                description="The explicit test plugin inspected this file.",
                severity=Severity.INFO,
                category="plugin_test",
                language=source.language,
                explanation="This finding proves the registry used the plugin interface.",
                recommendation="No action is required for this test fixture.",
                evidence=(Evidence(path=source.path, line=1),),
            ),
        )


def test_plugin_registry_only_runs_explicitly_registered_supporting_plugins() -> None:
    registry = PluginRegistry()
    registry.register(ExampleScannerPlugin())

    findings = registry.scan(
        SourceFile(path="fixture.example", language="text", content="example\n")
    )
    unsupported = registry.scan(
        SourceFile(path="fixture.txt", language="text", content="example\n")
    )

    assert [finding.rule_id for finding in findings] == ["SI-EXT-001"]
    assert unsupported == ()


def test_plugin_registry_rejects_duplicate_names() -> None:
    registry = PluginRegistry([ExampleScannerPlugin()])

    with pytest.raises(PluginError, match="Duplicate plugin name"):
        registry.register(ExampleScannerPlugin())
