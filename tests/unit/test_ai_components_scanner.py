import json

from safeinstall.models import Capability, SourceFile
from safeinstall.scanners.ai_components import AIComponentScanner


def test_skill_frontmatter_produces_a_capability_summary() -> None:
    source = SourceFile(
        path="skills/repository-helper/SKILL.md",
        language="markdown",
        content=(
            "---\n"
            "name: repository-helper\n"
            "allowed-tools: Bash, Read, Write, WebFetch\n"
            "---\n"
            "Use the declared tools to inspect a repository.\n"
        ),
    )

    findings = AIComponentScanner().scan(source)

    assert [finding.rule_id for finding in findings] == ["SI-AI-001", "SI-AI-002"]
    assert set(findings[1].capabilities) == {
        Capability.FILESYSTEM_READ,
        Capability.FILESYSTEM_WRITE,
        Capability.NETWORK_ACCESS,
        Capability.SHELL_EXECUTION,
    }
    assert findings[1].metadata["component_type"] == "skill"


def test_mcp_python_server_lists_tools_and_high_impact_capabilities() -> None:
    source = SourceFile(
        path="mcp_server.py",
        language="python",
        content=(
            "import os\n"
            "import subprocess\n"
            "@mcp.tool()\n"
            "def run_command(command):\n"
            "    return subprocess.run(command)\n"
            "@mcp.tool()\n"
            "def read_setting():\n"
            "    return os.environ.get('EXAMPLE_SETTING')\n"
        ),
    )

    findings = AIComponentScanner().scan(source)

    assert [finding.rule_id for finding in findings] == ["SI-MCP-002"]
    assert findings[0].metadata["tools"] == ["run_command", "read_setting"]
    assert Capability.SHELL_EXECUTION in findings[0].capabilities
    assert Capability.ENVIRONMENT_READ in findings[0].capabilities


def test_mcp_config_reports_server_process_without_returning_environment_values() -> None:
    secret_value = "fixture-secret-that-must-not-appear"
    source = SourceFile(
        path="mcp.json",
        language="json",
        content=(
            "{\n"
            '  "mcpServers": {\n'
            '    "example": {\n'
            '      "command": "python",\n'
            '      "args": ["mcp_server.py"],\n'
            f'      "env": {{"EXAMPLE_TOKEN": "{secret_value}"}}\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )

    findings = AIComponentScanner().scan(source)
    serialized = findings[0].model_dump_json()

    assert [finding.rule_id for finding in findings] == ["SI-MCP-001"]
    assert findings[0].metadata["servers"] == ["example"]
    assert set(findings[0].capabilities) == {
        Capability.SHELL_EXECUTION,
        Capability.ENVIRONMENT_READ,
    }
    assert secret_value not in serialized


def test_remote_mcp_config_reports_network_and_environment_without_values() -> None:
    secret_value = "another-fixture-secret"  # noqa: S105 - inert redaction fixture
    source = SourceFile(
        path="mcp.json",
        language="json",
        content=json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "url": "https://mcp.example.invalid/sse",
                        "env": {"ACCESS_TOKEN": secret_value},
                    }
                }
            }
        ),
    )

    findings = AIComponentScanner().scan(source)
    serialized = findings[0].model_dump_json()

    assert set(findings[0].capabilities) == {
        Capability.NETWORK_ACCESS,
        Capability.ENVIRONMENT_READ,
    }
    assert findings[0].metadata["environment_keys"] == ["ACCESS_TOKEN"]
    assert secret_value not in serialized
