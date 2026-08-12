"""AI Skill, plugin, and MCP capability analysis."""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from safeinstall.exceptions import ParseLimitError
from safeinstall.models import (
    Capability,
    CapabilitySummary,
    Evidence,
    Finding,
    FindingConfidence,
    Severity,
    SourceFile,
)
from safeinstall.redaction import redact_text
from safeinstall.safe_parsing import load_basic_yaml


class AIComponentScanner:
    """Summarize high-impact capabilities declared or implemented by AI extensions."""

    def supports(self, source: SourceFile) -> bool:
        path = PurePosixPath(source.path.replace("\\", "/"))
        name = path.name.casefold()
        parts = {part.casefold() for part in path.parts[:-1]}
        return (
            name in {"mcp.json", "mcp_server.py", "plugin.json", "skill.md"}
            or "skills" in parts
            or "plugins" in parts
        )

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        path = PurePosixPath(source.path.replace("\\", "/"))
        name = path.name.casefold()
        if name == "skill.md":
            return self._scan_skill(source)
        if name == "plugin.json":
            return self._scan_plugin_manifest(source)
        if name == "mcp.json":
            return self._scan_mcp_config(source)
        if name == "mcp_server.py" or (
            source.language == "python" and _looks_like_mcp_python(source.content)
        ):
            return self._scan_mcp_python(source)
        return ()

    def _scan_skill(self, source: SourceFile) -> tuple[Finding, ...]:
        findings = [
            _component_finding(
                source,
                line=1,
                rule_id="SI-AI-001",
                name="AI Skill definition",
                description="This file defines instructions for an AI Skill.",
                severity=Severity.INFO,
                explanation=(
                    "Skill instructions can influence an AI agent that installs or loads them. "
                    "SafeInstall treats the file as untrusted data."
                ),
                recommendation=(
                    "Review the instructions and declared tools before enabling the Skill."
                ),
                metadata={"component_type": "skill"},
            )
        ]
        frontmatter = _frontmatter(source.content)
        tool_value = frontmatter.get("allowed-tools") if frontmatter else None
        capabilities = _capabilities_from_tool_declaration(tool_value)
        if capabilities:
            findings.append(
                _capability_finding(
                    source,
                    line=_line_containing(source.content, "allowed-tools"),
                    rule_id="SI-AI-002",
                    component_type="skill",
                    name="AI Skill tool capability summary",
                    capabilities=capabilities,
                    metadata={"declared_tools": _safe_tool_list(tool_value)},
                )
            )
        return tuple(findings)

    def _scan_plugin_manifest(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            manifest = json.loads(source.content)
        except (json.JSONDecodeError, UnicodeError):
            return ()
        if not isinstance(manifest, Mapping):
            return ()
        findings = [
            _component_finding(
                source,
                line=1,
                rule_id="SI-AI-003",
                name="AI plugin manifest",
                description="This file declares an AI plugin or extension.",
                severity=Severity.INFO,
                explanation="Plugins can add tools and code to a host application.",
                recommendation="Review the plugin source and permissions before installation.",
                metadata={"component_type": "plugin"},
            )
        ]
        permissions = manifest.get("permissions")
        capabilities = _capabilities_from_tool_declaration(permissions)
        if capabilities:
            findings.append(
                _capability_finding(
                    source,
                    line=_line_containing(source.content, "permissions"),
                    rule_id="SI-AI-004",
                    component_type="plugin",
                    name="AI plugin capability summary",
                    capabilities=capabilities,
                    metadata={"declared_permissions": _safe_tool_list(permissions)},
                )
            )
        return tuple(findings)

    def _scan_mcp_config(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            config = json.loads(source.content)
        except (json.JSONDecodeError, UnicodeError):
            return ()
        if not isinstance(config, Mapping):
            return ()
        servers = config.get("mcpServers", config.get("servers", {}))
        if not isinstance(servers, Mapping):
            return ()
        server_names: list[str] = []
        commands: list[str] = []
        urls: list[str] = []
        environment_keys: list[str] = []
        capabilities: set[Capability] = set()
        for server_name, details in servers.items():
            if not isinstance(server_name, str) or not isinstance(details, Mapping):
                continue
            server_has_capability = False
            command = details.get("command")
            if isinstance(command, str):
                commands.append(redact_text(command)[:200])
                capabilities.add(Capability.SHELL_EXECUTION)
                server_has_capability = True
            url = details.get("url")
            if isinstance(url, str):
                urls.append(redact_text(url)[:500])
                capabilities.add(Capability.NETWORK_ACCESS)
                server_has_capability = True
            environment = details.get("env")
            if isinstance(environment, Mapping):
                keys = [redact_text(key)[:100] for key in environment if isinstance(key, str)]
                if keys:
                    environment_keys.extend(keys)
                    capabilities.add(Capability.ENVIRONMENT_READ)
                    server_has_capability = True
            if server_has_capability:
                server_names.append(redact_text(server_name)[:200])
        if not capabilities:
            return ()
        ordered = tuple(item for item in Capability if item in capabilities)
        metadata: dict[str, Any] = {"servers": server_names}
        if commands:
            metadata["commands"] = commands
        if urls:
            metadata["urls"] = urls
        if environment_keys:
            metadata["environment_keys"] = environment_keys
        evidence_key = "command" if commands else "url" if urls else "env"
        return (
            _capability_finding(
                source,
                line=_line_containing(source.content, evidence_key),
                rule_id="SI-MCP-001",
                component_type="mcp",
                name="MCP server configuration capability summary",
                capabilities=ordered,
                metadata=metadata,
            ),
        )

    def _scan_mcp_python(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            tree = ast.parse(source.content, filename=source.path)
        except (SyntaxError, ValueError, RecursionError):
            return ()
        tools = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(_decorator_is_tool(decorator) for decorator in node.decorator_list)
        ]
        tools.sort(key=lambda node: node.lineno)
        if not tools:
            return ()

        capabilities: set[Capability] = set()
        for tool in tools:
            capabilities.update(_python_capabilities(tool))
        ordered = tuple(item for item in Capability if item in capabilities)
        severity = _capability_severity(ordered)
        summary = CapabilitySummary(observed=ordered)
        first_line = min(tool.decorator_list[0].lineno for tool in tools)
        return (
            Finding(
                rule_id="SI-MCP-002",
                name="MCP server capability summary",
                description="This Python file exposes one or more MCP tools.",
                severity=severity,
                category="mcp_capability",
                language="python",
                explanation=(
                    "MCP tools can act with the permissions of the server process. "
                    "Capabilities are inferred statically and may require manual confirmation."
                ),
                recommendation=(
                    "Review each tool implementation and run the server with the least filesystem, "
                    "network, environment, and process permissions it needs."
                ),
                evidence=(
                    Evidence(
                        path=source.path,
                        line=first_line,
                        snippet=redact_text(source.line(first_line).strip())[:500],
                    ),
                ),
                capabilities=ordered,
                confidence=FindingConfidence.INFERRED,
                metadata={
                    "component_type": "mcp",
                    "tools": [tool.name for tool in tools],
                    "capability_summary": summary.as_mapping(),
                },
            ),
        )


def _frontmatter(content: str) -> Mapping[str, Any]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    for index, line in enumerate(lines[1:200], start=1):
        if line.strip() != "---":
            continue
        try:
            data = load_basic_yaml("\n".join(lines[1:index]))
        except ParseLimitError:
            return {}
        return data if isinstance(data, Mapping) else {}
    return {}


def _safe_tool_list(value: Any) -> list[str]:
    if isinstance(value, str):
        items = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        items = [item for item in value if isinstance(item, str)]
    else:
        return []
    return [redact_text(item)[:100] for item in items if item]


def _capabilities_from_tool_declaration(value: Any) -> tuple[Capability, ...]:
    tools = [item.casefold() for item in _safe_tool_list(value)]
    capabilities: set[Capability] = set()
    for tool in tools:
        if any(word in tool for word in ("bash", "command", "exec", "powershell", "shell")):
            capabilities.add(Capability.SHELL_EXECUTION)
        if any(word in tool for word in ("read", "filesystem:read")):
            capabilities.add(Capability.FILESYSTEM_READ)
        if any(word in tool for word in ("edit", "filesystem:write", "write")):
            capabilities.add(Capability.FILESYSTEM_WRITE)
        if any(word in tool for word in ("browser", "fetch", "http", "network", "web")):
            capabilities.add(Capability.NETWORK_ACCESS)
        if "env" in tool:
            capabilities.add(Capability.ENVIRONMENT_READ)
    return tuple(item for item in Capability if item in capabilities)


def _looks_like_mcp_python(content: str) -> bool:
    return bool(re.search(r"(?m)^\s*@\w+(?:\.\w+)*\.tool\s*\(", content))


def _decorator_is_tool(decorator: ast.expr) -> bool:
    value = decorator.func if isinstance(decorator, ast.Call) else decorator
    return (isinstance(value, ast.Attribute) and value.attr == "tool") or (
        isinstance(value, ast.Name) and value.id == "tool"
    )


def _python_capabilities(node: ast.AST) -> set[Capability]:
    capabilities: set[Capability] = set()
    for child in ast.walk(node):
        name = _python_qualified_name(child.func) if isinstance(child, ast.Call) else None
        if name and (name.startswith("subprocess.") or name == "os.system"):
            capabilities.add(Capability.SHELL_EXECUTION)
        if name and name in {"os.getenv", "os.environ.get"}:
            capabilities.add(Capability.ENVIRONMENT_READ)
        if isinstance(child, ast.Attribute) and _python_qualified_name(child.value) == "os.environ":
            capabilities.add(Capability.ENVIRONMENT_READ)
        if name and name.split(".", 1)[0] in {
            "aiohttp",
            "httpx",
            "requests",
            "socket",
            "urllib",
            "websockets",
        }:
            capabilities.add(Capability.NETWORK_ACCESS)
        if name in {"open", "Path.open", "pathlib.Path.open"}:
            mode = _open_mode(child)
            if any(flag in mode for flag in "wax+"):
                capabilities.add(Capability.FILESYSTEM_WRITE)
            else:
                capabilities.add(Capability.FILESYSTEM_READ)
        if name and name.endswith((".read_bytes", ".read_text")):
            capabilities.add(Capability.FILESYSTEM_READ)
        if name and name.endswith((".write_bytes", ".write_text")):
            capabilities.add(Capability.FILESYSTEM_WRITE)
        if name and name in {"os.remove", "os.rmdir", "os.unlink", "shutil.rmtree"}:
            capabilities.add(Capability.FILE_DELETE)
    return capabilities


def _python_qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _open_mode(call: ast.Call) -> str:
    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
        return str(call.args[1].value)
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    return "r"


def _capability_finding(
    source: SourceFile,
    *,
    line: int,
    rule_id: str,
    component_type: str,
    name: str,
    capabilities: tuple[Capability, ...],
    metadata: dict[str, Any],
) -> Finding:
    summary = CapabilitySummary(observed=capabilities)
    return Finding(
        rule_id=rule_id,
        name=name,
        description=f"This {component_type} declares or implements high-impact capabilities.",
        severity=_capability_severity(capabilities),
        category="ai_component_capability",
        language=source.language,
        explanation=(
            "Capabilities show what the component may be able to do if enabled. They do not prove "
            "that the component is malicious."
        ),
        recommendation="Review why each capability is needed and grant the smallest useful scope.",
        evidence=(
            Evidence(
                path=source.path,
                line=line,
                snippet=redact_text(source.line(line).strip())[:500],
            ),
        ),
        capabilities=capabilities,
        metadata={
            "component_type": component_type,
            "capability_summary": summary.as_mapping(),
            **metadata,
        },
    )


def _component_finding(
    source: SourceFile,
    *,
    line: int,
    rule_id: str,
    name: str,
    description: str,
    severity: Severity,
    explanation: str,
    recommendation: str,
    metadata: dict[str, Any],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        category="ai_component",
        language=source.language,
        explanation=explanation,
        recommendation=recommendation,
        evidence=(Evidence(path=source.path, line=line),),
        metadata=metadata,
    )


def _capability_severity(capabilities: tuple[Capability, ...]) -> Severity:
    values = set(capabilities)
    if values & {Capability.FILE_DELETE, Capability.SHELL_EXECUTION}:
        return Severity.HIGH
    if values & {
        Capability.ENVIRONMENT_READ,
        Capability.FILESYSTEM_WRITE,
        Capability.NETWORK_ACCESS,
    }:
        return Severity.MEDIUM
    return Severity.LOW


def _line_containing(content: str, needle: str) -> int:
    for number, line in enumerate(content.splitlines(), start=1):
        if needle.casefold() in line.casefold():
            return number
    return 1
