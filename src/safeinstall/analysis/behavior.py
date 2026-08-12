"""Context-aware filesystem, environment, and network behavior analysis."""

from __future__ import annotations

import ast
from typing import Any
from urllib.parse import urlsplit

from safeinstall.models import Capability, Evidence, Finding, Severity, SourceFile
from safeinstall.redaction import redact_text

_NETWORK_ROOTS = {"aiohttp", "httpx", "requests", "socket", "urllib", "websockets"}
_NETWORK_METHODS = {"delete", "get", "head", "open", "patch", "post", "put", "request", "urlopen"}
_READ_METHODS = {"read_bytes", "read_text", "readFile", "readFileSync"}
_WRITE_METHODS = {"append_text", "write_bytes", "write_text", "writeFile", "writeFileSync"}
_DELETE_NAMES = {"os.remove", "os.rmdir", "os.unlink", "shutil.rmtree"}
_DELETE_METHODS = {"remove", "rmdir", "rm", "unlink"}
_KNOWN_INFORMATIONAL_DOMAINS = {"api.github.com", "github.com"}
MAX_FINDINGS_PER_FILE = 1_000


class PythonBehaviorScanner:
    """Infer Python capabilities from syntax without importing target modules."""

    def supports(self, source: SourceFile) -> bool:
        return source.language == "python"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            tree = ast.parse(source.content, filename=source.path)
        except (SyntaxError, ValueError, RecursionError):
            return ()
        aliases = _collect_import_aliases(tree)
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            if (
                isinstance(node, ast.Subscript)
                and _qualified_name(node.value, aliases) == "os.environ"
            ):
                findings.append(_environment_finding(source, node))

        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            name = _qualified_name(call.func, aliases)
            if name in {"os.environ.get", "os.getenv"}:
                findings.append(_environment_finding(source, call))

            network = _network_details(call, name)
            if network is not None:
                method, destination, domain = network
                severity = Severity.INFO if domain in _KNOWN_INFORMATIONAL_DOMAINS else Severity.LOW
                findings.append(
                    _finding(
                        source,
                        call,
                        rule_id="SI-PY-021",
                        name="Outbound network request",
                        description=f"The program can make an outbound {method} request.",
                        severity=severity,
                        category="network_access",
                        explanation=(
                            "Network access can download or send data. It is common and is not "
                            "malicious by itself; destination and data flow determine the risk."
                        ),
                        recommendation=(
                            "Review the destination and any data included in the request."
                        ),
                        capabilities=(Capability.NETWORK_ACCESS,),
                        metadata={
                            "method": method,
                            "destination": destination,
                            "domain": domain,
                        },
                    )
                )

            filesystem = _filesystem_details(call, name)
            if filesystem is not None:
                operation, capabilities = filesystem
                sensitive_path = _sensitive_path(call)
                if sensitive_path is not None:
                    findings.append(
                        _finding(
                            source,
                            call,
                            rule_id="SI-FS-001",
                            name="Sensitive filesystem access",
                            description=(
                                "The program accesses an SSH, cloud, configuration, system, or "
                                "browser-data path."
                            ),
                            severity=Severity.MEDIUM,
                            category="sensitive_filesystem_access",
                            explanation=(
                                "These locations can contain credentials or private user data. "
                                "The path reference does not prove the data is misused."
                            ),
                            recommendation=(
                                "Confirm why this path is needed and where any data read "
                                "from it goes."
                            ),
                            capabilities=tuple(
                                dict.fromkeys((*capabilities, Capability.SENSITIVE_DATA_ACCESS))
                            ),
                            metadata={
                                "operation": operation,
                                "path_class": sensitive_path,
                            },
                        )
                    )
                else:
                    findings.append(
                        _generic_filesystem_finding(source, call, operation, capabilities)
                    )

        unique = {
            (finding.rule_id, finding.evidence[0].line, finding.evidence[0].snippet): finding
            for finding in findings
        }
        return tuple(
            sorted(
                unique.values(),
                key=lambda finding: (finding.evidence[0].line or 0, finding.rule_id),
            )
        )


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _network_details(call: ast.Call, name: str | None) -> tuple[str, str, str] | None:
    if not name:
        return None
    parts = name.split(".")
    if parts[0] not in _NETWORK_ROOTS or parts[-1].casefold() not in _NETWORK_METHODS:
        return None
    method = parts[-1].upper()
    if method in {"OPEN", "REQUEST", "URLOPEN"}:
        method = _request_method_keyword(call) or "REQUEST"
    url = _first_string_argument(call)
    domain = "dynamic"
    destination = "unknown"
    if url:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            hostname = None
        if hostname:
            domain = hostname.casefold()
            if domain in _KNOWN_INFORMATIONAL_DOMAINS:
                destination = "github"
    return method, destination, domain


def _request_method_keyword(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "method" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value).upper()
    if call.args and isinstance(call.args[0], ast.Constant):
        value = str(call.args[0].value).upper()
        if value in {"DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"}:
            return value
    return None


def _first_string_argument(call: ast.Call) -> str | None:
    for argument in call.args:
        if (
            isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and "://" in argument.value
        ):
            return argument.value
    for keyword in call.keywords:
        if (
            keyword.arg in {"url", "uri"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            return keyword.value.value
    return None


def _filesystem_details(
    call: ast.Call, name: str | None
) -> tuple[str, tuple[Capability, ...]] | None:
    if not name:
        return None
    method = name.rsplit(".", 1)[-1]
    if name == "open" or method == "open":
        mode = _open_mode(call)
        if any(flag in mode for flag in "wax+"):
            return "write", (Capability.FILESYSTEM_WRITE,)
        return "read", (Capability.FILESYSTEM_READ,)
    if method in _READ_METHODS:
        return "read", (Capability.FILESYSTEM_READ,)
    if method in _WRITE_METHODS:
        return "write", (Capability.FILESYSTEM_WRITE,)
    if name in _DELETE_NAMES or method in _DELETE_METHODS:
        return "delete", (Capability.FILE_DELETE,)
    return None


def _open_mode(call: ast.Call) -> str:
    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
        return str(call.args[1].value)
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    return "r"


def _sensitive_path(call: ast.Call) -> str | None:
    values = [
        str(node.value).replace("\\", "/").casefold()
        for node in ast.walk(call)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    patterns = {
        "ssh": ("/.ssh/", "~/.ssh", ".ssh/"),
        "aws": ("/.aws/", "~/.aws", ".aws/"),
        "user_config": ("/.config/", "~/.config", ".config/", "/.env"),
        "system": ("/etc/", "windows/system32"),
        "browser": ("google/chrome", "mozilla/firefox", "user data/default"),
    }
    for path_class, needles in patterns.items():
        if any(any(needle in value for needle in needles) for value in values):
            return path_class
    return None


def _environment_finding(source: SourceFile, node: ast.AST) -> Finding:
    return _finding(
        source,
        node,
        rule_id="SI-PY-020",
        name="Environment variable access",
        description="The program reads from the process environment.",
        severity=Severity.LOW,
        category="environment_access",
        explanation=(
            "Environment variables often contain configuration and sometimes secrets. Reading "
            "them is common and is not suspicious by itself."
        ),
        recommendation="Review which values are read and where they are subsequently used.",
        capabilities=(Capability.ENVIRONMENT_READ,),
    )


def _generic_filesystem_finding(
    source: SourceFile,
    node: ast.AST,
    operation: str,
    capabilities: tuple[Capability, ...],
) -> Finding:
    details = {
        "read": (
            "SI-PY-022",
            "Filesystem read",
            "The program can read a file.",
            Severity.LOW,
        ),
        "write": (
            "SI-PY-023",
            "Filesystem write",
            "The program can create or modify a file.",
            Severity.LOW,
        ),
        "delete": (
            "SI-PY-024",
            "File deletion",
            "The program can remove a file or directory.",
            Severity.MEDIUM,
        ),
    }
    rule_id, name, description, severity = details[operation]
    return _finding(
        source,
        node,
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        category=f"filesystem_{operation}",
        explanation=(
            f"This program has filesystem {operation} capability. Impact depends on "
            "the resolved path."
        ),
        recommendation="Review the resolved path and keep it inside the intended project area.",
        capabilities=capabilities,
    )


def _finding(
    source: SourceFile,
    node: ast.AST,
    *,
    rule_id: str,
    name: str,
    description: str,
    severity: Severity,
    category: str,
    explanation: str,
    recommendation: str,
    capabilities: tuple[Capability, ...],
    metadata: dict[str, Any] | None = None,
) -> Finding:
    line = getattr(node, "lineno", 1)
    return Finding(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        category=category,
        language="python",
        explanation=explanation,
        recommendation=recommendation,
        evidence=(
            Evidence(
                path=source.path,
                line=line,
                end_line=getattr(node, "end_lineno", line),
                snippet=redact_text(source.line(line).strip())[:500],
            ),
        ),
        capabilities=capabilities,
        metadata=metadata or {},
    )
