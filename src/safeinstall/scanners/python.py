"""AST-based Python capability scanner."""

from __future__ import annotations

import ast
import re
from itertools import islice

from safeinstall.models import Capability, Evidence, Finding, Severity, SourceFile
from safeinstall.redaction import redact_text

MAX_AST_CALLS_INSPECTED = 10_000
MAX_FINDINGS_PER_FILE = 1_000


class PythonScanner:
    """Detect security-relevant Python calls without importing target modules."""

    _SUBPROCESS_CALLS = {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
    _DYNAMIC_CODE_CALLS = {
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
        "compile",
        "eval",
        "exec",
    }

    def supports(self, source: SourceFile) -> bool:
        return source.language == "python"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        try:
            tree = ast.parse(source.content, filename=source.path)
        except (SyntaxError, ValueError, RecursionError):
            return ()

        aliases = _collect_import_aliases(tree)
        findings: list[Finding] = []
        calls = sorted(
            islice(
                (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
                MAX_AST_CALLS_INSPECTED,
            ),
            key=lambda node: (node.lineno, node.col_offset),
        )
        for call in calls:
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            name = _qualified_name(call.func, aliases)
            if name in self._SUBPROCESS_CALLS:
                capabilities = (Capability.SHELL_EXECUTION,)
                if _subprocess_starts_git(call):
                    capabilities = (*capabilities, Capability.GIT_OPERATIONS)
                shell_enabled = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in call.keywords
                )
                if shell_enabled:
                    findings.append(
                        _finding(
                            source,
                            call,
                            rule_id="SI-PY-001",
                            name="Shell command execution",
                            description=(
                                "A subprocess call explicitly enables shell interpretation."
                            ),
                            severity=Severity.HIGH,
                            explanation=(
                                "This code can ask the operating system shell to interpret "
                                "a command. It is a powerful capability, especially if input "
                                "is externally controlled."
                            ),
                            recommendation=(
                                "Review how the command is built and prefer an argument list "
                                "without shell=True."
                            ),
                            capabilities=capabilities,
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            source,
                            call,
                            rule_id="SI-PY-002",
                            name="System command execution",
                            description="A subprocess call can start another program.",
                            severity=Severity.MEDIUM,
                            explanation=(
                                "This program can launch system commands. That does not make it "
                                "malicious, but it increases what the program can do when run."
                            ),
                            recommendation=(
                                "Review the executable and arguments before running the project."
                            ),
                            capabilities=capabilities,
                        )
                    )
                continue

            if name == "os.system":
                findings.append(
                    _finding(
                        source,
                        call,
                        rule_id="SI-PY-003",
                        name="Shell command execution with os.system",
                        description="os.system asks the operating system shell to run a command.",
                        severity=Severity.HIGH,
                        explanation=(
                            "This code can execute a command through the system shell. The impact "
                            "depends on how the command string is created."
                        ),
                        recommendation=(
                            "Review the command source and prefer subprocess with an explicit "
                            "argument list."
                        ),
                    )
                )

            elif name in self._DYNAMIC_CODE_CALLS:
                findings.append(
                    _finding(
                        source,
                        call,
                        rule_id="SI-PY-004",
                        name="Dynamic code processing",
                        description=f"{name} can parse or execute Python code at runtime.",
                        severity=Severity.MEDIUM,
                        explanation=(
                            "Runtime code processing is a dangerous capability if the input can be "
                            "changed by an untrusted person. Its presence alone does not prove a "
                            "vulnerability."
                        ),
                        recommendation=(
                            "Trace where the supplied source text comes from and avoid evaluating "
                            "untrusted input."
                        ),
                        category="dynamic_code_execution",
                        capabilities=(Capability.CODE_EXECUTION,),
                    )
                )

            elif name in {"pickle.load", "pickle.loads"}:
                findings.append(
                    _finding(
                        source,
                        call,
                        rule_id="SI-PY-005",
                        name="Pickle deserialization",
                        description="Python pickle can construct objects while loading data.",
                        severity=Severity.HIGH,
                        explanation=(
                            "Loading pickle data can execute code embedded in a crafted payload. "
                            "This is dangerous when the data is not fully trusted."
                        ),
                        recommendation="Only load pickle data from a source you fully trust.",
                        category="unsafe_deserialization",
                        capabilities=(Capability.CODE_EXECUTION,),
                    )
                )

            elif name == "yaml.load" and not _uses_safe_yaml_loader(call):
                findings.append(
                    _finding(
                        source,
                        call,
                        rule_id="SI-PY-006",
                        name="Potentially unsafe YAML loading",
                        description="yaml.load is used without an explicitly safe loader.",
                        severity=Severity.HIGH,
                        explanation=(
                            "Some YAML loaders can construct Python objects from document content. "
                            "A crafted document may therefore have effects beyond reading data."
                        ),
                        recommendation="Use yaml.safe_load or explicitly select yaml.SafeLoader.",
                        category="unsafe_deserialization",
                        capabilities=(Capability.CODE_EXECUTION,),
                    )
                )
        return tuple(findings)


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


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _uses_safe_yaml_loader(call: ast.Call) -> bool:
    safe_names = {"CSafeLoader", "FullLoader", "SafeLoader"}
    for keyword in call.keywords:
        if keyword.arg != "Loader":
            continue
        if isinstance(keyword.value, ast.Name):
            return keyword.value.id in safe_names
        if isinstance(keyword.value, ast.Attribute):
            return keyword.value.attr in safe_names
    return False


def _subprocess_starts_git(call: ast.Call) -> bool:
    if not call.args:
        return False
    command = call.args[0]
    if isinstance(command, ast.Constant) and isinstance(command.value, str):
        return re.match(r"^\s*git(?:\.exe)?(?:\s|$)", command.value, re.IGNORECASE) is not None
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        executable = command.elts[0]
        return (
            isinstance(executable, ast.Constant)
            and isinstance(executable.value, str)
            and executable.value.casefold().replace("\\", "/").rsplit("/", 1)[-1]
            in {"git", "git.exe"}
        )
    return False


def _finding(
    source: SourceFile,
    node: ast.AST,
    *,
    rule_id: str,
    name: str,
    description: str,
    severity: Severity,
    explanation: str,
    recommendation: str,
    category: str = "command_execution",
    capabilities: tuple[Capability, ...] = (Capability.SHELL_EXECUTION,),
) -> Finding:
    line_number = getattr(node, "lineno", 1)
    return Finding(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        category=category,
        language="python",
        explanation=explanation,
        recommendation=recommendation,
        capabilities=capabilities,
        evidence=(
            Evidence(
                path=source.path,
                line=line_number,
                end_line=getattr(node, "end_lineno", line_number),
                snippet=redact_text(source.line(line_number).strip())[:500],
            ),
        ),
    )
