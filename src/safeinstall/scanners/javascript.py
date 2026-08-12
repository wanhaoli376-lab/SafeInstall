"""Capability-focused JavaScript and TypeScript scanner."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import islice

from safeinstall.models import (
    Capability,
    Evidence,
    Finding,
    FindingConfidence,
    Severity,
    SourceFile,
)
from safeinstall.redaction import redact_text

MAX_FINDINGS_PER_FILE = 1_000


@dataclass(frozen=True, slots=True)
class _Match:
    line: int
    column: int
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: str
    explanation: str
    recommendation: str
    capabilities: tuple[Capability, ...]
    confidence: FindingConfidence = FindingConfidence.OBSERVED
    metadata: dict[str, str] | None = None


class JavaScriptScanner:
    """Detect Node.js capabilities without evaluating or importing target code."""

    def supports(self, source: SourceFile) -> bool:
        return source.language == "javascript"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        code = _mask_javascript_comments_and_strings(source.content)
        matches: list[_Match] = []

        for match in _bounded_matches(
            r"\bchild_process\s*\.\s*(exec|execFile|spawn|fork)\s*\(",
            code,
            len(matches),
        ):
            method = match.group(1)
            severity = Severity.HIGH if method == "exec" else Severity.MEDIUM
            original_line = source.line(_line_number(code, match.start()))
            capabilities = (Capability.SHELL_EXECUTION,)
            if _javascript_starts_git(original_line):
                capabilities = (*capabilities, Capability.GIT_OPERATIONS)
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-001",
                    name="Child process execution",
                    description=f"child_process.{method} can start another process.",
                    severity=severity,
                    category="command_execution",
                    explanation=(
                        "This code can launch programs or commands on the computer. That "
                        "capability is not proof of malicious behavior, but it increases "
                        "the program's reach."
                    ),
                    recommendation="Review the executable, arguments, and source of any input.",
                    capabilities=capabilities,
                )
            )

        for match in _bounded_matches(
            r"(?:\beval\s*\(|\b(?:new\s+)?Function\s*\()", code, len(matches)
        ):
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-002",
                    name="Dynamic JavaScript execution",
                    description="The program can compile or evaluate JavaScript at runtime.",
                    severity=Severity.HIGH,
                    category="dynamic_code_execution",
                    explanation=(
                        "Runtime evaluation can execute text as code. It is dangerous when outside "
                        "input can influence that text."
                    ),
                    recommendation=(
                        "Trace the evaluated value and avoid evaluating untrusted input."
                    ),
                    capabilities=(Capability.CODE_EXECUTION,),
                )
            )

        for match in _bounded_matches(
            r"\bfs\s*\.\s*(?:rm|rmSync|unlink|unlinkSync|rmdir)\s*\(",
            code,
            len(matches),
        ):
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-003",
                    name="File deletion",
                    description="The Node.js filesystem module can delete a file or directory.",
                    severity=Severity.MEDIUM,
                    category="destructive_file_operation",
                    explanation=(
                        "This program can remove files. The actual impact depends on how "
                        "the target path is chosen."
                    ),
                    recommendation="Verify that delete paths remain inside the intended directory.",
                    capabilities=(Capability.FILE_DELETE,),
                )
            )

        for match in _bounded_matches(
            r"\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|createWriteStream)\s*\(",
            code,
            len(matches),
        ):
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-004",
                    name="Filesystem write",
                    description="The Node.js filesystem module can write data to disk.",
                    severity=Severity.LOW,
                    category="filesystem_write",
                    explanation="This program can create or modify files.",
                    recommendation=(
                        "Review which paths are written and whether they are user-controlled."
                    ),
                    capabilities=(Capability.FILESYSTEM_WRITE,),
                )
            )

        for match in _bounded_matches(
            r"(?:\bfetch\s*\(|\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\("
            r"|\bhttps?\s*\.\s*(?:get|request)\s*\("
            r"|\b(?:new\s+)?WebSocket\s*\("
            r"|\bws\s*\.\s*(?:connect|createWebSocketStream)\s*\("
            r"|\bnet\s*\.\s*(?:connect|createConnection)\s*\("
            r"|\bdgram\s*\.\s*createSocket\s*\()",
            code,
            len(matches),
        ):
            original_line = source.line(_line_number(code, match.start()))
            known_github = "api.github.com" in original_line.casefold()
            method = _javascript_network_method(match.group(0), original_line)
            transport = _javascript_network_transport(match.group(0))
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-005",
                    name={
                        "websocket": "WebSocket connection",
                        "socket": "Raw socket capability",
                    }.get(transport, "Network access"),
                    description=(
                        "The program can open a two-way WebSocket connection."
                        if transport == "websocket"
                        else "The program can create or use a low-level network socket."
                        if transport == "socket"
                        else "The program can make an outbound network request."
                    ),
                    severity=Severity.INFO if known_github else Severity.LOW,
                    category="network_access",
                    explanation=(
                        "Network access alone is not malicious. It can download or send data; this "
                        "request appears to target the GitHub API."
                        if known_github
                        else "Network access alone is not malicious. It can download or send data."
                    ),
                    recommendation="Review the destination and data sent with the request.",
                    capabilities=(Capability.NETWORK_ACCESS,),
                    metadata={
                        "destination": "github" if known_github else "unknown",
                        "method": method,
                        "transport": transport,
                    },
                )
            )
            if method in {"PATCH", "POST", "PUT"} and len(matches) < MAX_FINDINGS_PER_FILE:
                matches.append(
                    _match(
                        source,
                        match,
                        rule_id="SI-JS-008",
                        name="Potential outbound data upload",
                        description=(
                            f"The {method} request can send a request body away from this computer."
                        ),
                        severity=Severity.LOW,
                        category="network_upload",
                        explanation=(
                            "Sending data is common for APIs and telemetry. Review the payload "
                            "and who controls the destination."
                        ),
                        recommendation="Review the request body and destination.",
                        capabilities=(Capability.NETWORK_ACCESS,),
                        confidence=FindingConfidence.INFERRED,
                        metadata={
                            "destination": "github" if known_github else "unknown",
                            "method": method,
                        },
                    )
                )
            service_hint = _javascript_network_service_hint(original_line)
            if service_hint is not None and len(matches) < MAX_FINDINGS_PER_FILE:
                matches.append(
                    _match(
                        source,
                        match,
                        rule_id="SI-JS-009",
                        name="Telemetry or webhook destination hint",
                        description=f"The destination text resembles a {service_hint} endpoint.",
                        severity=Severity.LOW,
                        category="network_service_hint",
                        explanation=(
                            "The endpoint name suggests telemetry or webhook traffic, but its "
                            "actual purpose cannot be proven from the name alone."
                        ),
                        recommendation=(
                            "Review the payload, privacy expectations, and endpoint owner."
                        ),
                        capabilities=(Capability.NETWORK_ACCESS,),
                        confidence=FindingConfidence.INFERRED,
                        metadata={"hint": service_hint},
                    )
                )

        for match in _bounded_matches(r"\bprocess\s*\.\s*env(?:\b|\s*\[)", code, len(matches)):
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-006",
                    name="Environment variable access",
                    description="The program reads process environment variables.",
                    severity=Severity.LOW,
                    category="environment_access",
                    explanation=(
                        "Environment variables often contain configuration and sometimes secrets. "
                        "Reading them is common and is not suspicious by itself."
                    ),
                    recommendation=(
                        "Review which values are read and where they are subsequently used."
                    ),
                    capabilities=(Capability.ENVIRONMENT_READ,),
                )
            )

        for match in _bounded_matches(
            r"\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream)\s*\(",
            code,
            len(matches),
        ):
            matches.append(
                _match(
                    source,
                    match,
                    rule_id="SI-JS-007",
                    name="Filesystem read",
                    description="The Node.js filesystem module can read data from disk.",
                    severity=Severity.LOW,
                    category="filesystem_read",
                    explanation="This program can read files available to the current user.",
                    recommendation=(
                        "Review which paths are read, especially user configuration files."
                    ),
                    capabilities=(Capability.FILESYSTEM_READ,),
                )
            )

        matches.sort(key=lambda item: (item.line, item.column, item.rule_id))
        return tuple(_to_finding(source, item) for item in matches)


def _match(
    source: SourceFile,
    match: re.Match[str],
    **values: object,
) -> _Match:
    line = _line_number(source.content, match.start())
    column = match.start() - source.content.rfind("\n", 0, match.start()) - 1
    return _Match(line=line, column=column, **values)  # type: ignore[arg-type]


def _to_finding(source: SourceFile, match: _Match) -> Finding:
    return Finding(
        rule_id=match.rule_id,
        name=match.name,
        description=match.description,
        severity=match.severity,
        category=match.category,
        language="javascript",
        explanation=match.explanation,
        recommendation=match.recommendation,
        evidence=(
            Evidence(
                path=source.path,
                line=match.line,
                snippet=redact_text(source.line(match.line).strip())[:500],
            ),
        ),
        capabilities=match.capabilities,
        confidence=match.confidence,
        metadata=match.metadata or {},
    )


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _bounded_matches(pattern: str, text: str, already_emitted: int) -> Iterator[re.Match[str]]:
    remaining = max(0, MAX_FINDINGS_PER_FILE - already_emitted)
    return islice(re.finditer(pattern, text), remaining)


def _javascript_network_method(matched_text: str, original_line: str) -> str:
    normalized = matched_text.casefold()
    if "websocket" in normalized or re.search(r"\b(?:ws|net)\s*\.", normalized):
        return "CONNECT"
    if re.search(r"\bdgram\s*\.", normalized):
        return "SOCKET"
    method = re.search(
        r"\.\s*(get|post|put|patch|delete|request)\s*\(",
        matched_text,
        re.IGNORECASE,
    )
    if method is not None:
        return method.group(1).upper()
    fetch_method = re.search(
        r"\bmethod\s*:\s*['\"](DELETE|GET|HEAD|PATCH|POST|PUT)['\"]",
        original_line,
        re.IGNORECASE,
    )
    return fetch_method.group(1).upper() if fetch_method is not None else "GET"


def _javascript_network_transport(matched_text: str) -> str:
    normalized = matched_text.casefold()
    if "websocket" in normalized or re.search(r"\bws\s*\.", normalized):
        return "websocket"
    if re.search(r"\b(?:net|dgram)\s*\.", normalized):
        return "socket"
    return "http"


def _javascript_network_service_hint(line: str) -> str | None:
    normalized = line.casefold()
    if "webhook" in normalized or "hooks.slack" in normalized:
        return "webhook"
    if any(marker in normalized for marker in ("telemetry", "analytics", "/events", "sentry.io")):
        return "telemetry"
    return None


def _javascript_starts_git(line: str) -> bool:
    return (
        re.search(
            r"\bchild_process\s*\.\s*(?:execFile|spawn)\s*\(\s*['\"]git(?:\.exe)?['\"]",
            line,
            re.IGNORECASE,
        )
        is not None
    )


def _mask_javascript_comments_and_strings(text: str) -> str:
    """Replace comments and string contents with spaces while preserving newlines."""

    output = list(text)
    state = "code"
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {"'", '"', "`"}:
                output[index] = " "
                state = {"'": "single", '"': "double", "`": "template"}[char]
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        else:
            if escaped:
                escaped = False
                if char != "\n":
                    output[index] = " "
            elif char == "\\":
                escaped = True
                output[index] = " "
            elif (
                (state == "single" and char == "'")
                or (state == "double" and char == '"')
                or (state == "template" and char == "`")
            ):
                output[index] = " "
                state = "code"
            elif char != "\n":
                output[index] = " "
        index += 1
    return "".join(output)
