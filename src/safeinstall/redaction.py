"""Central redaction helpers for untrusted evidence and logs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_ASSIGNMENT = re.compile(
    r"(?P<key_quote>['\"]?)"
    r"(?P<key>\b(?=[A-Za-z_][A-Za-z0-9_]*\b)"
    r"(?=[A-Za-z0-9_]*(?:password|passwd|pwd|token|secret|api_key|access_key))"
    r"[A-Za-z_][A-Za-z0-9_]*\b)"
    r"(?P=key_quote)"
    r"(?P<separator>\s*[:=]\s*)"
    r'(?:"(?P<double>(?:\\.|[^"\\\r\n])*)"|'
    r"'(?P<single>(?:\\.|[^'\\\r\n])*)'|"
    r"(?P<bare>[^\s#,;]+))",
    re.IGNORECASE,
)
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})")
_URL_CREDENTIALS = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?P<credentials>[^/@\s]+)@",
    re.IGNORECASE,
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9 ]+ )?PRIVATE KEY)-----"
    r".*?(?:-----END (?P=label)-----|$)",
    re.DOTALL,
)
_DIRECTIONAL_CONTROLS = {
    0x061C,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}


def mask_secret(value: str) -> str:
    """Return a non-reversible preview that never contains the complete value."""

    if value.startswith("sk-"):
        return f"sk-****...{value[-4:]}"
    if len(value) <= 8:
        return "****"
    prefix_length = 4 if value.startswith(("AKIA", "ASIA", "gh")) else 2
    return f"{value[:prefix_length]}****...{value[-4:]}"


def redact_text(text: str) -> str:
    """Redact common credentials and password-like assignments from arbitrary text."""

    def redact_assignment(match: re.Match[str]) -> str:
        if match.group("double") is not None:
            quote = '"'
            value = match.group("double")
        elif match.group("single") is not None:
            quote = "'"
            value = match.group("single")
        else:
            quote = ""
            value = match.group("bare")
        key_quote = match.group("key_quote")
        return (
            f"{key_quote}{match.group('key')}{key_quote}"
            f"{match.group('separator')}{quote}{mask_secret(value)}{quote}"
        )

    redacted = _PRIVATE_KEY_BLOCK.sub(
        lambda match: f"-----BEGIN {match.group('label')}-----\n[REDACTED PRIVATE KEY]",
        text,
    )
    redacted = _ASSIGNMENT.sub(redact_assignment, redacted)
    redacted = _OPENAI_KEY.sub(lambda match: mask_secret(match.group(0)), redacted)
    redacted = _GITHUB_TOKEN.sub(lambda match: mask_secret(match.group(0)), redacted)
    redacted = _AWS_ACCESS_KEY.sub(lambda match: mask_secret(match.group(0)), redacted)
    redacted = _BEARER_TOKEN.sub(lambda match: f"Bearer {mask_secret(match.group(1))}", redacted)
    redacted = _URL_CREDENTIALS.sub(r"\g<scheme>****@", redacted)
    return _make_controls_visible(redacted)


def _make_controls_visible(text: str) -> str:
    output: list[str] = []
    for character in text:
        codepoint = ord(character)
        unsafe = (
            (codepoint < 32 and character not in {"\n", "\r", "\t"})
            or 127 <= codepoint <= 159
            or codepoint in _DIRECTIONAL_CONTROLS
        )
        output.append(f"\\u{codepoint:04x}" if unsafe else character)
    return "".join(output)


def redact_data(value: Any) -> Any:
    """Recursively redact strings before serializing a report or external payload."""

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {redact_text(str(key)): redact_data(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    return value
