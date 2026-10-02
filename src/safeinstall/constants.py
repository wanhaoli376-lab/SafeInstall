"""Stable product language shared by reports and documentation."""

from safeinstall.models import SkipReason

SKIP_REASON_LABELS = {
    SkipReason.FILE_TOO_LARGE: "exceeds the per-file scan size limit",
    SkipReason.UNDECODABLE_TEXT: "cannot be decoded as supported UTF-8 or UTF-16 text",
    SkipReason.UNREADABLE: "could not be read or traversed",
    SkipReason.UNSAFE_PATH: "link, reparse point, or path outside the allowed scan root",
}

DISCLAIMER = (
    "SafeInstall provides static risk analysis. It does not guarantee that software is safe, "
    "detect every threat, or replace antivirus software."
)

ANALYSIS_SCOPE = (
    "The target was analyzed statically; SafeInstall did not execute target code.",
    "Findings describe observed patterns or bounded inference, not proof of malicious intent.",
    "Dependencies were inspected from manifests and lockfiles; they were not installed.",
    "Coverage applies to supported text formats outside configured directory exclusions; "
    "unsupported formats and ignored dependency/build directories were not analyzed.",
)
