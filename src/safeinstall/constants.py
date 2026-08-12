"""Stable product language shared by reports and documentation."""

DISCLAIMER = (
    "SafeInstall provides static risk analysis. It does not guarantee that software is safe, "
    "detect every threat, or replace antivirus software."
)

ANALYSIS_SCOPE = (
    "The target was analyzed statically; SafeInstall did not execute target code.",
    "Findings describe observed patterns or bounded inference, not proof of malicious intent.",
    "Dependencies were inspected from manifests and lockfiles; they were not installed.",
)
