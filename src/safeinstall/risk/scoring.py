"""Scoring constants kept separate from behavior inference."""

from safeinstall.models import Severity

BASE_SCORE = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 28,
    Severity.HIGH: 58,
    Severity.CRITICAL: 88,
}

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def level_for_score(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 20:
        return Severity.MEDIUM
    if score >= 5:
        return Severity.LOW
    return Severity.INFO
