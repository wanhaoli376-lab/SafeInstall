"""Cross-language supply-chain indicators tied to file role and install flow."""

from __future__ import annotations

import re

from safeinstall.models import Capability, Evidence, Finding, Severity, SourceFile
from safeinstall.redaction import redact_text

_INSTALL_SCRIPT_NAMES = {
    "install.bat",
    "install.cmd",
    "install.ps1",
    "install.sh",
    "setup.py",
}
MAX_FINDINGS_PER_FILE = 1_000


class SupplyChainScanner:
    """Report install entrypoints and container inputs without executing them."""

    def supports(self, source: SourceFile) -> bool:
        name = source.path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        return name in _INSTALL_SCRIPT_NAMES or source.language == "dockerfile"

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        name = source.path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        findings: list[Finding] = []
        if name in _INSTALL_SCRIPT_NAMES:
            capability = (
                Capability.CODE_EXECUTION
                if source.language == "python"
                else Capability.SHELL_EXECUTION
            )
            findings.append(
                Finding(
                    rule_id="SI-SC-001",
                    name="Third-party installation script",
                    description=f"{source.path} is an installation entrypoint.",
                    severity=Severity.MEDIUM,
                    category="install_script",
                    language=source.language,
                    explanation=(
                        "Installation scripts often need broad file or command access. Their "
                        "presence does not make the project malicious, and SafeInstall does "
                        "not run them."
                    ),
                    recommendation="Review this file before using it to install the project.",
                    evidence=(Evidence(path=source.path, line=1),),
                    capabilities=(capability,),
                )
            )

        if source.language == "dockerfile":
            findings.extend(self._scan_dockerfile(source))
        return tuple(sorted(findings, key=lambda item: (item.evidence[0].line or 0, item.rule_id)))

    def _scan_dockerfile(self, source: SourceFile) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, raw_line in enumerate(source.content.splitlines(), start=1):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.casefold().startswith("from "):
                image = _docker_image(line)
                if (
                    image
                    and "@sha256:" not in image.casefold()
                    and (
                        ":" not in image.rsplit("/", 1)[-1] or image.casefold().endswith(":latest")
                    )
                ):
                    findings.append(
                        _docker_finding(
                            source,
                            line_number,
                            rule_id="SI-SC-003",
                            name="Container base image is not digest-pinned",
                            description=f"The base image {image} can resolve to different content.",
                            severity=Severity.LOW,
                            category="supply_chain",
                            explanation=(
                                "An image tag can move over time. This is a reproducibility and "
                                "supply-chain consideration, not automatically a vulnerability."
                            ),
                            recommendation="Pin reviewed release images by digest where practical.",
                        )
                    )
            if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:bash|sh)\b", line):
                findings.append(
                    _docker_finding(
                        source,
                        line_number,
                        rule_id="SI-SC-002",
                        name="Container build downloads and executes a script",
                        description="A Dockerfile RUN step pipes downloaded content to a shell.",
                        severity=Severity.HIGH,
                        category="download_and_execute",
                        explanation=(
                            "The remote response becomes build code immediately, so its "
                            "contents are not separately reviewed or verified."
                        ),
                        recommendation=(
                            "Download, verify, and execute a pinned script in separate steps."
                        ),
                        capabilities=(
                            Capability.NETWORK_ACCESS,
                            Capability.DOWNLOAD_EXECUTE,
                            Capability.SHELL_EXECUTION,
                        ),
                    )
                )
        return findings


def _docker_image(line: str) -> str | None:
    parts = line.split()
    for part in parts[1:]:
        if part.startswith("--"):
            continue
        return part
    return None


def _docker_finding(
    source: SourceFile,
    line: int,
    *,
    rule_id: str,
    name: str,
    description: str,
    severity: Severity,
    category: str,
    explanation: str,
    recommendation: str,
    capabilities: tuple[Capability, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        category=category,
        language="dockerfile",
        explanation=explanation,
        recommendation=recommendation,
        evidence=(
            Evidence(
                path=source.path,
                line=line,
                snippet=redact_text(source.line(line).strip())[:500],
            ),
        ),
        capabilities=capabilities,
    )
