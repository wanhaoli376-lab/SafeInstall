"""Structured manifest and supply-chain analysis."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from typing import Any

from safeinstall.models import (
    Capability,
    DependencyRecord,
    Evidence,
    Finding,
    ManifestAnalysis,
    Severity,
    SourceFile,
)
from safeinstall.redaction import redact_text

_NPM_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
_NPM_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
_EXACT_NPM_VERSION = re.compile(r"^(?:v)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_PYTHON_NAME = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?")
_EXACT_PYTHON_SPECIFIER = re.compile(r"^={2,3}[^,;*\s]+$")
MAX_DEPENDENCIES_PER_MANIFEST = 20_000
MAX_FINDINGS_PER_MANIFEST = 20_000


class DependencyScanner:
    """Parse supported manifests as data and never invoke a package manager."""

    def supports(self, source: SourceFile) -> bool:
        name = source.path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        return name in {"package-lock.json", "package.json", "requirements.txt", "pyproject.toml"}

    def analyze(self, source: SourceFile) -> ManifestAnalysis:
        name = source.path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if name == "package.json":
            return self._analyze_package_json(source)
        if name == "package-lock.json":
            return self._analyze_package_lock(source)
        if name == "requirements.txt":
            return self._analyze_requirements(source)
        if name == "pyproject.toml":
            return self._analyze_pyproject(source)
        return ManifestAnalysis()

    def _analyze_package_json(self, source: SourceFile) -> ManifestAnalysis:
        try:
            raw = json.loads(source.content)
        except (json.JSONDecodeError, UnicodeError):
            return ManifestAnalysis()
        if not isinstance(raw, Mapping):
            return ManifestAnalysis()

        dependencies: list[DependencyRecord] = []
        findings: list[Finding] = []
        scripts = raw.get("scripts", {})
        if isinstance(scripts, Mapping):
            for script_name, command in scripts.items():
                if len(findings) >= MAX_FINDINGS_PER_MANIFEST:
                    break
                if script_name not in _NPM_LIFECYCLE_SCRIPTS or not isinstance(command, str):
                    continue
                line = _line_for_json_key(source.content, script_name)
                findings.append(
                    Finding(
                        rule_id="SI-NPM-001",
                        name=f"npm {script_name} lifecycle script",
                        description=(
                            f"package.json defines {script_name}, which a package manager may run "
                            "during installation."
                        ),
                        severity=Severity.HIGH,
                        category="install_script",
                        language="javascript",
                        explanation=(
                            "Install lifecycle scripts can execute commands automatically "
                            "when a dependency or project is installed. Their presence does "
                            "not prove abuse."
                        ),
                        recommendation=(
                            "Review this script before running npm install, and consider "
                            "installing with lifecycle scripts disabled during inspection."
                        ),
                        evidence=(
                            Evidence(
                                path=source.path,
                                line=line,
                                snippet=redact_text(source.line(line).strip())[:500],
                            ),
                        ),
                        capabilities=(Capability.SHELL_EXECUTION,),
                        metadata={
                            "lifecycle": script_name,
                            "command": redact_text(command)[:500],
                        },
                    )
                )

        for section in _NPM_DEPENDENCY_SECTIONS:
            if (
                len(dependencies) >= MAX_DEPENDENCIES_PER_MANIFEST
                or len(findings) >= MAX_FINDINGS_PER_MANIFEST
            ):
                break
            values = raw.get(section, {})
            if not isinstance(values, Mapping):
                continue
            for dependency_name, raw_specifier in values.items():
                if (
                    len(dependencies) >= MAX_DEPENDENCIES_PER_MANIFEST
                    or len(findings) >= MAX_FINDINGS_PER_MANIFEST
                ):
                    break
                if not isinstance(dependency_name, str) or not isinstance(raw_specifier, str):
                    continue
                specifier = redact_text(raw_specifier)
                source_type = _npm_source_type(raw_specifier)
                pinned = (
                    source_type == "registry"
                    and _EXACT_NPM_VERSION.fullmatch(raw_specifier) is not None
                )
                dependencies.append(
                    DependencyRecord(
                        name=dependency_name,
                        specifier=specifier,
                        ecosystem="npm",
                        scope=section,
                        source_file=source.path,
                        pinned=pinned,
                        source_type=source_type,
                    )
                )
                line = _line_for_json_key(source.content, dependency_name)
                if source_type == "git":
                    findings.append(
                        _dependency_finding(
                            source,
                            line=line,
                            rule_id="SI-DEP-002",
                            name="Git URL dependency",
                            description=(
                                f"{dependency_name} is installed directly from a Git repository."
                            ),
                            severity=Severity.MEDIUM,
                            explanation=(
                                "Git dependencies can change outside a package registry release "
                                "flow. The risk depends on whether a fixed commit is selected."
                            ),
                            recommendation=(
                                "Pin the dependency to a reviewed commit hash where possible."
                            ),
                            metadata={"dependency": dependency_name, "specifier": specifier},
                        )
                    )
                elif not pinned:
                    findings.append(
                        _dependency_finding(
                            source,
                            line=line,
                            rule_id="SI-DEP-001",
                            name="Dependency version is not fixed",
                            description=f"{dependency_name} uses the version range {specifier!r}.",
                            severity=Severity.LOW,
                            explanation=(
                                "A version range can resolve to different code over time. "
                                "This is a supply-chain consideration, not automatically "
                                "a vulnerability."
                            ),
                            recommendation="Use and review a lockfile or pin an exact version.",
                            metadata={"dependency": dependency_name, "specifier": specifier},
                        )
                    )

        return ManifestAnalysis(dependencies=tuple(dependencies), findings=tuple(findings))

    def _analyze_package_lock(self, source: SourceFile) -> ManifestAnalysis:
        try:
            raw = json.loads(source.content)
        except (json.JSONDecodeError, UnicodeError):
            return ManifestAnalysis()
        if not isinstance(raw, Mapping):
            return ManifestAnalysis()
        packages = raw.get("packages", {})
        if not isinstance(packages, Mapping):
            return ManifestAnalysis()

        dependencies: list[DependencyRecord] = []
        findings: list[Finding] = []
        for package_path, details in packages.items():
            if (
                len(dependencies) >= MAX_DEPENDENCIES_PER_MANIFEST
                or len(findings) >= MAX_FINDINGS_PER_MANIFEST
            ):
                break
            if (
                not isinstance(package_path, str)
                or not package_path
                or "node_modules/" not in package_path
                or not isinstance(details, Mapping)
            ):
                continue
            dependency_name = package_path.rsplit("node_modules/", 1)[-1]
            version = details.get("version")
            resolved = details.get("resolved", "")
            if not isinstance(version, str):
                continue
            resolved_text = resolved if isinstance(resolved, str) else ""
            source_type = (
                "git"
                if version.casefold().startswith("git+")
                or resolved_text.casefold().startswith("git+")
                else "registry"
            )
            pinned = (
                _EXACT_NPM_VERSION.fullmatch(version) is not None
                if source_type == "registry"
                else re.search(r"[0-9a-fA-F]{40}(?:[#?]|$)", version + resolved_text) is not None
            )
            safe_version = redact_text(version)
            dependencies.append(
                DependencyRecord(
                    name=dependency_name,
                    specifier=safe_version,
                    ecosystem="npm",
                    scope="lockfile",
                    source_file=source.path,
                    pinned=pinned,
                    source_type=source_type,
                )
            )
            if source_type == "git":
                line = _line_containing(source.content, package_path)
                findings.append(
                    _dependency_finding(
                        source,
                        line=line,
                        rule_id="SI-DEP-002",
                        name="Git URL dependency",
                        description=(
                            f"The lockfile resolves {dependency_name} from a Git repository."
                        ),
                        severity=Severity.MEDIUM,
                        explanation=(
                            "Git dependencies can change outside a package registry release flow."
                        ),
                        recommendation="Pin and review a full commit hash.",
                        metadata={
                            "dependency": dependency_name,
                            "specifier": safe_version,
                            "resolved": redact_text(resolved_text),
                        },
                    )
                )
        return ManifestAnalysis(dependencies=tuple(dependencies), findings=tuple(findings))

    def _analyze_requirements(self, source: SourceFile) -> ManifestAnalysis:
        dependencies: list[DependencyRecord] = []
        findings: list[Finding] = []
        for line_number, raw_line in enumerate(source.content.splitlines(), start=1):
            if (
                len(dependencies) >= MAX_DEPENDENCIES_PER_MANIFEST
                or len(findings) >= MAX_FINDINGS_PER_MANIFEST
            ):
                break
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-e ", "--editable ")):
                line = line.split(maxsplit=1)[1]
            if line.startswith("-"):
                continue
            parsed = _parse_python_requirement(line)
            if parsed is None:
                continue
            dependency_name, specifier, source_type, pinned = parsed
            safe_specifier = redact_text(specifier)
            dependencies.append(
                DependencyRecord(
                    name=dependency_name,
                    specifier=safe_specifier,
                    ecosystem="pypi",
                    scope="requirements",
                    source_file=source.path,
                    pinned=pinned,
                    source_type=source_type,
                )
            )
            finding = _supply_chain_finding_for_dependency(
                source,
                line=line_number,
                dependency_name=dependency_name,
                specifier=safe_specifier,
                source_type=source_type,
                pinned=pinned,
            )
            if finding is not None:
                findings.append(finding)
        return ManifestAnalysis(dependencies=tuple(dependencies), findings=tuple(findings))

    def _analyze_pyproject(self, source: SourceFile) -> ManifestAnalysis:
        try:
            raw = tomllib.loads(source.content)
        except (tomllib.TOMLDecodeError, UnicodeError):
            return ManifestAnalysis()
        declarations: list[tuple[str, str]] = []
        project = raw.get("project", {})
        if isinstance(project, Mapping):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                declarations.extend(
                    ("project", item) for item in dependencies if isinstance(item, str)
                )
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, Mapping):
                for group, items in optional.items():
                    if isinstance(items, list):
                        declarations.extend(
                            (f"project.optional:{group}", item)
                            for item in items
                            if isinstance(item, str)
                        )
        build_system = raw.get("build-system", {})
        if isinstance(build_system, Mapping):
            requirements = build_system.get("requires", [])
            if isinstance(requirements, list):
                declarations.extend(
                    ("build-system", item) for item in requirements if isinstance(item, str)
                )

        dependencies_out: list[DependencyRecord] = []
        findings: list[Finding] = []
        for scope, declaration in declarations[:MAX_DEPENDENCIES_PER_MANIFEST]:
            if len(findings) >= MAX_FINDINGS_PER_MANIFEST:
                break
            parsed = _parse_python_requirement(declaration)
            if parsed is None:
                continue
            dependency_name, specifier, source_type, pinned = parsed
            safe_specifier = redact_text(specifier)
            dependencies_out.append(
                DependencyRecord(
                    name=dependency_name,
                    specifier=safe_specifier,
                    ecosystem="pypi",
                    scope=scope,
                    source_file=source.path,
                    pinned=pinned,
                    source_type=source_type,
                )
            )
            line = _line_containing(source.content, dependency_name)
            finding = _supply_chain_finding_for_dependency(
                source,
                line=line,
                dependency_name=dependency_name,
                specifier=safe_specifier,
                source_type=source_type,
                pinned=pinned,
            )
            if finding is not None:
                findings.append(finding)
        return ManifestAnalysis(dependencies=tuple(dependencies_out), findings=tuple(findings))


def _npm_source_type(specifier: str) -> str:
    normalized = specifier.casefold()
    if normalized.startswith(("git+", "git://", "github:", "http://", "https://")):
        return "git"
    if normalized.startswith(("file:", "link:", "workspace:")):
        return "local"
    return "registry"


def _parse_python_requirement(specifier: str) -> tuple[str, str, str, bool] | None:
    declaration = specifier.split(";", 1)[0].strip()
    name_match = _PYTHON_NAME.match(declaration)
    if name_match is None:
        egg_match = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", declaration)
        if egg_match is None:
            return None
        name = egg_match.group(1)
        return name, declaration, "git" if "git+" in declaration.casefold() else "url", False

    name = name_match.group("name")
    remainder = declaration[name_match.end() :].strip()
    if remainder.startswith("@"):
        target = remainder[1:].strip()
        source_type = "git" if target.casefold().startswith("git+") else "url"
        pinned = (
            source_type == "git" and re.search(r"@[0-9a-fA-F]{40}(?:[#?]|$)", target) is not None
        )
        return name, remainder, source_type, pinned
    pinned = _EXACT_PYTHON_SPECIFIER.fullmatch(remainder) is not None
    return name, remainder or "*", "registry", pinned


def _line_for_json_key(content: str, key: object) -> int:
    escaped = re.escape(str(key))
    pattern = re.compile(rf'^[ \t]*"{escaped}"[ \t]*:')
    for number, line in enumerate(content.splitlines(), start=1):
        if pattern.search(line):
            return number
    return 1


def _line_containing(content: str, value: str) -> int:
    for number, line in enumerate(content.splitlines(), start=1):
        if value.casefold() in line.casefold():
            return number
    return 1


def _supply_chain_finding_for_dependency(
    source: SourceFile,
    *,
    line: int,
    dependency_name: str,
    specifier: str,
    source_type: str,
    pinned: bool,
) -> Finding | None:
    if source_type == "git":
        return _dependency_finding(
            source,
            line=line,
            rule_id="SI-DEP-002",
            name="Git URL dependency",
            description=f"{dependency_name} is installed directly from a Git repository.",
            severity=Severity.MEDIUM,
            explanation=(
                "Git dependencies can change outside a package registry release flow. The risk "
                "depends on whether a fixed commit is selected."
            ),
            recommendation="Pin the dependency to a reviewed commit hash where possible.",
            metadata={"dependency": dependency_name, "specifier": specifier},
        )
    if not pinned:
        return _dependency_finding(
            source,
            line=line,
            rule_id="SI-DEP-001",
            name="Dependency version is not fixed",
            description=f"{dependency_name} uses the version range {specifier!r}.",
            severity=Severity.LOW,
            explanation=(
                "A version range can resolve to different code over time. This is a supply-chain "
                "consideration, not automatically a vulnerability."
            ),
            recommendation="Use and review a lockfile or pin an exact version.",
            metadata={"dependency": dependency_name, "specifier": specifier},
        )
    return None


def _dependency_finding(
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
        category="supply_chain",
        language=source.language,
        explanation=explanation,
        recommendation=recommendation,
        evidence=(
            Evidence(
                path=source.path,
                line=line,
                snippet=redact_text(source.line(line).strip())[:500],
            ),
        ),
        metadata=metadata,
    )
