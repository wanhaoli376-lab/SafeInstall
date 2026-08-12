from safeinstall.models import Severity, SourceFile
from safeinstall.scanners.dependencies import DependencyScanner


def test_package_json_lists_dependencies_and_flags_lifecycle_and_unpinned_specs() -> None:
    source = SourceFile(
        path="package.json",
        language="json",
        content=(
            "{\n"
            '  "scripts": {\n'
            '    "postinstall": "node scripts/setup.js"\n'
            "  },\n"
            '  "dependencies": {\n'
            '    "exact-package": "1.2.3",\n'
            '    "floating-package": "^4.0.0",\n'
            '    "git-package": "git+https://github.com/example/project.git"\n'
            "  }\n"
            "}\n"
        ),
    )

    analysis = DependencyScanner().analyze(source)

    assert [(item.name, item.pinned, item.source_type) for item in analysis.dependencies] == [
        ("exact-package", True, "registry"),
        ("floating-package", False, "registry"),
        ("git-package", False, "git"),
    ]
    assert [(item.rule_id, item.severity) for item in analysis.findings] == [
        ("SI-NPM-001", Severity.HIGH),
        ("SI-DEP-001", Severity.LOW),
        ("SI-DEP-002", Severity.MEDIUM),
    ]
    assert analysis.findings[0].evidence[0].line == 3


def test_python_manifests_list_pinned_unpinned_and_git_dependencies() -> None:
    requirements = SourceFile(
        path="requirements.txt",
        language="text",
        content=(
            "httpx==0.28.1\n"
            "pydantic>=2.7\n"
            "sample @ git+https://github.com/example/sample.git@main\n"
        ),
    )
    pyproject = SourceFile(
        path="pyproject.toml",
        language="toml",
        content=(
            "[project]\n"
            'dependencies = ["rich==13.9.4", "typer~=0.15"]\n'
            "[build-system]\n"
            'requires = ["hatchling>=1.26"]\n'
        ),
    )

    requirements_analysis = DependencyScanner().analyze(requirements)
    pyproject_analysis = DependencyScanner().analyze(pyproject)

    assert [(item.name, item.pinned) for item in requirements_analysis.dependencies] == [
        ("httpx", True),
        ("pydantic", False),
        ("sample", False),
    ]
    assert [item.source_type for item in requirements_analysis.dependencies] == [
        "registry",
        "registry",
        "git",
    ]
    assert [(item.name, item.scope) for item in pyproject_analysis.dependencies] == [
        ("rich", "project"),
        ("typer", "project"),
        ("hatchling", "build-system"),
    ]
    assert {finding.rule_id for finding in pyproject_analysis.findings} == {"SI-DEP-001"}


def test_package_lock_lists_resolved_versions_without_marking_them_floating() -> None:
    source = SourceFile(
        path="package-lock.json",
        language="json",
        content=(
            "{\n"
            '  "lockfileVersion": 3,\n'
            '  "packages": {\n'
            '    "": {},\n'
            '    "node_modules/locked-package": {\n'
            '      "version": "2.3.4",\n'
            '      "resolved": "https://registry.npmjs.org/locked-package/-/locked-package-2.3.4.tgz"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )

    analysis = DependencyScanner().analyze(source)

    assert [(item.name, item.specifier, item.pinned) for item in analysis.dependencies] == [
        ("locked-package", "2.3.4", True)
    ]
    assert analysis.findings == ()
