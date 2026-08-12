import re
from pathlib import Path


def test_pull_request_ci_is_minimal_and_uses_pinned_actions() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "secrets." not in workflow
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "desktop-tests" in workflow
    assert ".[dev,gui,gui-test]" in workflow
    assert "QT_QPA_PLATFORM: offscreen" in workflow


def _release_workflow() -> str:
    return (Path(__file__).parents[2] / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )


def test_release_workflow_cannot_publish_from_a_pull_request() -> None:
    workflow = _release_workflow()

    assert "workflow_dispatch:" in workflow
    assert "tags:" in workflow
    assert "pull_request:" not in workflow
    assert "pull_request_target" not in workflow
    publish = workflow.split("  publish-release:", maxsplit=1)[1]
    assert "github.event_name == 'push'" in publish
    assert "startsWith(github.ref, 'refs/tags/')" in publish


def test_release_workflow_grants_write_only_to_publish_job() -> None:
    workflow = _release_workflow()

    assert "permissions:\n  contents: read" in workflow
    assert workflow.count("contents: write") == 1
    before_publish, publish = workflow.split("  publish-release:", maxsplit=1)
    assert "contents: write" not in before_publish
    assert "permissions:\n      contents: write" in publish
    assert "issues: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "actions: write" not in workflow
    assert "packages: write" not in workflow
    assert "id-token: write" not in workflow
    assert "secrets." not in workflow
    assert "${{ secrets.OPENAI_API_KEY }}" not in workflow


def test_release_workflow_pins_actions_and_separates_publish() -> None:
    workflow = _release_workflow()

    for job in (
        "validate-release",
        "windows-build",
        "macos-build",
        "release-metadata",
        "publish-release",
    ):
        assert f"  {job}:" in workflow
    publish = workflow.split("  publish-release:", maxsplit=1)[1]
    assert "validate-release" in publish
    assert "windows-build" in publish
    assert "macos-build" in publish
    assert "release-metadata" in publish
    assert "gh release create" in publish
    assert "--draft" in publish
    assert "gh release edit" in publish
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)


def test_release_workflow_smoke_scans_without_ai_and_checks_assets() -> None:
    workflow = _release_workflow()

    assert "--smoke-test" in workflow
    assert "--smoke-scan" in workflow
    assert "System.Diagnostics.ProcessStartInfo" in workflow
    assert "ArgumentList.Add" in workflow
    assert ".ExitCode" in workflow
    assert "Remove-Item Env:OPENAI_API_KEY" in workflow
    assert "unset OPENAI_API_KEY" in workflow
    assert "SafeInstall-Windows-x64.zip" in workflow
    assert "SafeInstall-macOS-unsigned.zip" in workflow
    assert "SHA256SUMS.txt" in workflow
    assert "SBOM.json" in workflow
    assert "cyclonedx-bom==" in workflow
    assert "tools/release.py generate-checksums" in workflow
    assert "tools/release.py verify-assets" in workflow


def test_release_workflow_does_not_use_floating_action_refs() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
