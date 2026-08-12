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


def test_desktop_artifact_workflow_has_no_pr_secrets_or_release_permission() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "tags:" in workflow
    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "gh release" not in workflow
    assert "action-gh-release" not in workflow
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
