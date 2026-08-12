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
