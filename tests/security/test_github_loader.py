from pathlib import Path

import pytest

from safeinstall.exceptions import RepositoryLoadError
from safeinstall.loaders.github import GitHubLoader, GitRunResult


class RecordingGitRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []

    def run(self, args: tuple[str, ...], *, env: dict[str, str], timeout: float) -> GitRunResult:
        self.calls.append(args)
        self.environments.append(env.copy())
        return GitRunResult(returncode=0, stdout="", stderr="")


class SuccessfulGitRunner(RecordingGitRunner):
    def run(self, args: tuple[str, ...], *, env: dict[str, str], timeout: float) -> GitRunResult:
        self.calls.append(args)
        self.environments.append(env.copy())
        if "clone" in args:
            checkout = Path(args[-1])
            checkout.mkdir()
            (checkout / "README.md").write_text("# Fixture\n", encoding="utf-8")
            return GitRunResult(returncode=0, stdout="", stderr="")
        if args[-2:] == ("rev-parse", "HEAD"):
            return GitRunResult(returncode=0, stdout="a" * 40 + "\n", stderr="")
        if args[-2:] == ("branch", "--show-current"):
            return GitRunResult(returncode=0, stdout="main\n", stderr="")
        return GitRunResult(returncode=1, stdout="", stderr="unexpected command")


def test_github_url_with_shell_metacharacters_is_rejected_before_git(
    tmp_path: Path,
) -> None:
    runner = RecordingGitRunner()
    loader = GitHubLoader(runner=runner, temp_parent=tmp_path)

    with (
        pytest.raises(RepositoryLoadError, match="Invalid GitHub repository URL"),
        loader.open("https://github.com/example/repo;whoami"),
    ):
        pytest.fail("invalid URL must not reach the loader context")

    assert runner.calls == []


def test_github_clone_uses_canonical_url_as_one_argument_and_cleans_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "attacker-controlled-hooks")
    monkeypatch.setenv("GIT_ASKPASS", "attacker-controlled-askpass")
    runner = SuccessfulGitRunner()
    loader = GitHubLoader(runner=runner, temp_parent=tmp_path)

    with loader.open("https://github.com/Example/Project") as target:
        checkout = target.root
        assert target.metadata == {
            "repository": "Example/Project",
            "default_branch": "main",
            "commit": "a" * 40,
        }
        clone_args = runner.calls[0]
        url_index = clone_args.index("https://github.com/Example/Project.git")
        assert clone_args[url_index - 1] == "--"
        assert clone_args[url_index + 1] == str(checkout)
        clone_environment = runner.environments[0]
        assert "GIT_CONFIG_COUNT" not in clone_environment
        assert "GIT_CONFIG_KEY_0" not in clone_environment
        assert "GIT_CONFIG_VALUE_0" not in clone_environment
        assert "GIT_ASKPASS" not in clone_environment
        assert clone_environment["GIT_ALLOW_PROTOCOL"] == "https"

    assert not checkout.exists()
