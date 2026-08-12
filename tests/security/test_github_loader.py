from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
import pytest

from safeinstall.exceptions import RepositoryLoadError, UnsafeArchiveError
from safeinstall.loaders.github import (
    GitHubLimits,
    GitHubLoader,
    GitRunResult,
    HttpxGitHubArchiveFetcher,
)
from safeinstall.models import TargetKind


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


class SuccessfulArchiveFetcher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Path]] = []

    def fetch(
        self,
        owner: str,
        repository: str,
        destination: Path,
        *,
        limits: GitHubLimits,
    ) -> dict[str, str]:
        assert limits.max_archive_bytes > 0
        self.calls.append((owner, repository, destination))
        with ZipFile(destination, "w", ZIP_DEFLATED) as archive:
            archive.writestr(f"{repository}-fixture/README.md", "# Fixture\n")
            archive.writestr(f"{repository}-fixture/app.py", "# inert fixture\n")
        return {"default_branch": "main", "commit": "b" * 40}


class TraversalArchiveFetcher:
    def fetch(
        self,
        owner: str,
        repository: str,
        destination: Path,
        *,
        limits: GitHubLimits,
    ) -> dict[str, str]:
        del owner, repository, limits
        with ZipFile(destination, "w") as archive:
            archive.writestr("../../outside.txt", "must never escape")
        return {"default_branch": "main", "commit": "c" * 40}


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


def test_checkout_validation_hides_low_level_filesystem_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SuccessfulGitRunner()
    loader = GitHubLoader(runner=runner, temp_parent=tmp_path)

    def fail_validation(_checkout: Path) -> None:
        raise OSError("attacker-controlled filename")

    monkeypatch.setattr(loader, "_validate_checkout", fail_validation)

    with (
        pytest.raises(
            RepositoryLoadError,
            match="Could not safely validate the repository checkout",
        ) as error,
        loader.open("https://github.com/example/project"),
    ):
        pytest.fail("validation failure must stop loading")

    assert "attacker-controlled filename" not in str(error.value)


def test_https_snapshot_fallback_works_without_system_git_and_cleans_workspace(
    tmp_path: Path,
) -> None:
    fetcher = SuccessfulArchiveFetcher()
    loader = GitHubLoader(
        archive_fetcher=fetcher,
        git_available=False,
        temp_parent=tmp_path,
    )

    with loader.open("https://github.com/Example/Project") as target:
        checkout = target.root
        assert target.kind is TargetKind.GITHUB
        assert (checkout / "README.md").is_file()
        assert target.metadata == {
            "repository": "Example/Project",
            "default_branch": "main",
            "commit": "b" * 40,
            "transport": "https_snapshot",
        }

    assert fetcher.calls[0][:2] == ("Example", "Project")
    assert not checkout.exists()


def test_https_snapshot_fallback_still_rejects_archive_traversal(tmp_path: Path) -> None:
    loader = GitHubLoader(
        archive_fetcher=TraversalArchiveFetcher(),
        git_available=False,
        temp_parent=tmp_path,
    )

    with (
        pytest.raises(UnsafeArchiveError, match="unsafe path"),
        loader.open("https://github.com/example/project"),
    ):
        pytest.fail("unsafe archive must not produce a target")

    assert not (tmp_path / "outside.txt").exists()


def test_https_fetcher_uses_only_fixed_github_hosts_and_commit_pinned_snapshot(
    tmp_path: Path,
) -> None:
    commit = "d" * 40
    archive_stream = BytesIO()
    with ZipFile(archive_stream, "w") as archive:
        archive.writestr("project-fixture/README.md", "# Fixture\n")
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        assert request.headers.get("authorization") is None
        if request.url.path == "/repos/example/project":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.path == "/repos/example/project/commits/main":
            return httpx.Response(200, json={"sha": commit})
        if request.url.path == f"/example/project/zip/{commit}":
            return httpx.Response(200, content=archive_stream.getvalue())
        return httpx.Response(404)

    destination = tmp_path / "snapshot.zip"
    fetcher = HttpxGitHubArchiveFetcher(transport=httpx.MockTransport(handler))

    metadata = fetcher.fetch(
        "example",
        "project",
        destination,
        limits=GitHubLimits(),
    )

    assert metadata == {"default_branch": "main", "commit": commit}
    assert destination.read_bytes().startswith(b"PK")
    assert {urlsplit(url).hostname for url in requested} == {
        "api.github.com",
        "codeload.github.com",
    }
    assert requested[-1].endswith(f"/zip/{commit}")
