"""Constrained shallow cloning for public GitHub repositories."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

from safeinstall import __version__
from safeinstall.exceptions import RepositoryLoadError
from safeinstall.loaders.archive import ArchiveLoader
from safeinstall.loaders.base import LoadedTarget
from safeinstall.models import TargetKind
from safeinstall.redaction import redact_text

_GITHUB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


@dataclass(frozen=True, slots=True)
class GitRunResult:
    returncode: int
    stdout: str
    stderr: str


class GitRunner(Protocol):
    def run(
        self,
        args: tuple[str, ...],
        *,
        env: dict[str, str],
        timeout: float,
    ) -> GitRunResult:
        """Run a Git argument vector without a shell."""


class GitHubArchiveFetcher(Protocol):
    def fetch(
        self,
        owner: str,
        repository: str,
        destination: Path,
        *,
        limits: GitHubLimits,
    ) -> dict[str, str]:
        """Download one public repository snapshot without executing target content."""


class SubprocessGitRunner:
    """Production Git adapter with non-interactive, shell-free execution."""

    def run(
        self,
        args: tuple[str, ...],
        *,
        env: dict[str, str],
        timeout: float,
    ) -> GitRunResult:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed executable and validated arguments
                args,
                check=False,
                capture_output=True,
                env=env,
                shell=False,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RepositoryLoadError(f"Git command failed or timed out: {exc}") from exc
        return GitRunResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


@dataclass(frozen=True, slots=True)
class GitHubLimits:
    clone_timeout_seconds: float = 60.0
    max_checkout_bytes: int = 500_000_000
    max_checkout_files: int = 100_000
    max_archive_bytes: int = 100_000_000
    max_metadata_bytes: int = 1_000_000


class HttpxGitHubArchiveFetcher:
    """Fetch a commit-pinned public snapshot from fixed GitHub HTTPS hosts."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def fetch(
        self,
        owner: str,
        repository: str,
        destination: Path,
        *,
        limits: GitHubLimits,
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": f"SafeInstall/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        timeout = httpx.Timeout(limits.clone_timeout_seconds)
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=timeout,
                transport=self._transport,
            ) as client:
                repository_data = _get_json(
                    client,
                    f"https://api.github.com/repos/{owner}/{repository}",
                    headers=headers,
                    max_bytes=limits.max_metadata_bytes,
                )
                branch = repository_data.get("default_branch")
                if not _safe_api_name(branch):
                    raise RepositoryLoadError("GitHub returned invalid default-branch metadata.")
                commit_data = _get_json(
                    client,
                    (
                        f"https://api.github.com/repos/{owner}/{repository}/commits/"
                        f"{quote(branch, safe='')}"
                    ),
                    headers=headers,
                    max_bytes=limits.max_metadata_bytes,
                )
                commit = commit_data.get("sha")
                if not isinstance(commit, str) or re.fullmatch(r"[0-9a-fA-F]{40}", commit) is None:
                    raise RepositoryLoadError("GitHub returned invalid commit metadata.")
                commit = commit.casefold()
                archive_headers = {
                    "Accept": "application/zip",
                    "User-Agent": f"SafeInstall/{__version__}",
                }
                _download_bounded(
                    client,
                    f"https://codeload.github.com/{owner}/{repository}/zip/{commit}",
                    destination,
                    headers=archive_headers,
                    max_bytes=limits.max_archive_bytes,
                )
        except RepositoryLoadError:
            raise
        except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
            destination.unlink(missing_ok=True)
            raise RepositoryLoadError(
                "Could not download the public GitHub repository snapshot."
            ) from exc
        return {"default_branch": branch, "commit": commit}


class GitHubLoader:
    """Clone a validated public GitHub URL into an ephemeral workspace."""

    def __init__(
        self,
        *,
        runner: GitRunner | None = None,
        archive_fetcher: GitHubArchiveFetcher | None = None,
        git_available: bool | None = None,
        limits: GitHubLimits | None = None,
        temp_parent: Path | None = None,
    ) -> None:
        self._runner = runner or SubprocessGitRunner()
        self._archive_fetcher = archive_fetcher or HttpxGitHubArchiveFetcher()
        self._git_available = (
            runner is not None or shutil.which("git") is not None
            if git_available is None
            else git_available
        )
        self._limits = limits or GitHubLimits()
        self._temp_parent = temp_parent

    def supports(self, target: str) -> bool:
        try:
            _parse_github_url(target)
        except RepositoryLoadError:
            return False
        return True

    @contextmanager
    def open(self, target: str | Path) -> Iterator[LoadedTarget]:
        owner, repository = _parse_github_url(str(target))
        if not self._git_available:
            with self._open_archive(owner, repository) as loaded:
                yield loaded
            return

        with self._open_git(owner, repository) as loaded:
            yield loaded

    @contextmanager
    def _open_git(self, owner: str, repository: str) -> Iterator[LoadedTarget]:
        canonical_url = f"https://github.com/{owner}/{repository}.git"
        temp_parent = str(self._temp_parent) if self._temp_parent is not None else None
        with TemporaryDirectory(prefix="safeinstall-github-", dir=temp_parent) as temp_name:
            checkout = Path(temp_name) / "repository"
            environment = _git_environment()
            clone_args = (
                "git",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "filter.lfs.smudge=",
                "-c",
                "filter.lfs.required=false",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--no-tags",
                "--single-branch",
                "--",
                canonical_url,
                str(checkout),
            )
            result = self._runner.run(
                clone_args,
                env=environment,
                timeout=self._limits.clone_timeout_seconds,
            )
            if result.returncode != 0:
                detail = redact_text(result.stderr.strip())[:500]
                raise RepositoryLoadError(f"Git clone failed: {detail or 'unknown error'}")
            try:
                self._validate_checkout(checkout)
            except RepositoryLoadError:
                raise
            except OSError as exc:
                raise RepositoryLoadError(
                    "Could not safely validate the repository checkout."
                ) from exc
            commit = self._git_value(checkout, ("rev-parse", "HEAD"), environment)
            branch = self._git_value(checkout, ("branch", "--show-current"), environment)
            yield LoadedTarget(
                root=checkout,
                source=canonical_url,
                kind=TargetKind.GITHUB,
                metadata={
                    "repository": f"{owner}/{repository}",
                    "default_branch": branch or "detached",
                    "commit": commit,
                },
            )

    @contextmanager
    def _open_archive(self, owner: str, repository: str) -> Iterator[LoadedTarget]:
        canonical_url = f"https://github.com/{owner}/{repository}.git"
        temp_parent = str(self._temp_parent) if self._temp_parent is not None else None
        with TemporaryDirectory(prefix="safeinstall-github-", dir=temp_parent) as temp_name:
            workspace = Path(temp_name)
            archive = workspace / "repository.zip"
            metadata = self._archive_fetcher.fetch(
                owner,
                repository,
                archive,
                limits=self._limits,
            )
            archive_loader = ArchiveLoader(temp_parent=workspace)
            with archive_loader.open(archive) as extracted:
                checkout = _snapshot_root(extracted.root)
                self._validate_checkout(checkout)
                yield LoadedTarget(
                    root=checkout,
                    source=canonical_url,
                    kind=TargetKind.GITHUB,
                    metadata={
                        "repository": f"{owner}/{repository}",
                        "default_branch": redact_text(metadata["default_branch"])[:200],
                        "commit": redact_text(metadata["commit"])[:200],
                        "transport": "https_snapshot",
                    },
                )

    def _git_value(
        self, checkout: Path, command: tuple[str, ...], environment: dict[str, str]
    ) -> str:
        result = self._runner.run(
            ("git", "-C", str(checkout), *command),
            env=environment,
            timeout=min(10.0, self._limits.clone_timeout_seconds),
        )
        if result.returncode != 0:
            return "unavailable"
        return redact_text(result.stdout.strip())[:200]

    def _validate_checkout(self, checkout: Path) -> None:
        if not checkout.is_dir():
            raise RepositoryLoadError("Git clone did not create a checkout directory.")
        file_count = 0
        total_bytes = 0
        for current, directories, filenames in os.walk(checkout, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name for name in directories if not (current_path / name).is_symlink()
            ]
            for filename in filenames:
                path = current_path / filename
                if path.is_symlink():
                    continue
                file_count += 1
                total_bytes += path.stat().st_size
                if file_count > self._limits.max_checkout_files:
                    raise RepositoryLoadError("Repository checkout contains too many files.")
                if total_bytes > self._limits.max_checkout_bytes:
                    raise RepositoryLoadError("Repository checkout exceeds the size limit.")


def _parse_github_url(target: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError as exc:
        raise RepositoryLoadError("Invalid GitHub repository URL.") from exc
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.hostname.casefold() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RepositoryLoadError("Invalid GitHub repository URL.")

    path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
    parts = path.split("/")
    if len(parts) != 3 or parts[0] != "":
        raise RepositoryLoadError("Invalid GitHub repository URL.")
    owner, repository = parts[1], parts[2]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        owner in {".", ".."}
        or repository in {".", ".."}
        or _GITHUB_NAME.fullmatch(owner) is None
        or _GITHUB_NAME.fullmatch(repository) is None
    ):
        raise RepositoryLoadError("Invalid GitHub repository URL.")
    return owner, repository


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
        and key.upper() not in {"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"}
    }
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _get_json(
    client: httpx.Client,
    url: str,
    *,
    headers: dict[str, str],
    max_bytes: int,
) -> dict[str, object]:
    with client.stream("GET", url, headers=headers) as response:
        _require_success(response)
        _validate_content_length(response, max_bytes)
        content = bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > max_bytes:
                raise RepositoryLoadError("GitHub metadata exceeded the size limit.")
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise RepositoryLoadError("GitHub returned invalid repository metadata.")
    return parsed


def _download_bounded(
    client: httpx.Client,
    url: str,
    destination: Path,
    *,
    headers: dict[str, str],
    max_bytes: int,
) -> None:
    try:
        with client.stream("GET", url, headers=headers) as response:
            _require_success(response)
            _validate_content_length(response, max_bytes)
            copied = 0
            with destination.open("xb") as output:
                for chunk in response.iter_bytes():
                    copied += len(chunk)
                    if copied > max_bytes:
                        raise RepositoryLoadError(
                            "GitHub repository snapshot exceeded the download limit."
                        )
                    output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _require_success(response: httpx.Response) -> None:
    if response.status_code == 200:
        return
    if response.status_code == 404:
        raise RepositoryLoadError("GitHub repository does not exist or is not public.")
    if response.status_code in {403, 429}:
        raise RepositoryLoadError("GitHub API is unavailable or rate-limited.")
    raise RepositoryLoadError("GitHub returned an unsuccessful response.")


def _validate_content_length(response: httpx.Response, max_bytes: int) -> None:
    value = response.headers.get("content-length")
    if value is None:
        return
    try:
        length = int(value)
    except ValueError as exc:
        raise RepositoryLoadError("GitHub returned an invalid content length.") from exc
    if length < 0 or length > max_bytes:
        raise RepositoryLoadError("GitHub response exceeded the download size limit.")


def _safe_api_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _snapshot_root(root: Path) -> Path:
    entries = list(root.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return root
