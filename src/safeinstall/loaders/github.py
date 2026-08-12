"""Constrained shallow cloning for public GitHub repositories."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol
from urllib.parse import urlsplit

from safeinstall.exceptions import RepositoryLoadError
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


class GitHubLoader:
    """Clone a validated public GitHub URL into an ephemeral workspace."""

    def __init__(
        self,
        *,
        runner: GitRunner | None = None,
        limits: GitHubLimits | None = None,
        temp_parent: Path | None = None,
    ) -> None:
        self._runner = runner or SubprocessGitRunner()
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
            self._validate_checkout(checkout)
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
