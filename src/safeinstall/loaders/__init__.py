"""Safe target loaders."""

from safeinstall.loaders.archive import ArchiveLoader
from safeinstall.loaders.base import LoadedTarget
from safeinstall.loaders.discovery import FileDiscoverer
from safeinstall.loaders.github import GitHubLoader
from safeinstall.loaders.local import LocalLoader

__all__ = [
    "ArchiveLoader",
    "FileDiscoverer",
    "GitHubLoader",
    "LoadedTarget",
    "LocalLoader",
]
