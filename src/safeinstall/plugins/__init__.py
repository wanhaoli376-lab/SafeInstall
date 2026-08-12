"""Explicit scanner plugin interface and registry."""

from safeinstall.plugins.base import ScannerPlugin
from safeinstall.plugins.registry import PluginRegistry

__all__ = ["PluginRegistry", "ScannerPlugin"]
