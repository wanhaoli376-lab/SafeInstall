"""Explicit, duplicate-safe scanner plugin registration."""

from __future__ import annotations

import re
from collections.abc import Iterable

from safeinstall.exceptions import PluginError
from safeinstall.models import Finding, SourceFile
from safeinstall.plugins.base import ScannerPlugin
from safeinstall.redaction import redact_text

_PLUGIN_NAME = re.compile(r"^[a-z][a-z0-9-]{1,63}$")


class PluginRegistry:
    """Run only plugin objects deliberately registered by the application."""

    def __init__(self, plugins: Iterable[ScannerPlugin] = ()) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin: ScannerPlugin) -> None:
        name = getattr(plugin, "name", "")
        if not isinstance(name, str) or _PLUGIN_NAME.fullmatch(name) is None:
            raise PluginError("Plugin name must be a lowercase, hyphenated identifier.")
        if name in self._plugins:
            raise PluginError(f"Duplicate plugin name: {name}")
        self._plugins[name] = plugin

    def names(self) -> tuple[str, ...]:
        return tuple(self._plugins)

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for plugin in self._plugins.values():
            try:
                if not plugin.supports(source):
                    continue
                result = plugin.scan(source)
            except Exception as exc:  # noqa: BLE001 - isolate an explicitly trusted extension
                detail = redact_text(str(exc))[:300]
                raise PluginError(f"Plugin {plugin.name} failed: {detail}") from exc
            for finding in result:
                if not isinstance(finding, Finding):
                    raise PluginError(f"Plugin {plugin.name} returned an invalid finding.")
                findings.append(finding)
        return tuple(findings)
