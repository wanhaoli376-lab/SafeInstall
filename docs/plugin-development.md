# Plugin Development

The v0.1 plugin framework is intentionally small. A plugin is trusted in-process Python code,
not a sandboxed extension. Importing one can do anything the SafeInstall process can do, so
SafeInstall never searches a target repository for plugins and never imports one automatically.

```python
from safeinstall.models import Finding, SourceFile
from safeinstall.plugins.base import ScannerPlugin


class ExampleScanner(ScannerPlugin):
    name = "example-scanner"

    def supports(self, source: SourceFile) -> bool:
        return source.path.endswith(".example")

    def scan(self, source: SourceFile) -> tuple[Finding, ...]:
        # Parse source.content as untrusted data. Return validated findings.
        return ()
```

Trusted callers register an object explicitly:

```python
from safeinstall.core import scan_target
from safeinstall.plugins.registry import PluginRegistry

registry = PluginRegistry([ExampleScanner()])
report = scan_target("./target", plugin_registry=registry)
```

Plugin names must be unique lowercase identifiers and findings must be real `Finding` instances.
Exceptions are isolated, redacted, and surfaced as `PluginError`; SafeInstall does not silently
discard a failed trusted scanner.

## Plugin requirements

- Never execute, import, build, or install target content.
- Parse `SourceFile.content` within explicit time, size, and nesting limits.
- Report exact evidence and distinguish observations from inference.
- Pass any evidence or metadata through central redaction helpers.
- Make network use separately opt-in and document what leaves the machine.
- Add positive, negative, resource-limit, and malformed-input tests.

There is no online store, automatic entry-point discovery, or security certification for plugins
in v0.1. A future SDK must define version compatibility and isolation before those features can
be considered stable.
