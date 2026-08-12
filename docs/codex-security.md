# Codex Security Review Guide

SafeInstall is unusually exposed to attacker-controlled input: its normal job is to open the
repository or archive an attacker wants reviewed. Codex Security can assist maintainers by
tracing these input-to-impact paths and proposing focused tests. Its output remains a review aid;
maintainers must reproduce every finding, assess reachability, and review the patch.

## Highest-priority review paths

### Parser attack surface

Trace every untrusted byte through ZIP/TAR, YAML, JSON, TOML, Python AST, workflow, manifest, and
text parsers. Look for uncontrolled allocation, deep nesting, decompression bombs, parser object
construction, catastrophic regular expressions, and exceptions that include sensitive content.
Fuzz malformed and boundary-size inputs rather than testing only valid projects.

### Path traversal and archive escape

Follow archive member names through normalization, collision checks, directory creation, and
file writes. Test `../`, absolute paths, Windows drive/UNC forms, mixed separators, trailing dots
and spaces, Unicode aliases, duplicate case-folded names, and long components. Verify the final
destination remains under the unique extraction root.

ZIP/TAR symlinks, hard links, junction-like behavior, and device entries need separate review.
Reject them before extraction; do not attempt to make an unsafe link “safe” after creating it.

### Command and argument injection

Trace GitHub URL, owner, repository, branch-like input, checkout path, and error output into every
subprocess call. Confirm SafeInstall uses a fixed executable, an argument vector, `shell=False`,
the `--` option terminator, non-interactive settings, disabled hooks/LFS smudging, and a timeout.
No target text should become shell source.

### Temporary-directory security

Review creation, containment, permissions, cleanup on exceptions, and lifetime. Ensure scanning
uses in-memory `SourceFile` values after the loader context closes and no target-controlled link
can redirect cleanup or writes outside the temporary root.

### Secret leakage

Search for paths from file content, Git stderr, parser errors, finding metadata, logs, reports,
test snapshots, AI requests, and AI responses to an output boundary. Confirm redaction happens
both when evidence is created and immediately before serialization. Add canary-secret tests for
new formats, while recognizing that regex redaction is not complete DLP.

### Plugin and rule supply chain

Python plugins execute with the host process's authority. Confirm they are never discovered or
imported from a scanned target, and document explicit registration as a trust decision. For YAML
rules, verify safe loading, strict fields, size/depth/alias limits, regex validation, and duplicate
ID handling so data-only rules cannot become code execution.

### GitHub Actions and third-party contributions

Review workflow changes as executable supply-chain changes. Pull-request jobs should have
read-only permissions, pinned actions, no `pull_request_target`, no deployment path, and no
repository/API secrets. Treat contributor tests, build configuration, package hooks, snapshots,
and generated fixtures as untrusted even when the production diff looks small.

For a Release, trace the complete chain from tag to constrained dependency resolution,
PyInstaller output, artifact upload/download, checksum/SBOM generation, draft creation, and final
publication. Confirm that build jobs are read-only, the publish job is tag-only, exact artifacts
come from the same successful workflow run, SHA-256 covers the final ZIPs, and server-side assets
are re-downloaded before the draft is exposed. Treat a stale artifact mix-up or unexpected build
dependency as a supply-chain finding, not merely a packaging error.

### AI analysis and prompt isolation

The attack chain to examine is:

```text
untrusted repository content
        -> prompt/file excerpt
        -> optional AI request
        -> model output or unintended tool/secret access
```

Target README files, `SKILL.md`, MCP descriptions, source comments, filenames, and Git metadata
may say “ignore safety rules,” “reveal secrets,” or imitate system messages. They must remain
user-data JSON beneath fixed higher-priority instructions. The model receives no tools, the API
key is supplied only to the SDK, payloads are bounded and redacted, output is schema-validated,
and AI output cannot alter deterministic findings or risk.

## Suggested recurring review

Use Codex Security after changes to archive/Git loaders, parser dependencies, redaction, workflow
files, plugin registration, or AI context construction. Ask it to produce the exact source-to-sink
path, required attacker control, violated invariant, and a harmless regression test. Reject vague
“suspicious code” claims and fixes that merely hide an error without restoring the invariant.
