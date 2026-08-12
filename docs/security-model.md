# Security Model

SafeInstall is a parser and analyzer for hostile input. A repository being popular, public, or
valid source code does not make any of its bytes trustworthy.

## Security objectives

- Never execute, import, build, or install target content in the default scan path.
- Keep archive members and temporary repository data inside their assigned roots.
- Pass external values as subprocess arguments, never through a shell command string.
- Bound file count, file size, archive expansion, parser input, Git transfer, and AI context.
- Redact secrets when a finding is created and again at every output/API boundary.
- Preserve evidence and distinguish observed facts from inference and advice.
- Make all network-backed AI analysis explicit and optional in both CLI and desktop interfaces.

## Trust boundaries

| Input | Trust | Main controls |
|---|---|---|
| Local file/folder | Untrusted | no link traversal, bounded discovery, text-only analysis |
| ZIP/TAR archive | Hostile | manual member validation, path containment, link/device rejection, expansion limits |
| GitHub URL/repository | Hostile | strict public HTTPS URL grammar, argument-vector Git, hooks/LFS disabled, timeout and size limits |
| YAML/JSON/TOML/manifests | Hostile data | safe parsers, shape validation, size/depth/alias limits where applicable |
| README/Skill/prompt/tool text | Hostile data and possible prompt injection | never promoted to instructions; redacted bounded excerpts only in opt-in AI mode |
| Declarative rule file | Untrusted configuration | `safe_load`, strict schema, regex size/compile validation, duplicate rejection |
| Python scanner plugin | Trusted executable code | explicit registration only; no discovery from targets |
| AI response | Untrusted advisory output | strict JSON validation, redaction, cannot alter local findings or risk |
| Desktop path/URL input | Untrusted selection | local classification only, one target at a time, explicit start action, existing loaders remain authoritative |
| Report export path | User-selected output | no symlink output, exclusive create by default, explicit overwrite confirmation, atomic replacement |

## Archive controls

ZIP and TAR members are normalized before writing. Absolute paths, drive-qualified paths,
`..` traversal, duplicate/colliding destinations, oversized names, symlinks, hard links, device
nodes, and unsupported member types are rejected. File count, individual size, total expanded
size, and compression ratio are bounded. Extraction occurs in a unique temporary directory that
is removed when the loader context closes.

No archive format is treated as perfectly safe. Parser-library vulnerabilities and filesystem
reparse behavior remain residual risks; dependencies and test coverage must be kept current.

## Repository controls

Only `https://github.com/OWNER/REPOSITORY` public URLs are accepted in v0.2 alpha. When Git is
available, clone is shallow, blob-filtered, non-interactive, and passed as a subprocess argument
list with `shell=False`. Global/system Git configuration, credential prompts, hooks, optional
locks, and Git LFS smudging are disabled.

When Git is unavailable, SafeInstall obtains the public default branch and 40-character commit
SHA from `api.github.com`, then streams a commit-pinned ZIP from `codeload.github.com`. Redirects
are disabled, response metadata and compressed bytes are bounded, no token or ambient GitHub
credential is sent, and the result passes through the existing traversal/link-safe archive
loader. Both transports use temporary directories and do not run checkout scripts or repository
code. Anonymous API rate limiting and compromise of GitHub/TLS remain residual availability and
supply-chain risks.

## Secret handling

Detection values are masked at source. Evidence, metadata, exception details, target identifiers,
JSON, Markdown, terminal output, and AI payloads pass through centralized redaction. Redaction is
defense in depth, not a complete data-loss-prevention system: unknown secret formats or secret
fragments can evade pattern matching. Users should avoid AI mode for code that cannot leave their
environment and should inspect reports before publishing them.

## AI isolation

AI is disabled by default. When explicitly enabled, SafeInstall sends a limited number of
locally produced findings and bounded prompt excerpts. Fixed developer instructions state that
target text is untrusted data, while the target appears in a separate user input. No tools are
made available to the model, API storage is disabled by the client request, and the response is
schema-validated and redacted. The AI result is explanatory; it cannot suppress local evidence,
change the deterministic score, execute a tool, or read the process environment.

## Desktop and packaging controls

The GUI never implements a second scan path. It invokes `scan_target()` on a `QThread`, and only
Qt presentation code runs on the main thread. Drag-and-drop does not start a scan automatically.
Navigation cannot interrupt and forcibly terminate an active parser thread. Errors are mapped to
plain-language pages; bounded, redacted technical text is available separately without a Python
traceback.

AI is off on first launch. The GUI does not check a key at startup, store a key, or import the
optional OpenAI SDK for a normal scan. Enabling AI checks `OPENAI_API_KEY` and SDK availability;
failure leaves all local features available. No telemetry, crash upload, persistent scan history,
or automatic executable updater is included.

Exports reuse the core renderers so final recursive redaction still applies. A new destination is
created exclusively with restricted permissions. Existing files require confirmation and are
replaced through a temporary file in the same directory; symlink destinations are rejected.

Portable packages are platform-specific one-folder builds. Built-in YAML rule data is collected,
while the optional OpenAI SDK is excluded. Release builds use reviewed Python 3.11 constraints.
The workflow is not triggered by pull requests, uses full-SHA action pins, and gives build/metadata
jobs only `contents: read`; only the tag-only publish job receives `contents: write`.

Windows packaging performs startup plus local folder/ZIP smoke scans after removing
`OPENAI_API_KEY`. Publication requires both platform artifacts, a CycloneDX SBOM from the
constrained Python application dependency environment, and SHA-256 over the exact final ZIPs.
The SBOM does not claim binary- or OS-level completeness. Assets are first uploaded to a private draft, downloaded,
and revalidated before the draft becomes a prerelease. Windows code signing, macOS Developer ID
signing, and notarization remain unresolved distribution risks and are disclosed to users.

## Non-goals and residual risk

SafeInstall v0.2 alpha does not perform dynamic sandboxing, decompilation, full control/data-flow
analysis, package reputation lookup, signature validation, or a malware-free certification.
Static analysis has both false positives and false negatives. A clean report means only that no
supported pattern was observed within configured limits.
