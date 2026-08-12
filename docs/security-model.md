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
- Make all network-backed AI analysis explicit and optional.

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

## Archive controls

ZIP and TAR members are normalized before writing. Absolute paths, drive-qualified paths,
`..` traversal, duplicate/colliding destinations, oversized names, symlinks, hard links, device
nodes, and unsupported member types are rejected. File count, individual size, total expanded
size, and compression ratio are bounded. Extraction occurs in a unique temporary directory that
is removed when the loader context closes.

No archive format is treated as perfectly safe. Parser-library vulnerabilities and filesystem
reparse behavior remain residual risks; dependencies and test coverage must be kept current.

## Repository controls

Only `https://github.com/OWNER/REPOSITORY` public URLs are accepted in v0.1. Clone is shallow,
blob-filtered, non-interactive, and passed as a subprocess argument list with `shell=False`.
Global/system Git configuration, credential prompts, hooks, optional locks, and Git LFS smudging
are disabled for the operation. SafeInstall does not run checkout scripts or repository code.

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

## Non-goals and residual risk

SafeInstall v0.1 does not perform dynamic sandboxing, decompilation, full control/data-flow
analysis, package reputation lookup, signature validation, or a malware-free certification.
Static analysis has both false positives and false negatives. A clean report means only that no
supported pattern was observed within configured limits.
