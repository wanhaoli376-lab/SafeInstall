# Maintainer release process

This document is the publication checklist for SafeInstall desktop prereleases. A release is
complete only when every required asset is present and independently verified.

## Version contract

SafeInstall uses PEP 440 for the Python package and a reader-friendly Git tag:

- Python package: `0.2.0a2`
- Git tag and GitHub Release: `v0.2.0-alpha.2`

Run the checked-in validator before tagging:

```console
python tools/release.py validate-version --root . --tag v0.2.0-alpha.2
```

## Before tagging

1. Confirm `main` is clean and synchronized with `origin/main`.
2. Confirm the intended commit is on `main`.
3. Update `pyproject.toml`, `src/safeinstall/__init__.py`, and `CHANGELOG.md`.
4. Confirm the release notes exist at `docs/releases/<tag>.md`.
5. Run:

   ```console
   python -m ruff check .
   python -m ruff format --check .
   python -m pytest
   ```

6. Confirm the required GitHub checks pass for Python 3.11, 3.12, 3.13, and the Windows GUI job.
7. Run a local Windows PyInstaller build, `--smoke-test`, and `--smoke-scan` when preparing a
   Windows-focused release.
8. Review dependency and workflow changes, including `constraints/release-python311.txt`.

Do not tag when any required check is failing.

## Build-only rehearsal

Run the **Build and publish desktop alpha** workflow with `workflow_dispatch`. A manual run builds
and verifies Windows, macOS, checksums, and the SBOM, but the publish job is skipped. Inspect the
`verified-release-assets` artifact before creating a tag.

Release builds use `constraints/release-python311.txt`; normal development keeps compatible ranges
in `pyproject.toml`. Updating a release pin requires dependency review and another rehearsal.

## Publish

Create an annotated tag on the reviewed commit and push only that tag:

```console
git tag -a v0.2.0-alpha.2 -m "SafeInstall v0.2.0-alpha.2"
git push origin v0.2.0-alpha.2
```

The tag workflow then performs these gates:

1. validate the tag/package/runtime version mapping;
2. build the constrained Windows portable application;
3. run Windows `--smoke-test` and non-AI folder/ZIP `--smoke-scan` checks;
4. build the unsigned Apple Silicon application on `macos-15`, verify runner and Mach-O arm64
   architecture, validate Info.plist versions, and smoke-test the application;
5. download both exact build artifacts into one metadata job;
6. generate a CycloneDX SBOM from the constrained Python application dependency environment;
7. calculate SHA-256 over the two final ZIP files;
8. verify exact names, ZIP structure, non-empty files, checksums, and SBOM metadata;
9. create a private draft prerelease with exactly four assets;
10. download the server-side draft assets and verify them again; and
11. publish the draft as a prerelease only after all verification succeeds.

Only `publish-release` has `contents: write`. Build and metadata jobs have `contents: read`.
Pull requests cannot trigger this workflow, and manual dispatch cannot publish.

## Required assets

- `SafeInstall-Windows-x64.zip`
- `SafeInstall-macOS-arm64-unsigned.zip`
- `SHA256SUMS.txt`
- `SBOM.json`

Do not publish a release with a missing, renamed, empty, or unverified asset. GitHub Actions artifact
digests are not substitutes for the SHA-256 hashes of the final release ZIP files.

## Failure handling

If a build or metadata job fails, no Release is created. Fix the cause and rerun the build-only
workflow before retagging.

If publication fails after a private draft is created, leave it private while investigating.
Verify its assets, then either resume publication through an explicitly reviewed manual recovery
or delete only that exact draft through the GitHub UI and rerun the tag workflow. Never publish a
partial draft, reuse assets from a different workflow run, or silently replace an existing public
asset.

## Post-publication verification

1. Confirm the Release tag is exact and **Pre-release** is enabled.
2. Confirm the Release is not a draft.
3. Confirm exactly four uploaded assets are listed.
4. Download all four files into an empty directory.
5. Run:

   ```console
   python tools/release.py verify-assets --directory <download-directory> \
     --root . --tag v0.2.0-alpha.2
   ```

6. Open the Windows ZIP and confirm `SafeInstall/SafeInstall.exe` exists.
7. Record the Release URL, commit SHA, workflow run, and verification result in the release handoff.

## Recommended `main` branch protection

Repository administrators should configure **Settings → Branches → Add branch protection rule**
for `main`:

- require a pull request before merging;
- require the status checks `Python 3.11`, `Python 3.12`, `Python 3.13`, and
  `Desktop GUI (Windows, Python 3.11)`;
- require branches to be up to date before merging;
- block force pushes; and
- block branch deletion.

Do not claim these controls are active until the GitHub settings page or branch-protection API
confirms them. Keep release write permission out of pull-request workflows.
