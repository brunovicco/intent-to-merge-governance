# Public research release qualification (1.0.0)

This final source qualification candidate includes the previously audited lockfile, scoped synthetic HTTP transport, and exact-source SAST review. See [final qualification](final-qualification.md). It is not a published or signed release. Apache-2.0 is a proposed license: the rights holder must confirm it, attribution, repository-specific lab identifiers, and distribution rights before publication. The bundled historical lab references are retained for reproducibility; review them before making the repository public. No automatic upload, signing, tag or publication is performed.

## 1. Verify the exact package before installing anything

```sh
python3 scripts/release_inventory.py verify
```

The candidate inventory is unsigned and includes the maintainer-audited `uv.lock`. Compare the ZIP SHA-256 with a separately trusted digest. Review all inventory differences; never regenerate to conceal unexpected edits. The inventory excludes Git metadata, virtualenv, generated results and caches. It is not a guarantee against files outside its scope; publish only reviewed tracked files. The inventory itself requires an external signature/digest for authenticity.

## 2. Verify the existing locked graph

Use the maintainer-validated uv 0.12.10, or separately review a compatible version. Do not resolve a new lock unless deliberately changing dependencies and starting a new qualification.

```sh
uv --version
python3 scripts/release_inventory.py verify --require-lock
uv lock --check
uv sync --locked --extra telemetry
uv run --locked python -m unittest discover -s tests -v
```

The lockfile is already in the inventory; do not use `seal-lock` again. The command remains available for future maintainer-side candidates without a lock.

## 3. Security and supply chain

Install a trusted copy of Gitleaks (e.g. `brew install gitleaks` on macOS; check version/source), then run:

```sh
bash scripts/public_security.sh
```

The script uses the locked runtime dependency graph to export CycloneDX 1.5 and hashed requirements, runs pip-audit and Bandit, and a high-confidence offline pattern preflight plus Gitleaks directory scan. Bandit runs on Python 3.11. The four exact, digest-pinned public-key fixture findings can be classified in gitleaks-review.json; all other findings remain unresolved. The Bandit report is retained unfiltered and checked against the exact-source review baseline; any unresolved or unexpectedly absent finding or scanner error requires review. Do not suppress findings to get green CI. Reports are stored under ignored `results/public-security/`, which must not be published unreviewed. A fresh report directory is required. The runtime SBOM excludes build isolation dependencies, scanner tools, images, Git, Python, operating system and agent CLIs. Audit coverage is platform/tool-dependent; it is not a comprehensive vulnerability assessment. The scanner tools' top-level versions and CI action commits are pinned, not their entire transitive toolchain. For a repository with history run `gitleaks git --redact` separately. Prior evidence is retained for the pre-final source only; fresh scans are required after final edits.

## 4. Manual release gate

Review findings (including SAST subprocess and HTTP warnings), resolve or document accepted risks, verify the license/NOTICE and private reporting route, inspect tracked files including historical fixtures for secrets and private identifiers, rerun full regression with the locked environment, and confirm the final inventory. Review dependencies and image digests, CI runner and third-party actions. No production claim. Record scanner versions, scan output hashes, lock hash and test evidence. Only after independent review, create a signed Git tag and verify it against the expected signer. Use a separately controlled signing identity. A signed tag does not automatically authenticate arbitrary ZIP bytes; sign the archive checksum separately if distributing a ZIP. The archive candidate itself has no merge authority. Do not push this source candidate or tag until the maintainer has approved all gates.
