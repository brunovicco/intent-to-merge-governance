# 1.0.0 — final source qualification candidate

**Publication HOLD.** Research/reference implementation only. No merge authority or production readiness. This package incorporates the maintainer's exact, previously audited lockfile, not a new resolution. The supplied sealed inventory matched all 669 files before changes. The lock SHA-256 is `891e8c8dd597002fd42e9da05725ba2a50502308b0f851ae875ed8a0ff1b2061`.

## Prior evidence (not a fresh scan)

The preceding security-remediation source passed 217 tests on the maintainer's Mac, reported no known vulnerabilities across seven audited Python dependencies (cryptography 50.0.2), and recorded 15/15 distributed synthetic decisions after the HTTP changes. The received Compose report lacked its external public trust inventory, so the builder has not independently replayed its signatures. The report's trust digest was supplied separately in the terminal output. See `examples/public-release/remediation-evidence/`; original evidence file hashes are recorded there. These reports refer to the **pre-final source**, not this modified source. The SBOM covers the Python graph only, not OS, image, build tools, or scanners.

## Bandit review

`docs/bandit-review.json` records each of the 62 original findings, exact source and line hashes, severity, confidence, disposition and rationale. The proposed review is restricted to the lab threat model and requires maintainer acceptance. Five B101 demo assertions were replaced by explicit exceptions. Fifty-seven other findings remain expected: 13 B404 imports, 22 B603 process calls, 17 B607 PATH lookups, two B311 deterministic benchmark PRNGs, two B608 SQL constructions, and one B108 container tmpfs. These are not all false positives: process execution and PATH risk remain. Do not expose the runtime to hostile repositories or operate with privileged credentials. The raw scanner runs without exclusions; `review_bandit.py` compares the current findings to the exact reviewed code hashes and rejects new, duplicate, missing or changed findings and scanner errors. It is not independent security approval. The five remediated B101 findings must be absent in a fresh scan. This strict baseline may require a new review if tool behavior or source changes.

## SQLite and build

Three known context-manager connection leaks were addressed using `contextlib.closing` (checkpoint CLI and two test cases). This is not a complete connection-lifecycle audit. The old signed verifier and historical corpus are unchanged. The control-plane image pins the observed Python base manifest and installs all seven audited packages from the lock using wheel hashes, no source-build fallback, no dependency resolution, and pip check. Project code is loaded directly via PYTHONPATH, avoiding unpinned setuptools build dependencies. No claim of bit-for-bit image reproducibility, OS vulnerability coverage or fully locked toolchain. The new Docker build has not been run by the builder. The macOS lock contains multiple platform wheels; an unsupported platform must fail rather than build an unreviewed wheel. CI uv version matches the maintainer's observed 0.12.10.

## Maintainer gates

1. Verify the new archive and sealed inventory before installation. Use uv 0.12.10 (or separately reviewed compatible version), `uv lock --check`, then `uv sync --locked --extra telemetry`; never implicitly resolve a new lock. Run all 224 tests.
2. Run `bash scripts/public_security.sh results/final-security` in the new tree. Review both raw and classified outputs; unexpected findings or scanner errors block approval. No need to run paid agents again unless code affecting that runtime changes.
3. Rebuild and rerun Compose with fresh keys and a fresh results directory. Verify the actual installed image package versions and replay the report using its public `trust.json` and independently recorded digest. See `docs/rc4-runbook.md`. Never distribute private keys or journal DBs.
4. Confirm licensing, ownership, lab identifiers and privacy review. Verify CI, perform history secret scanning if publishing existing history, and approve the explicitly documented lab residual risks. Sign Git tag and archive checksum using a separately controlled signing identity. Do not publish or sign automatically. Production readiness remains false.
