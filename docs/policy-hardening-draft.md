# Policy hardening — development increment 1

Status: review candidate, not a new release or production authorization. The signed v1.0.0 tag and historical evidence remain unchanged. This increment deliberately does not change the package version or regenerate the dependency lock.

## Path semantics

Fresh PAY-104 decisions and GitHub preflight now use `segment-v2` (case-sensitive, full repository-relative path matching). `*` and `?` match within a single path segment; a whole `**` segment matches zero or more segments. For example, `app/*.py` does not match `app/sub/x.py`; `app/**/*.py` matches both `app/x.py` and `app/sub/x.py`; `**/policy.toml` matches a root-level policy file. `docs/**` also matches `docs` itself. Protected patterns take precedence. No gitignore negation, bracket classes, escaping or implicit directory patterns are supported. Invalid paths (absolute, traversal, empty segments, backslash, control characters) cannot match an allowlist; unsupported patterns are rejected. This is not gitignore or CODEOWNERS syntax.

A fresh local binding must contain `path_semantics: segment-v2`; approvals and checkpoint bindings consequently include it. Historical local evidence without a semantics marker is replayed using `fnmatch-v1`. Such replay is historical only; it must never be used for new authorization. New GitHub policies loaded via `policy_from` are normalized to include `path_semantics = "segment-v2"`; the digest changes even for otherwise identical policy files. Direct dictionary callers must supply the marker. Regenerate external assertions and control receipts under the normalized policy after review; do not reuse old evidence. No remote check publication or merge is performed by this increment.

## Policy validation and approvals

The local decision API checks the policy version, fields, checks, risk levels, role references, path patterns and convergence limits, and the spec's scope/criteria. It returns an `INVALID_CONFIGURATION` denial on invalid configuration. The fixture runner records a distinct `configuration-rejection.jsonl` before creating an executor or repository when these checks fail. This is a diagnostic log, not a signed evidence bundle or a successful candidate run. Full spec validation and TOML parse/IO failures can still raise; general structured error handling is not complete. The GitHub preflight rejects invalid policy inputs before reading or publishing checks.

Fresh local decisions accept Ed25519 public-key verification only. Symmetric legacy approval verification is retained for explicit historical replay. The old signing helper still exists for legacy compatibility; it is not sufficient for a fresh authorization. Domain-separated, time-bound approval envelopes, external trust separation, and key/identity lifecycle are subsequent work.

## Validation and limits

Run `uv sync --locked --extra telemetry`, the full unittest suite and the existing security workflow before integrating. The seven existing Bandit findings in `runner.py` retain the exact finding line hashes and dispositions; their source pins and line numbers were adjusted for the inspected diff. `source_report_sha256` remains the historical scan, not a new report. A fresh scan must match the baseline, with any new or changed findings reviewed explicitly. Do not suppress or auto-approve unexpected findings.

The separate signed local changeset v1 profile still uses its original matcher. Its migration requires an explicit versioned contract and replay tests; this increment does not claim coverage of every profile. This is an experimental fixture-specific implementation, not a general verifier or a qualified production merge service. No hostile-code isolation, merge queue enforcement or organizational approval independence is established. `production_ready: false`; `merge_authority: false`.
