# Contributing

Use synthetic data and disposable environments. Do not include private signing keys, local journals, raw agent transcripts, customer data, or privileged repository credentials. Read SECURITY.md and the threat model before running external probes.

Changes require an intent, tests, and explicit limitations. Keep historical signed artifacts and the verifier they bind byte-identical; introduce a new evidence profile when changing replay semantics. Tests and synthetic approvals are not permission to merge. Add negative tests for any new trust boundary. Do not edit historic benchmark results to make tests pass.

Before submitting changes: run `uv sync --locked --extra telemetry`, `uv run --locked python -m unittest discover -s tests -v`, and the relevant fixture. The release inventory is an exact release snapshot, not a manifest to regenerate after arbitrary edits; update it only as part of a reviewed release process. Report vulnerabilities privately as described in SECURITY.md.
