# RC.5 — Integrated candidate runtime (experimental)

This release connects a real Git workspace, bounded candidate attempts, independent post-run functional verification and a persistent local readiness lifecycle. It does not grant merge authorization. AUTH-201 is the only supported integrated scenario. Previous five-scenario studies and the six-service RC.4 synthetic Compose lab remain available unchanged.

## Reproduce without an LLM

```
uv sync --extra telemetry
uv run python -m unittest discover -s tests -v
uv run python scripts/integrated_runtime.py run --fixture repair --out results/rc5-repair
```

`repair` yields two attempts (incomplete, then corrected), `PASSED` convergence and `BLOCK` governance. `first` uses the known correct reference. `repeat` stops at repeated tree, `scope` stops before verification, `budget --tokens 100` stops even though the candidate is correct. Stop outcomes intentionally return exit code 2; inspect the report rather than blindly repeating. The synthetic telemetry is not provider usage. Every output directory must be new. The fixture verifier only executes the fixed known reference and the specified incomplete reference locally.

## Live pilot (opt-in)

Run in a disposable separate user/VM with no GitHub App private key, no privileged tokens or other sensitive files reachable by the agents. Unsetting environment variables is not a security boundary. Install and authenticate the desired agent CLI in that environment and preload `python:3.11-slim` for Docker. No local fallback is used.

```
uv run python scripts/integrated_runtime.py run --allow-agent-execution --provider claude --attempts 3 --tokens 400000 --seconds 180 --out results/rc5-claude
uv run python scripts/integrated_runtime.py run --allow-agent-execution --provider codex --attempts 3 --tokens 400000 --seconds 180 --out results/rc5-codex
```

Each attempt begins on the prior committed tree. Trusted code checks status/scope and structural invariants, commits the allowed path and verifies the exact Git object. Functional failure may trigger another invocation with aggregate pass counts; scope violations, repeated trees, unknown usage, limits or execution errors stop. Token budgets apply to **observed** usage after each call; no hard provider token cap. Time is checked before admission and after evaluation; Git/Docker operations and cleanup may overrun the requested wall time. The post-run verifier has its own timeout and is not part of the agent budget. A first-pass success is valid, not evidence of multi-attempt live convergence.

## Evidence and lifecycle

- `convergence.json`, `attempts.jsonl`, local `repo/`, prompt files and metadata-only observations: preserve locally; review before publishing.
- `verification-receipt.json`, `verifier-trust.json`: the worker re-evaluates the exact head/base and signs artifact + convergence digest with a distinct ephemeral Ed25519 lab key created after agent calls. Pin the public key from a trusted channel before replay. No key is retained in the report. Receipt lifetime is 60 seconds.
- `report.json`: `candidate_verified` may be true but gate remains `BLOCK` because human approval and complete external control inventory are absent. Actual strict receipt validator rejects the lab profile. No call to GitHub or conversion to external-control-v1.
- `lifecycle.sqlite`: local readiness (not authorization) with HMAC event deduplication, permanent revocation of the same decision ID, reconciliation by trusted current head/base/clock. Demo emits a local synthetic review-withdrawal event; it is not a real webhook. Tests cover expiry, binding drift, conflicting delivery and restart. This single-candidate journal does not enforce global event ordering, prevent a fresh decision from being registered after old revocation, or authenticate snapshots from a remote API.

Historical replay (does not assert current authorization or replay revocations):

```
uv run python scripts/integrated_runtime.py replay --out results/rc5-repair --expected-verifier-key <independently-pinned-public-key-hex>
```

## Boundaries

The separate verifier process is not an independent organization or a secure service boundary. The candidate and observation worker share an interpreter in Docker; no hostile-code integrity guarantee. Same-user agents may modify Git metadata, controller files or environment outside the workspace; run only in a disposable trusted lab. The HMAC event handler is local; there is no HTTP service authentication or remote event reconciliation in RC.5. Existing RC.4 six-service receipts remain synthetic, with separate signing domains. Existing GitHub strict gate, webhook worker and sweep remain unchanged; no new live gate publication, positive independent approval, actual authorization revocation, or merge queue enforcement is claimed. Production promotion HOLD.
