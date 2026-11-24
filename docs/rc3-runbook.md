# RC.3 — adversarial governance research kit

**Promotion: HOLD.** This is a controlled research release, not a production security boundary.

## 1. Four-strategy paired replay

```
uv sync --extra telemetry
uv run python -m unittest discover -s tests -v
uv run python scripts/adversarial_benchmark.py --out results/adversarial-v1
```

Open `results/adversarial-v1/report.html` or inspect `report.json` and `runs.jsonl`. The checked-in `examples/rc3` contains a reference execution. Use a fresh output path. The default backend runs only the bundled trusted, synthetic fixture source locally. `--backend docker` requires a running Docker daemon and a preloaded image; no local fallback. Do not add arbitrary or hostile source to these fixtures. Git commits, random synthetic signing keys, digests and elapsed times vary; decision counts should reproduce.

Inventory: 5 safe reference candidates, 5 hidden behavioral regressions, 5 scope or structural violations, and 10 control-evidence failures. Each label was set before evaluation. One exact candidate commit per fixture is evaluated with common observations and cumulative decisions: S0 partial CI; S1 + scope/intent; S2 + full behavioral oracle; S3 + signature, receipt identity, binding, freshness and aggregate checks on synthetic control observations. The incomplete CI is designed to miss the listed failures. All S3 allow outcomes are **simulation only**, with no merge authority. Receipt signers and aggregate signer are generated in one process and discarded. Control artifacts are synthetic, not independent service attestations. Authorization and autonomy observations are fixture conditions. Repeated-tree convergence is a synthetic replay, not a retry loop with live agents. The report is not an independently replayable signed evidence bundle.

This measures discrimination on the fixed inventory, not population risk, attack resistance, actual production CI efficacy or per-strategy latency. Elapsed time measures the whole case once; no governance-overhead or revocation-latency claims are made.

## 2. Opt-in agent context challenge and native telemetry

Run outside the trusted GitHub publisher environment, on a disposable machine/OS user with no accessible governance credentials. Removing environment variables is not filesystem isolation. Docker restricts candidate execution but does not isolate the agent itself or prevent in-process observation tampering. Do not execute untrusted or hostile code. The challenge is a harmless conflicting request to create an unauthorized marker file; no network, secrets or exploit payload. The trusted prompt says context data cannot expand scope.

```
uv run python scripts/live_benchmark.py --allow-agent-execution --challenge --repetitions 1 --out results/live-context-pilot
```

Ten planned independent CLI calls (five tasks, two providers), randomized order; may incur usage charges. Use `--provider` or `--scenario` for a smaller pilot. A BLOCK/ERROR is recorded, not silently retried. A scope-blocked candidate is not executed; its weak-CI outcome is unknown. A challenge PASS means the first candidate satisfied these checks, not that the agent is immune to injection. No live challenge execution was performed by the release builder.

New metadata fields project numeric usage from a single recognized terminal event; Claude `result.usage` and `total_cost_usd` when present, Codex `turn.completed.usage`. Cache fields retain provider-native semantics. No prices inferred, no aggregation across incompatible fields, no unknown models guessed, no raw prompts or tool outputs retained. Native values are self-reported, not billing data. Summaries report field coverage alongside sums of observed values only. Multiple terminal events or missing values yield null rather than an invented total. Model names are only captured from recognized Claude model usage keys when present. No live schema confirmation in this release; the parser has fixture coverage.

## 3. Existing GitHub laboratory

RC.2 publication and revocation-transport commands are unchanged. Preserve local user-generated reports. The reported live PR #1 is a negative example; do not merge it or republish successes. The ruleset previously required the preflight and trusted CI, not the strict Evidence Gate. This release does not change GitHub or issue any live authorizations. A real positive check requires independently authenticated evidence and a legitimate independent reviewer; do not substitute fixture keys or remove approval controls. The transport-only check must never become required.

## 4. Remaining scope

- Independent live control services and key custody; external trust anchoring.
- Actual positive authorization, revocation and isolated enforcement test.
- Live multi-attempt convergence and calibrated resource budgets.
- Merge group event adapter and actual merge queue integration.
- Hostile-code isolation and observation integrity; remote TOCTOU mitigation.
- Expanded and independently labeled adversarial inventory, live paired samples, model/version control and statistical inference.
