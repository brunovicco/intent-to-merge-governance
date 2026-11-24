# RC.2 live qualification runbook

Promotion: HOLD. No automatic remote merge. RC.1 results remain historical and must not be relabelled as RC.2 executions. The user's terminal results establish live single-task Claude/Codex/Docker, GitHub authenticated negative preflight, failure check publication and GitHub ruleset reporting `blocked` (alongside a missing human approval); original JSON files should be retained locally. No attempt to merge has been made. The RC.2 package contains no credentials and no fabricated live results.

## Prepare

Use a separate directory from RC.1. Copy no credentials into the workspace. Agent processes can read files accessible to their OS user; removing environment variables is not a security boundary. Use a disposable isolated user/VM with no unrelated credentials, only provider authentication needed for the study. Keep the GitHub App key on a separate trusted environment. Docker must have the image preloaded; there is no local fallback for live trials.

```sh
uv sync --extra telemetry
uv run python -m unittest discover -s tests -v
uv run python scripts/rc1_external.py --self-test
uv run python scripts/live_benchmark.py --fixture --out results/rc2-fixtures
```

## Paired live agent study

Five tasks, one independent run per agent per scenario per repetition. Defaults are one repetition (10 runs); the proposed 5 repetitions are 50 paid executions. The schedule is seeded and shuffled; do not selectively delete failures. Fresh Git baseline per run, no retry or automatic repair; one attempt measures first-pass reliability, not convergence. Model selection uses each CLI's configured default, not pinned model equivalence; record exact CLI versions, model settings, plan and runtime independently before execution. Tokens and costs are deliberately null, not estimated. Scope checks inspect Git status and observed heads, not all process side effects or ignored files. Docker observations are not hostile-code-proof. Four new scenarios have finite oracle cases and structural checks, not the full PAY-104 mutation harness. The weak CI comparison is a predetermined subset, not a general claim about CI.

```sh
claude --version
codex --version
docker --version
docker pull python:3.11-slim
uv run python scripts/live_benchmark.py --allow-agent-execution --repetitions 1 --out results/live-pilot
# Only after inspecting pilot results, if desired:
uv run python scripts/live_benchmark.py --allow-agent-execution --repetitions 5 --out results/live-study
```

`manifest.json` records schedule and configuration; `runs.jsonl` stores one row per completed trial, and `report.json` aggregates results. On interruption keep partial rows; do not overwrite or treat an incomplete schedule as complete. `ERROR` indicates an execution/infrastructure issue, `BLOCK` indicates a rejected candidate, `PASS` means the technical oracle passed only. No merge authority. Fixture mode uses reference code, not either agent.

## GitHub lab: strict gate negative

The lab commands are intentionally pinned to `brunovicco/intent-to-merge-governance-lab`. Use the existing negative policy in `~/.config/itm/github-policy-negative.toml`. The PR must remain open; never merge it for these tests. Do not copy the key to the repo. Run the following in the separate trusted environment (not the agent environment):

```sh
export APP_ID=5897543
export INSTALLATION_ID=185227022
export APP_KEY="$HOME/.config/itm/github-app.pem"
uv run python scripts/github_lab.py negative --policy "$HOME/.config/itm/github-policy-negative.toml" --pr 1 --app-id "$APP_ID" --installation "$INSTALLATION_ID" --app-key "$APP_KEY" --out results/strict-negative-dry
# Explicitly writes a failure check, without touching existing required checks:
uv run python scripts/github_lab.py negative --policy "$HOME/.config/itm/github-policy-negative.toml" --pr 1 --app-id "$APP_ID" --installation "$INSTALLATION_ID" --app-key "$APP_KEY" --out results/strict-negative-live --publish
```

Expected: BLOCK because the signed aggregate assertion and independent receipts are absent, in addition to any preflight denial. The check is `ITM / evidence gate`, distinct from `ITM / PR preflight`. Trust pins generated for this negative-only test have no retained signing keys; no signed PASS is created. Publication uses the existing durable worker and records remote identity; the check is not yet required by the ruleset. Never require the full evidence gate until its genuine positive path is qualified. Inspect `jobs.sqlite` and remote checks if response is uncertain. Do not repeat POST blindly; use the existing `itm-ops reconcile` with the saved journal and delivery ID.

## GitHub lab: transport lifecycle (optional)

This writes a separate check `ITM / lab transport only (non-authorizing)` on an already blocked PR, checks the rulesets do not require that context, then PATCHes it to failure and verifies the same ID. The temporary success means only the transport test was created, never authorization. Do not add this name to required checks, even temporarily. The probe cannot rule out concurrent rule changes or legacy settings; inspect settings before running. The required preflight check is untouched. The check creation and update intent are written to disk before side effects. If the API reports uncertainty, inspect by `external_id` and check ID before any retry; no automatic POST retry is implemented. This is not the existing strict gate sweep or proof of actual permission revocation.

```sh
uv run python scripts/github_lab.py transport --policy "$HOME/.config/itm/github-policy-negative.toml" --pr 1 --app-id "$APP_ID" --installation "$INSTALLATION_ID" --app-key "$APP_KEY" --out results/transport-live --publish
```

Pending: actual independently approved PASS, real signed evidence from independently operated services, real authorization revocation, webhook lifecycle, merge-group enforcement, hostile-code isolation, external audit anchors and statistically meaningful live results. No positive scenario is simulated as live. No merge queue availability claim is made for the personal public repository.
