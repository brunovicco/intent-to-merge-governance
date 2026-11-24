# Release qualification — 1.0.0-rc.1

**Promotion decision: HOLD.** This candidate freezes the v0.10 feature set and adds qualification tooling, not production enforcement. All local results use synthetic payment code, ephemeral identities, and a simulated GitHub API. Do not install sample trust roots in a real environment.

## Reproduce the local qualification

```sh
uv sync --extra telemetry
uv run python -m unittest discover -s tests -v
uv run python scripts/rc1_validate.py --out results/rc1-local
```

The harness creates four fresh Git histories, independently re-verifies the exact candidate objects, signs their evidence bundles and deletes both Git copies before verifying the bundles offline. It evaluates the operational autonomy overlay against those same bundles. It then exercises the existing strict gate with a local API double, authenticated delivery, durable journal, separate ephemeral signing keys, and artifacts derived from the synthetic observations. Production wire-profile names are used only inside temporary fixture state. Neither those receipts nor their private keys are exported. The simulated Check Runs have no remote merge authority.

The local merge happens within the original synthetic harness; the subsequent simulated API check is a separate downstream qualification, not a real pre-merge enforcement boundary. The local governance policy and the mock GitHub policy are distinct, and the adapter is a test bridge rather than a live control service.

### Expected results

| Candidate | Exact verification | Local authorization |
| --- | --- | --- |
| Happy path | Pass | Allow |
| Authorization drift | Fail | Deny |
| Property regression | Fail | Deny |
| Missing approval | Pass | Deny |

The mock boundary must also reject tampered artifacts, stale reviews and a critical incident, revoke expired successes, and reconcile a lost publication response without duplication. The historical 19-bundle AMGB corpus must reproduce its checked-in report; three historical change-set receipts must verify offline. Fresh commit IDs and keys are intentionally nondeterministic. The historical corpus replay is deterministic.

## Opt-in external probes

Use a disposable developer VM/account and test-only repositories; avoid exposing unrelated credentials or code. Provider execution may incur charges. The candidate does not initiate any of these operations by default.

### Docker

```sh
docker pull python:3.11-slim
uv run python scripts/rc1_external.py --docker --out results/docker-probe.json
```

The probe tests positive and negative candidates on exact Git objects using the actual Docker runtime, with no local fallback. This is a fixture smoke test, not a sandbox security certification. Record the image ID, runtime version and independent adversarial containment results before production promotion.

### Real agent execution

In a dedicated disposable VM with only the relevant provider authentication, and a preloaded Docker image:

```sh
uv run python scripts/rc1_external.py --agent claude --allow-agent-execution --out results/claude-probe.json
uv run python scripts/rc1_external.py --agent codex --allow-agent-execution --out results/codex-probe.json
```

Each probe creates a fresh synthetic repo, runs the native CLI, records metadata-only provenance, requires the expected single-file change, commits it locally and independently runs the existing PAY-104 verifier using Docker. No GitHub pushes or remote merge. The agent runner is not a security sandbox. Run only with isolated credentials and a disposable VM. Results are single-task smoke tests, not a live comparative benchmark. A real comparative benchmark needs a frozen task corpus, repeated trials, model versions, execution settings, token/cost/latency measurement and explicit failures.

### Authenticated GitHub App

Configure an App and a disposable same-repository PR. Use a trusted policy with real App/check and reviewer IDs. Do not use sample keys or policies as production trust configuration.

```sh
uv run python scripts/rc1_external.py \
  --policy /trusted/github-policy.toml --pr 42 \
  --app-id "$APP_ID" --installation "$INSTALLATION_ID" \
  --app-key /trusted/app.pem --expect PASS --out results/github-probe.json
```

This exercises the real installation-token exchange and reads the PR, reviews, changed paths, and checks. It does not publish a check. Repeat with a deliberately missing approval (`--expect BLOCK`, new output path). Verify token scope independently. The authenticated publish/revoke/reconcile workflow requires a separate approved test environment and real control services; never substitute the local fixture bridge for those services.

## Promotion gates (all mandatory)

| Gate | Evidence needed |
| --- | --- |
| Regression | Entire inherited suite and new RC qualification checks pass |
| Local E2E | Fresh Git scenarios, offline bundles, API contract, recovery and revocation pass |
| Docker | Real runtime smoke test plus independent containment/security review |
| Claude Code / Codex | Authenticated probe results plus repeated comparative experiments |
| GitHub | Real App authentication, positive/negative PR preflight, check publication, revocation and recovery on disposable PR |
| Merge Queue | Implement and test `merge_group` admission on exact merge-group SHA, stale base, review removal, queue reordering and multi-PR group; require the trusted check in branch rules |
| Live controls | Independent services actually produce all six control receipts over real evidence, with independent credentials and no fixture-profile substitution |
| Persistent trust | Externally anchored current state, concurrency/fencing, and recovery exercise in deployment topology |

The v0.10 production ingress ignores `merge_group` events; RC.1 deliberately does not disguise this missing implementation as a successful test. No sequence of passing mock checks can promote the release by itself. A real check is a snapshot, not a transactional guarantee. Require merge-queue revalidation and explicitly characterize remaining timing/race limits.

Recorded local artifacts are in `examples/rc1/`. External probes default to NOT_RUN and never set `production_ready=true`. Only an independently reviewed release decision after all gates are satisfied can promote the candidate.
