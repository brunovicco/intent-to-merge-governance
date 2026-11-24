# Intent-to-Merge Governance

**Agents generate code. Evidence earns trust. Policy grants authority.**

`v1.0.0-rc.6` · Vendor-neutral reference harness for evidence-bound agentic software delivery.

**A green CI is not enough to authorize a merge.** A candidate can pass the four original functional checks while violating the intent or a generated business invariant. ITM separates execution, verification and deterministic authorization.

Inspired by [Anthropic's code review](https://claude.dev/blog/solving-code-review-at-anthropic/), [verification](https://claude.dev/blog/how-the-claude-code-team-thinks-about-verification/), [Claude Ship](https://claude.com/resources/articles/introducing-claude-ship) and [Entire](https://entire.com/). Independent educational project, not affiliated with these vendors.

## Release candidate 6 — security hardening

**Research/reference implementation — production promotion HOLD.** RC6 hardens the integrated AUTH-201 lab with bounded output capture, exact Git candidate checks, durable pre-registration revocation fences, and externally pinned journal checkpoints. Legacy signed bundle replay remains intact. No hostile-code isolation, actual independent approval or live authorization revocation is claimed.

- [Threat model, risk register and ADR-006](docs/rc6-security-review.md)
- [RC6 runbook](docs/rc6-runbook.md) · [Security policy](SECURITY.md)
- [Consolidated experimental evidence and publication gates](docs/experimental-results.md)

```sh
uv run python -m unittest discover -s tests -p 'test_rc6.py' -v
uv run python scripts/integrated_runtime.py run --fixture repair --out results/rc6-repair
uv run python scripts/journal_checkpoint.py --db results/rc6-repair/lifecycle.sqlite
uv run python scripts/release_inventory.py verify
```

## Release candidates 4–5 — distributed plane and integrated runtime

**RC.5 — Integrated candidate runtime.** AUTH-201 bounded multi-attempt execution, exact Git candidate verification in a separate process, signed non-authorizing receipt, and authenticated local revocation/reconciliation. See [RC.5 runbook](docs/rc5-runbook.md). The six-control lab and live GitHub gate remain separate trust domains.

```sh
uv run python scripts/integrated_runtime.py run --fixture repair --out results/rc5-repair
```

**RC.4 — Distributed synthetic control plane.** Six HTTP controls, separate Ed25519 lab keys, signed aggregation, offline replay, and local revocation lifecycle. See [RC.4 runbook](docs/rc4-runbook.md). Production promotion remains HOLD.

```bash
uv run python scripts/control_plane.py demo --out results/rc4-local
```

[Reference report](examples/rc4/report.html) · [Qualification](examples/rc4/qualification.json). Six separate processes, not independently administered authorities.

## Release candidate 3 — adversarial research kit

**Promotion remains HOLD.** Four cumulative strategies are evaluated against 25 pre-labelled synthetic Git candidates (5 safe, 20 unsafe). The reference run accepted 20/20 unsafe cases with partial CI (S0), 15/20 with scope and intent (S1), 10/20 with behavioral verification (S2), and 0/20 with the synthetic signed-control gate (S3); no safe fixtures were blocked. This curated study intentionally includes failures that partial CI misses; these counts are not a production security rate.

- `scripts/adversarial_benchmark.py`: exact Git fixture evaluation, cryptographic negative controls, repeated-tree convergence replay and HTML/JSON report.
- `scripts/live_benchmark.py --challenge`: opt-in harmless untrusted-context challenge with native CLI telemetry projection. No live challenge runs performed by the builder.
- [RC.3 runbook and boundaries](docs/rc3-runbook.md) · [Reference report](examples/rc3/report.html) · [JSON](examples/rc3/report.json).

```bash
uv sync --extra telemetry
uv run python scripts/adversarial_benchmark.py --out results/adversarial-v1
```

## Release candidate 2 — live qualification toolkit

**Promotion remains HOLD.** RC.2 incorporates the validated workspace-diagnostics v3 probe and explicit Claude edit permissions. It adds a five-scenario live-agent study and two explicitly opt-in GitHub lab experiments. No remote merge authority or independent human approval is manufactured.

- `scripts/live_benchmark.py`: paired runs of PAY-104, AUTH-201, API-302, DATA-403 and REF-504; fresh repositories, exact candidate commits, independent oracle, Docker-only live execution, append-only trial records. Fixture mode is not live agent evidence.
- `scripts/github_lab.py negative`: uses the existing strict Evidence Gate and durable journal; deliberately empty independent evidence inventory must produce BLOCK. Publication is opt-in.
- `scripts/github_lab.py transport`: dedicated, non-required transport-only check, verifies success-to-failure update of the same remote check. Not evidence authorization or production revocation.
- [RC.2 runbook, limitations and experiment protocol](docs/rc2-runbook.md).

```bash
uv sync --extra telemetry
uv run python scripts/rc1_external.py --self-test
uv run python scripts/live_benchmark.py --fixture --out results/rc2-fixtures
```

## Release candidate 1 — end-to-end qualification

**Release promotion: HOLD.** This release freezes the v0.10 feature set. It adds an executable local qualification study and explicit opt-in external probes. No real remote merge authority is introduced.

- Four fresh synthetic Git candidates; four offline signed bundles verified after removal of the original Git repositories.
- All 139 inherited tests passed in a fresh regression run. Eight isolated GitHub API contract cases, including expiry revocation, artifact tampering, stale reviews, critical incident and lost-response reconciliation.
- Historical AMGB report reproduced; three historical change-set receipts verified.
- [Qualification protocol and promotion gates](docs/release-qualification.md) · [Local report (HTML)](examples/rc1/report.html) · [Machine-readable results](examples/rc1/report.json) · [Promotion status](examples/rc1/qualification.json).

```bash
uv sync --extra telemetry
uv run python scripts/rc1_validate.py --out results/rc1-local
uv run python scripts/rc1_external.py --help
```

Docker, live Claude Code/Codex execution, authenticated GitHub checks, actual merge-queue enforcement and independent live control services remain release blockers. The local API double never accesses GitHub. See [qualification protocol](docs/release-qualification.md) before running opt-in probes.

## What's new in v0.10 — operational hardening

- Strict operational CLI requires six independently signed control receipts, actual digest-bound artifact objects, and the separate aggregate assertion. Legacy fixture assertions alone cannot pass the strict gate.
- Periodic check revalidation and optional revocation of journal-known obsolete GitHub successes. The sweep never creates success.
- Exact-Git-object verification of the PAY-104 demonstration contract, with scope, intent and 37 behavioral cases plus mutation adequacy. Local execution requires explicit fixture opt-in.
- Durable local multi-repository CAS recovery with signed SQLite state, explicit compensation and manual escalation on ambiguous ref drift.
- See [hardening setup and trust boundaries](docs/hardening.md). The remote check/merge race, external service truth, live provider integration, and distributed atomicity remain explicit limitations. Docker is exercised in CI, not in the current environment.

```bash
uv sync --extra telemetry
uv run itm-ops --help
uv run python -m unittest discover -s tests -p test_hardening.py -v
```

**Validation:** 122 legacy tests and 17 new hardening tests passed (139 total, two invocations). [Validation records](examples/hardening-v1/validation.json). Docker and authenticated external APIs were not exercised locally.

## What's new in v0.9 — operational integration

A GitHub App worker connects the prior reference architecture to a real PR snapshot boundary: authenticated webhook ingress, SQLite delivery journal, scoped installation tokens, independently signed external verifier assertions and optional check-run publication. An ambiguous publication is reconciled rather than blindly retried. No remote merge endpoint is exposed.

| Feature | Scope |
|---|---|
| GitHub App authentication | RS256 JWT and scoped installation token exchange |
| Webhook ingress | HMAC verification, repository/installation allowlist, deduplication |
| Evidence gate | Exact PR/head/base/policy binding, Ed25519 signature, expiry, six required controls |
| Persistent recovery | SQLite journal and remote check reconciliation |
| Agent runner / hook | Local Claude Code and Codex CLI adapters, metadata-only observations |
| OpenTelemetry | Optional console spans; injectable tracer |

```bash
uv sync --extra telemetry
uv run itm-ops --help
uv run python scripts/operational_demo.py --out results/operational-study
uv run python -m unittest discover -s tests -p test_operational.py -v
```

[Operational study (HTML)](examples/operational-v1/report.html) · [Architecture and setup](docs/operational-integration.md).

**Validation:** 22 new tests and 81 selected regression tests passed locally. Six fixture-only scenarios exercise the gate and journal; local runner tests use fake CLI executables. No authenticated GitHub or official agent CLI calls. A separate trusted verifier must supply actual live assertions; this release does not verify their underlying evidence, enforce atomic merge-time authorization, or recover the v0.8 multi-repository coordinator after a crash. A snapshot success can become stale. Keep native GitHub protections; do not use as a sole production merge control.

## What's new in v0.8 — Multi-Repository Change Sets

**A compatible final state does not imply a safe rollout.** A single intent can span several repositories; the change-set coordinator checks the dependency graph, declared contract compatibility at every rollout prefix, scope, exact Git commits and separate reviewer approvals before local execution.

![Multi-repository change set](docs/changeset-results.svg)

| Scenario | Observed outcome |
|---|---|
| Compatible provider-first rollout | COMPLETED |
| Incompatible final state | BLOCKED |
| Compatible final state, incompatible intermediate state | BLOCKED |
| Partial failure | COMPENSATED |
| External ref movement during compensation | MANUAL_INTERVENTION |
| Stale plan | BLOCKED |
| Missing approval | BLOCKED |
| Scope violation | BLOCKED |

```bash
uv run intent-merge changeset-demo --out results/changeset-study
```

The study created three actual local bare Git repositories per scenario. Three execution receipts were signed and replayed offline; five preflight-blocked scenarios produced zero coordinator writes. See the [HTML report](examples/changeset-v1/report.html), [raw results](examples/changeset-v1/report.json) and [architecture and trust model](docs/multi-repository.md).

This is a separate local synthetic reference coordinator, not a live GitHub integration, distributed transaction, crash-safe saga or production deployment rollback. Contract checks verify explicit version declarations, not executable API behavior. The previous AMGB and autonomy studies are unchanged.

## What's new in v0.7 — Adaptive Autonomy & Incident-to-Eval

**Autonomy must be earned again.** A previously eligible change can become ineligible after an incident, even when the original CI and base policy are green.

The new signed operational event stream implements role-separated incident reporting, regression proposal and approval, candidate-bound observations, explicit recovery, and automatic circuit breakers. It adds an eligibility overlay to authenticated AMGB traces; it cannot grant merge authority or weaken existing approvals.

![Adaptive autonomy study](docs/autonomy-results.svg)

| Study result | Observed |
|---|---:|
| Signed operational events | 13 |
| Demonstration stages | 13 |
| Distinct signing roles | 5 |
| Fault fixture: original verification cases | 37/37 passed |
| Fault fixture: incident-specific regression | Failed (detected) |
| New unit/integration tests | 20 passed |
| Selected regression tests | 42 passed |

```bash
uv run intent-merge autonomy-demo --out results/autonomy-study
```

Open the [offline report](examples/autonomy-v1/report.html), inspect the [raw JSON](examples/autonomy-v1/report.json), or follow the [architecture, replay and trust model](docs/adaptive-autonomy.md). The sample includes public role keys, signed events and a demo anchor, not private keys. The overlay operates on synthetic historical bundles; it does not enforce a live PR, attest real production outcomes, or replace a trusted external root service. The AMGB v1 study below is unchanged.

## What's new in v0.6 — Agentic Merge Governance Benchmark (AMGB)

**19 synthetic scenarios, five cumulative governance strategies, 95 paired decisions.** The benchmark asks which controls contribute to correct eligibility decisions, rather than which model writes better code.

![AMGB v1: unsafe eligibility across five cumulative strategies](docs/amgb-results.svg)

| Strategy | Unsafe allows (of 15) | False blocks (of 4) | Correct decisions (of 19) |
|---|---:|---:|---:|
| S0 — Acceptance checks | 10 | 0 | 9 |
| S1 — Extended verification | 8 | 0 | 11 |
| S2 — Intent, scope and provenance | 6 | 0 | 13 |
| S3 — Convergence governor | 5 | 0 | 14 |
| S4 — Deterministic authorization | 0 | 0 | 19 |

The full harness generated 32 proposals and 31 candidate evaluations (1,147 executed candidate verification cases, excluding baseline and mutation work). Four intentionally valid fixtures include first-pass success, equivalent refactoring and delayed success. Fifteen intentionally blocked fixtures cover functional failures, drift, scope, loops, budget and approval/freshness problems. S4 correctly reproduced all predeclared labels. This is a fixed, hand-designed suite, **not a claim of zero production risk**.

### Reproduce without running candidate code

```bash
uv run intent-merge benchmark-replay \
  --bundles examples/amgb-v1/bundles \
  --public-key examples/amgb-v1/signer.pub \
  --output results/amgb-replay
```

The report should exactly match the committed JSON for this corpus. A fresh run generates independent keys and Git commits, so evidence digests will differ; compare scenario decisions and metric counts, not bytes.

```bash
uv run intent-merge benchmark --out results/amgb-fresh --workers 4
```

The fixture executor runs trusted synthetic Python only. No API key or Docker daemon is needed. Output includes `report.json`, `report.html`, `strategies.csv`, `scenario-matrix.csv`, 19 signed bundles and the demo public signer key. The ephemeral private key is not distributed. See the [methodology](docs/benchmark.md), [HTML report](examples/amgb-v1/report.html), [raw results](examples/amgb-v1/report.json) and [scenario matrix](examples/amgb-v1/scenario-matrix.csv).

**Method:** all strategies observe the same authenticated final inputs from the full harness. S0 uses four original acceptance checks; S1 adds property, differential, contract and mutation gates; S2 adds scope, trusted harness, structural drift, requirement coverage and checkpoint binding; S3 adds convergence; S4 reproduces the complete policy decision after signature and audit replay. Missing evidence fails closed. Two out-of-scope proposals were rejected before execution; their baseline blocks are due to missing observations, not scope detection by baseline CI. The suite fixes the spec and policy digests so labels cannot silently change.

This is an ablation, not an independent end-to-end run of each architecture. No LLM reviewer, commercial tool, inference cost, human review time or adaptive autonomy is benchmarked. `ALLOW` is hypothetical eligibility only. Do not use AMGB reports as authorization for real changes. See [methodology](docs/benchmark.md) for metric denominators and limitations.

## What's new in v0.5 — GitHub preflight, native agent streams and Governance Explorer

**A preflight is not a merge authorization.** The existing signed-evidence demo remains separate from live GitHub checks. Synthetic attestations cannot authorize a real pull request. The new modules are independent adapters, not a production GitHub App service.

```mermaid
flowchart LR
  A[Claude Code or Codex JSONL] --> N[Privacy-filtered session metadata]
  P[GitHub PR API] --> G[Scope, check and reviewer preflight]
  T[Trusted out-of-band policy] --> G
  G --> C[Optional SHA-bound GitHub check]
  G --> X[Offline Governance Explorer]
  N --> X
  B[Signed synthetic evidence bundle] --> V[Independent signature and audit verification]
  V --> X
```

### Explore the release in one command (no external credentials)

```bash
uv run intent-merge explorer \
  --bundle examples/sample-evidence/signed-demo-bundle \
  --public-key examples/sample-evidence/demo-signer.pub \
  --pr-report examples/sample-evidence/pr-preflight-fixture.json \
  --session examples/sample-evidence/claude-session-fixture.json \
  --session examples/sample-evidence/codex-session-fixture.json \
  --output governance-explorer.html
```

Open the resulting HTML in a browser. The [prebuilt Explorer](examples/sample-evidence/governance-explorer.html) uses the same inputs. Bundle signatures and deterministic audit are verified before rendering. Imported PR snapshots and agent metadata are **not authenticated**; fixture data is explicitly marked. The HTML is a read-only presentation artifact, not a signed attestation. No JavaScript, server or network requests are required. Do not publish reports with confidential paths, identifiers or evidence.

### GitHub integration

Copy `examples/github-policy.toml` into a trusted location outside the candidate repository, fill in the repository, target branch, allowed/protected globs, trusted check name and GitHub App ID, and immutable reviewer account IDs. Glob matching uses Python `fnmatchcase` (wildcards can cross `/`). Review the allowlist carefully. Different roles must have disjoint members. The example IDs are placeholders. Use a GitHub App installation token scoped to the repository, with Pull requests: read and Checks: read (and Checks: write only for publication). See [GitHub Checks API](https://docs.github.com/en/rest/checks/runs) and [GitHub App CI checks](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app).

Set `ITM_GITHUB_TOKEN` securely in your shell or secret manager. Do not expose it to agent processes. Run the CLI from a trusted ITM installation, not from a PR-controlled checkout:

```bash
uv run intent-merge github-preflight --repo OWNER/REPO --pr 42 \
  --policy /trusted/github-policy.toml > pr-report.json
```

Optional publication (writes only a check run; never merges or edits code):

```bash
uv run intent-merge github-preflight --repo OWNER/REPO --pr 42 \
  --policy /trusted/github-policy.toml --publish > pr-report.json
```

The check is named `ITM / PR preflight`; `success` means only the configured preflight gates passed. It checks scope (including source and destination of renames), exact head SHA, latest run of the required named check from its pinned app ID, and distinct approved reviewer roles on the same SHA. It rejects self-approval, drafts, wrong branches, incomplete file lists, stale approvals and forks. A changed head or base during collection aborts publication. Tokens are never written into reports. The command returns exit 0 for both PASS and BLOCK; integration callers must inspect `decision`. Transport/validation errors exit nonzero and do not publish a check. Reports are unsigned observations, not portable full ITM evidence.

For a pilot, use an isolated test repository and a trusted runner. If making the preflight check required, pin its GitHub App identity and separately require native up-to-date branch protections, dismissal of stale reviews, required approvals, trusted CI and all other organizational gates. GitHub remains the enforcement layer. A check tied to head SHA is not tied atomically to future base changes, review dismissals or a later CI rerun. This implementation has no event listener, no automatic invalidation, no GitHub App token minting, no merge queue integration and no atomic merge operation. Do **not** treat the preflight check as the sole production gate. Forks and more than 2,999 changed files are unsupported. No candidate code is executed in this path.

### Native agent session imports

Run your own installed and authenticated CLI in a disposable development workspace, with your usual restricted permission settings. Export native JSONL into a private directory outside the workspace. For example (run the agent only if you intend to use its paid inference):

```bash
# Claude Code (print mode)
claude -p 'Implement the approved specification' --output-format stream-json --verbose > /private/path/claude.jsonl
# Codex CLI (non-interactive, workspace-limited mode)
codex exec --json --sandbox workspace-write 'Implement the approved specification' > /private/path/codex.jsonl
```

Use the native agent's own login; ITM does not request or broker provider credentials. Review and commit your change yourself. Import either stream using the observed commit as a *claim*, not authenticated provenance:

```bash
uv run intent-merge import-agent --provider claude --input /private/path/claude.jsonl \
  --head "$(git rev-parse HEAD)" > claude-session.json
uv run intent-merge import-agent --provider codex --input /private/path/codex.jsonl \
  --head "$(git rev-parse HEAD)" > codex-session.json
```

The importer retains only a hash of the raw stream, a hash of the session ID, allowlisted tool categories, count and claimed head. It requires a recognized completed session and refuses mixed or failed sessions. It never retains prompts, tool arguments, output or raw commands. Raw exports may themselves contain secrets: keep them private. These formats are based on native JSONL event envelopes and tested with representative fixtures, not actual provider executions. Unknown events are ignored; this is neither a complete event trace nor cryptographically attested identity. Imported session objects retain `self_reported` trust and cannot grant authorization. The demo runner still uses synthetic agents, not these CLIs.

### Validation

`python -m unittest discover -s tests -p test_integration_v05.py -v` runs the v0.5 adapter and Explorer tests with no network. Live API installation, provider CLI output compatibility and Docker execution need environment-specific smoke tests. The [sample reports](examples/sample-evidence/) are generated from fixtures and the signed v0.4 example, not live customer data.


## Architecture

```mermaid
flowchart TD
  S[Versioned intent and non-goals] --> A[Fixture agent / adapter protocol]
  A --> P[Scope guard]
  P --> G[Git candidate + universal checkpoint]
  G --> I[Structural intent checks]
  G --> W[Restricted worker: local fixture or Docker]
  T[Trusted plan and host oracle] --> W
  W --> V[Host-side verification of observations]
  I --> C[Convergence governor]
  V --> C
  C -->|Continue| A
  C -->|Stop or escalate| X[Denied]
  C -->|Passed| D[Deterministic policy engine]
  R[Trusted policy and simulated distinct approvals] --> D
  D -->|Authorized exact SHA| M[Local Git merge]
  D -->|Denied| X
  G --> E[Evidence ledger and intent graph]
  V --> E
  C --> E
  D --> E
  E --> B[Signed in-toto / DSSE evidence bundle]
  B --> U[Offline evidence verification]
  B --> Y[Counterfactual policy replay]
```

## Quickstart

Python 3.11+ and Git; no API credentials or paid service required. Run from the repository root:

```sh
uv run intent-merge demo --scenario happy --out results/happy
uv run intent-merge demo --scenario property-regression --out results/property-regression
uv run intent-merge demo --scenario loop --out results/loop
uv run intent-merge audit --out results/happy --anchor results/happy/anchor.json --trust results/happy/demo-trust.json
uv run python -m unittest discover -s tests -v
```

Without uv: `python -m pip install -e .`, then omit `uv run`. Use a new output directory for each run. A denied merge is an expected experiment outcome (exit 0); check `decision.authorized` before using this in CI. Invocation/audit failures return nonzero. Use the matching release for historical evidence; the v0.4 portable bundle requires Ed25519 approval keys and does not export legacy HMAC runs.

## What's new in v0.4 — proof-carrying changes

A portable evidence bundle binds the recorded candidate, intent, policy, evaluation results, provenance, convergence, approvals and merge decision to an **Ed25519 signature**. The envelope uses [DSSE](https://github.com/secure-systems-lab/dsse) and the [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with a project-specific predicate. It is not a Sigstore certificate, a SLSA level claim, or a proof of program correctness.

```mermaid
flowchart LR
  R[Audited historical run] --> S[Evidence signer]
  S --> B[DSSE signed bundle]
  K[External trusted public key] --> V[Offline verifier]
  B --> V
  V --> P[Decision-only policy replay]
  Q[Proposed policy] --> P
  P --> T[Would allow / would deny / unchanged]
```

### Try it

After installing the project (Python 3.11+, Git, cryptography dependency):

```bash
uv run intent-merge demo --scenario happy --out results/v04-happy
uv run intent-merge keygen --private-key results/signer.pem --public-key results/signer.pub
uv run intent-merge bundle --out results/v04-happy --bundle results/happy-bundle --private-key results/signer.pem
uv run intent-merge verify-bundle --bundle results/happy-bundle --public-key results/signer.pub
```

The public key must be obtained independently of the bundle. The signer endorses the recorded evidence and the simulated approvers' public keys. The new runs use ephemeral Ed25519 approval keys rather than shared HMAC secrets; only public approval keys are written to disk. The bundle excludes the original Git checkout and private keys. It contains the exact SHA-256 inventory of evidence files, manifest, anchor and public approval trust; unexpected files, missing files, changed signatures and symlinks are rejected. Verification replays deterministic checks without executing candidate code or contacting a model provider. Do not sign unknown or unreviewed runs: signing does not turn an untrusted observation into a true observation. There is no timestamp authority, revocation service, independently attested worker, or real human identity provider in this demonstration.

### Counterfactual policy replay

```bash
uv run python scripts/demo_release.py --out results/v04-study
uv run intent-merge policy-replay \
  --bundle results/v04-study/bundles/happy \
  --bundle results/v04-study/bundles/missing-approval \
  --public-key results/v04-study/demo-signer.pub \
  --policy examples/policy-proposed.toml
```

The proposed example removes the Security approval requirement for payment changes solely to demonstrate the impact of a policy relaxation. The eight-scenario fixture study expects one previously denied change (missing Security approval) to become hypothetically eligible, one authorized change to remain eligible, and six denials to remain unchanged. These are synthetic outcomes, not predictions of production safety.

Replay verifies every bundle against the supplied signer, rejects duplicate histories, and authenticates historical approvals under the original policy. It then applies the proposed decision-time rules using those historical actors as hypothetical inputs. **No original approval is re-signed or transferred to the new policy; a fresh authorization is always required.** Replay holds the recorded evaluations, base/head and convergence outcome fixed; it does not rerun agents or predict what a different execution policy would have produced. Only `required_checks`, `protected_paths`, and `risk_rules` may change; unknown gates fail closed. Changes to identity mappings or execution/convergence parameters are rejected. A different policy may affect convergence in real execution, so decision-only replay is not equivalent to a full rerun.

### Portable format

```text
bundle/
  evidence/              # recorded source snapshots, diffs, observations, graph, ledger
  manifest.json
  anchor.json
  approval-trust.json    # public keys, endorsed by signer
  attestation.json       # DSSE envelope containing in-toto Statement v1
```

The verifier trusts the external signer and the matching verifier implementation, not a key supplied by an untrusted bundle. Evidence may contain proprietary source and metadata: apply access control and data classification before distribution. The bundle does not independently authenticate a remote Git server or prove that the signed candidate corresponds to a deployed artifact. The verifier assumes files are not concurrently modified during verification; production requires immutable snapshots, resource limits, independent identities and key lifecycle controls.

## What's new in v0.3

### Verification Harness

The host constructs a seeded verification plan and compares observations from a separate worker against an independent reference oracle. The worker does not return boolean gate decisions. Each candidate receives 37 deterministic cases:

| Family | Cases | Purpose |
|---|---:|---|
| Original acceptance | 4 | Invalid amounts, replay, distinct keys, conflicts |
| Generated property checks | 24 | Randomized (seed 104) positive amounts, repetitions, conflicts and negative amounts |
| Differential compatibility | 8 | Compare candidate with actual baseline observations on distinct positive keys |
| Contract flow | 1 | Authorization and payment operation sequence |

Additionally, the suite is challenged with three deliberately defective fixture variants (invalid amount, ignored conflict, duplicate identity). All must be detected for `mutation_adequacy` to pass. This is a small curated mutation suite, not a full mutation-testing framework or mutation score for the candidate. The contract flow is an in-process domain contract, not an HTTP/network E2E test.

```sh
uv run intent-merge demo --scenario property-regression --out results/property-regression
```

This candidate rejects zero but accepts negative amounts. The four original criteria pass, while generated properties fail. Merge is denied. This demonstrates the difference between example-based tests and broader invariant checking.

### Convergence Governor

A pure state machine records failed gate IDs, resolved and reopened gates, exact Git tree repetitions, cycle length, cumulative verification cases, diff bytes, and absence of improvement. Improvement requires a strict subset of the best failed-gate set, rather than a higher aggregate score alone. Mandatory drift violations terminate immediately. Execution errors, cumulative case/diff budgets, excessive reopened checks, repeated trees, no progress and iteration limits prevent authorization.

```toml
[convergence]
max_cases = 148
max_diff_bytes = 12000
max_reopened = 1
```

These are candidate-loop limits, not total execution or API token limits: baseline calibration, mutation probes and a stale-approval refresh are outside this budget. Case/diff limits are evaluated after candidate verification and prevent merge, not resource preemption. Worker timeout and container resource limits address runtime separately. No real LLM cost or token telemetry is claimed.

```sh
uv run intent-merge demo --scenario budget-exceeded --out results/budget
uv run intent-merge demo --scenario regression-loop --out results/regression
```

### Docker worker adapter

```sh
docker pull python:3.11-slim
uv run intent-merge demo --scenario happy --executor docker --image python:3.11-slim --out results/docker-happy
```

The adapter resolves the locally available image ID, runs by ID with `--pull never`, and records the ID. Only a temporary directory containing the worker and candidate is mounted read-only. No repository, Git credentials, trust keys or Docker socket are mounted. Network disabled, non-root UID, dropped capabilities, no-new-privileges, read-only root filesystem, bounded tmpfs, CPU/memory/PID limits and wall-clock timeout with best-effort cleanup. If Docker or its image is unavailable, execution fails rather than silently falling back. A CI job is supplied for runtime validation on GitHub-hosted Linux.

**Trust boundary:** Docker adds containment but is not a guarantee against container escapes or fabricated observations by malicious Python inside the worker. The default `local` executor is explicitly for bundled synthetic fixtures, not untrusted code. Neither executor constitutes a hardened production sandbox. The worker output is parsed and compared on the host, but shares a process with the candidate and is not independently attested. Host output capture is not a hard memory bound. Production requires stronger process isolation, output limits, verified images, independent test attestations, and an explicit threat model. Docker was not available in the release-build environment.

## Scenario catalog

| Scenario | Expected outcome |
|---|---|
| happy | 9/13 → 13/13 checks, simulated Engineering and Security approval, actual local Git fast-forward |
| missing-approval | Deny missing Security approval |
| stale-approval | Deny approvals bound to an older SHA |
| scope-violation | Reject proposed out-of-scope path before writing |
| protected-path | Reject attempted test modification |
| loop | Stop repeated Git tree (two-state cycle) |
| failed-eval | Stop no progress with unresolved acceptance |
| self-approval | Deny author approval |
| stale-base | Deny moved target branch |
| stale-eval | Deny stale evaluation |
| intent-drift | Deny protected authorization-symbol change |
| signature-drift | Deny API signature change |
| import-drift | Deny new static import |
| property-regression | Deny despite 4/4 original functional checks |
| budget-exceeded | Deny otherwise passing oversized diff |
| regression-loop | Stop reopened gates above threshold |

## Existing v0.2 capabilities

- Spec-driven requirements, non-goals and executable structural invariants (AST).
- Intent Graph linking requirements, evidence, Git commits, checkpoint and decision.
- Portable session metadata normalization; vendor identities are self-reported. Real Claude Code and Codex hooks are not implemented.
- Deterministic policy enforces mandatory gates, required independent approval roles, scope, exact head/base, spec, policy and harness bindings. Approval identities and signatures are simulated.
- Hash-chained evidence, manifest and separately trusted anchor; policy and intent graph replay.

```sh
uv run intent-merge normalize-session --input examples/sessions/codex-portable.json
uv run intent-merge inspect --out results/happy --requirement R02
```

## Evidence

Alongside existing `ledger.jsonl`, candidate snapshots, diffs, `intent-graph.json`, `checkpoints.json` and `report.json`, v0.3 writes:

| Artifact | Contents |
|---|---|
| `verification-plan.json` | Seed, stable IDs, case inputs |
| `baseline-observations.json` | Differential baseline |
| `verification.json` | Candidate observations, check and case outcomes |
| `mutation-report.json` | Mutant digest, observations and detection result |
| `convergence.json` | Per-iteration state and termination reasons |
| `acceptance.py` | Worker program |

The harness binding includes hashes of the worker, verification plan, host oracle and convergence source. The auditor checks evidence integrity and reconstructs the gate outcomes from recorded observations, mutation results, convergence transitions, structural drift, graph and policy decision. It does not rerun the candidate or prove observations were faithfully collected by an external execution environment. The local anchor and Ed25519 public approval keys are colocated for reproducibility. Local audit alone is not an external trust anchor; the signed bundle uses an externally distributed signer public key. Never publish private keys. The local merge is single-process, not atomic remote authorization.

## Roadmap

- v0.4 (implemented): signed evidence bundles and decision-only counterfactual policy replay.
- v0.5 (implemented): GitHub preflight REST adapter, native Claude Code/Codex session import and offline Governance Explorer. Live smoke tests and full real-change attestations remain outstanding.
- v0.6 (implemented): AMGB v1 signed fixed-trace ablation, offline replay and visual reports.
- v0.7: adaptive autonomy and incident-to-eval.
- v0.8: coordinated multi-repository change sets (local reference).

## Release scope

The payment governance demo remains synthetic. v0.5 adds an optional live GitHub REST client and native session import; neither is a full real-change authorization pipeline. No production payment processing is included. Structural invariants are not general semantic equivalence. Verification cases are finite and public. This project is a reference implementation for research and engineering demonstrations, not production-ready governance software.
