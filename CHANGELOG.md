# Changelog

## 2.0.0-rc.1 — Security hardening (candidate, unpublished)

- Versioned segment-based paths and configuration validation in the local policy engine, GitHub preflight and new changesets.
- Domain-separated, time-bound Ed25519 approval envelopes and a single-use local SQLite challenge registry.
- Explicit historical versus externally pinned historical trust profiles; no current organizational authorization.
- Redacted CLI execution errors, explicit GitHub App credentials for CLI check publication, minimal and telemetry-enabled test jobs.
- Preserve signed v1 artifacts and historical replay; new decisions require the new contracts. See [migration](docs/migration-v2.md).
- Pre-version-change qualification is recorded separately; exact RC scans, test runs, Docker and publication approval remain required.

## 1.0.0 — security remediation candidate (unpublished)

- Raise cryptography dependency floor to 50.0.0, pending resolution and fresh audit.
- Restrict synthetic control-plane HTTP targets and routes; preserve signed historical corpus.
- Run Bandit with Python 3.11; classify four digest-pinned public-key fixture findings without disabling Gitleaks rules. Preserve raw redacted findings and manual review gate.
- Publication remains HOLD; see docs/security-remediation.md.

## 1.0.0 — public research source candidate

- Freeze the RC.6 runtime and historical signed corpus; retain experimental non-authorizing profiles.
- Add publication runbook, architecture, methodology, candidate qualification and proposed Apache-2.0 licensing.
- Report inventory differences; seal only a resolver-generated lockfile without accepting unrelated changes.
- Prepare read-only CI/security workflows; public publication remains conditional on lock, scans, review, signing and owner approval.

## 1.0.0-rc.6 — Scoped security hardening

- Bound integrated verifier stdout/stderr and enforce deadline while collecting output; preserve legacy signed verifier bytes.
- Check exact fixture tree inventory, ancestry and convergence-to-verifier binding; ignore Git replace refs and inherited GIT_* selectors in integrated Git wrapper.
- Journal v2: persistent pre-registration denial, binding-change fence, stale snapshot rejection, external checkpoint digest comparison. Old journals remain historical.
- Add threat model, security policy, runbook and regression probes; production HOLD. No remote changes or hostile isolation claimed.

## 1.0.0-rc.5 — Integrated candidate runtime

- Bounded AUTH-201 multi-attempt loop with exact Git candidates and provider-aware observed usage.
- Separate post-run verification process signs a dedicated non-authorizing lab receipt; real gate receipt validator rejects it.
- Local HMAC event deduplication, revocation persistence, expiry and binding reconciliation.
- Synthetic repair and stop fixtures; no live merge authorization or production qualification.

## 1.0.0-rc.4 — Distributed governance laboratory

- Six separate HTTP control processes and seven independent lab keys; signed, nonce-bound, expiring receipts and aggregate.
- Fifteen distributed synthetic scenarios and persistent local revocation lifecycle.
- Docker Compose topology with per-role key mounts; runtime validation pending.
- Provider-aware observed-budget admission controller and standalone authenticated merge-group parser; not connected to real agent or GitHub workers.
- 16 new unit tests passed and 15/15 HTTP scenarios matched. Full regression and Compose execution pending. No merge authority.

## 1.0.0-rc.3

- Add paired synthetic adversarial replay (25 curated fixtures, four cumulative strategies), exact Git candidate evaluation, and JSON/HTML reporting.
- Exercise real Ed25519 verification with ephemeral synthetic control and aggregate keys, invalid bindings, freshness and tampering; replay a repeated-tree stop. No independent live authority is created.
- Add opt-in live untrusted-context challenge and conservative native usage/cost projection with null for unavailable values and coverage counts.
- Preserve HOLD; live challenge, multi-attempt convergence, independent services, positive authorization/revocation, merge queue and hostile-code isolation remain unqualified.

## 1.0.0-rc.2

- Consolidate validated binary Git status diagnostics and Claude Code explicit edit tool permissions.
- Add randomized paired five-scenario benchmark with synthetic fixture mode and opt-in Docker-only live agent runs.
- Add strict negative evidence-gate publication and distinct non-authorizing GitHub transport lifecycle probe.
- Preserve HOLD; positive independent approval, production authorization revocation, merge queue and hostile isolation remain unqualified.

## 1.0.0-rc.1

- Freeze v0.10 features; add local end-to-end qualification across exact Git objects, signed bundles, autonomy and simulated GitHub strict gate.
- Add opt-in external Docker, real agent and authenticated read-only GitHub App probes.
- Add release qualification protocol, evidence reports and explicit promotion blockers. All 139 inherited tests passed in this candidate; 4 fresh end-to-end and 8 simulated API cases passed.
- No production promotion, remote merge or merge-group enforcement.

## 0.10.0

- Require independent artifact-bound Ed25519 receipts for all six controls in the operational CLI.
- Add check sweep/revocation with remote identity validation and explicit uncertainty states.
- Recompute the payment fixture verification from exact Git objects.
- Persist signed multi-repo CAS state and reconcile interrupted writes or compensate explicitly.
- 17 new hardening tests and all 122 legacy tests passed locally; Docker runtime was unavailable. Document remaining deployment trust boundaries. No atomic remote merge enforcement or live credentials used.

## 0.9.0

- Added scoped GitHub App authentication, authenticated webhook ingress, SQLite delivery deduplication and a single-worker publication journal.
- Added an external verifier assertion gate bound to PR, head, base, policy and expiry; synthetic evidence cannot satisfy the live profile.
- Added uncertainty reconciliation, local agent runner, metadata-only hook adapter and optional OpenTelemetry console spans.
- Added six synthetic transport scenarios, 22 new tests, 81 selected regression tests and operator setup documentation.
- No live GitHub/agent execution, full live verification pipeline, merge-time enforcement or durable multi-repo recovery.

## 0.8.0

- Added local multi-repository change-set planning with a deterministic dependency order, declared contract checks for every intermediate state and exact Git commit bindings.
- Added independent Ed25519 reviewer approvals of the complete plan, per-ref CAS updates, reverse compensation and manual escalation on ref drift.
- Added signed execution receipts, hash-chained event records and offline replay with an externally pinned configuration digest.
- Added eight synthetic scenarios, a reproducible HTML report, and 19 new tests. Re-ran 62 selected prior tests. Legacy bundle/governance suites and Docker runtime were not rerun.
- The coordinator is intentionally local-only; no real remote merge authority, atomic cross-repository updates, durable crash recovery or production rollback.

## 0.7.0 — Adaptive autonomy and incident-to-eval

- Added a signed, scope-bound operational event stream with independent role keys, hash-chain replay and external root pinning.
- Added L0/L1/L2 eligibility restrictions, critical/major incident circuit breakers, adverse-window downgrade and explicit clean-streak recovery.
- Added incident-derived restricted payment regression cases, separate approval, candidate-bound signed observations and persistent regression gates.
- Added `autonomy-demo`, `autonomy-replay`, `autonomy-gate`, an offline HTML study and a checked-in signed example.
- Validated 22 new tests and 42 selected regression tests; reproduced final operational state offline. Legacy bundle/governance suites and Docker were not rerun in this release.
- Operational data and roles are synthetic. No live GitHub enforcement or real merge authority; the existing AMGB v1 corpus and methodology are unchanged.


## 0.6.0

- Added AMGB v1: 19 predeclared synthetic fixtures, five cumulative strategies, paired decision-only ablation, and explicit missing-evidence handling.
- Added three valid fixture variants to complement the original happy path; kept the legacy scenario interface unchanged.
- Added signed corpus generation, external-key verification, exact offline report replay, and fixed specification/policy digests.
- Added HTML, JSON, CSV reports and an SVG results figure, with metric definitions and limitations.
- Added 12 tests covering full replay, tampering, labels, missing evidence, configuration pinning and report exports.
- No LLM or vendor comparison, real approvals, or live GitHub calls in AMGB. No claim of counterfactual execution cost or production safety.

## 0.5.0

- Added opt-in GitHub REST preflight for same-repository PRs, with explicit scope, pinned app/check identities, SHA-bound reviewer roles and optional check-run publication.
- Added native Claude Code and Codex JSONL session import with allowlisted metadata, digest binding claims and explicit self-reported trust.
- Added an offline HTML Governance Explorer that verifies signed bundles and separately labels imported snapshots and fixture sessions.
- Added 16 adapter/Explorer tests and representative fixtures; no live GitHub or provider CLI calls in the tests.
- Preserved the v0.4 signed evidence and replay formats; real PR preflight does not accept synthetic authorization bundles.
- Documented remaining live-validation, event invalidation and enforcement limitations.

## 0.4.0

- Added portable signed change evidence bundles using in-toto Statement v1, DSSE and Ed25519.
- Switched new fixture approvals to ephemeral asymmetric keys; public approval trust only is exported.
- Added offline verification with an externally supplied signer key, exact inventory and deterministic audit replay.
- Added decision-only counterfactual replay, original-policy identity verification, transition summaries and rejection of unsupported policy changes.
- Added a reproducible eight-scenario study, example policy and 14 bundle/replay tests.
- Legacy HMAC evidence is not eligible for portable bundle export.

## 0.3.0

- Added seeded property checks, actual baseline differential comparisons, contract flow and curated mutation checks.
- Added host-side verification oracle and replay of recorded observations.
- Added set-based convergence governor with cycle length, reopened gates, diff and case budgets.
- Added opt-in restricted Docker execution, with no silent local fallback; runtime CI job supplied.
- Added property-regression, budget-exceeded and regression-loop integration scenarios.
- Added verification, mutation and convergence evidence and audit replay.
- Retained v0.2 CLI commands; evidence schema requires matching release.


## 0.2.0

- Typed Intent Graph with JSON and Mermaid exports, reconstructed during audit.
- Versioned requirements and explicit non-goals; mandatory requirement coverage.
- Universal checkpoint contract with portable metadata normalization, observed Git bindings and explicit trust labels.
- Structural AST drift checks for authorization, API signature and static imports.
- Three additional deny scenarios where functional acceptance tests pass.
- Independent audit reconstruction of derived artifacts and structural checks.
- New `inspect` and `normalize-session` commands; 13 unittest methods and 13 scenario matrix cases verified.

Breaking: demo spec now requires requirement mappings and non-goals; audit expects v0.2 evidence bundles. v0.1 artifacts should be audited using the v0.1 release. Real agent integrations and production-grade isolation remain out of scope.
