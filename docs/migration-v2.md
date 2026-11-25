# Migrating from v1.0.0 to v2.0.0-rc.1

Unpublished experimental candidate. Python package version: `2.0.0rc1` (PEP 440); proposed Git tag: `v2.0.0-rc.1`. No production or remote merge authority. Do not migrate a production gate to this research implementation.

| Contract | Migration |
| --- | --- |
| Scope patterns | Review every allowlist, protected pattern and risk rule. `*` and `?` do not cross `/`; whole-segment `**` matches zero or more segments. No gitignore negation, character classes or implicit directory patterns. Reject unsupported patterns. |
| Local candidate binding | Fresh decisions require `path_semantics: segment-v2` and the v2 approval context. Recompute evidence and approvals; do not relabel historical artifacts. |
| Approval | Use the domain-separated Ed25519 envelope with expected author, role, candidate binding, key fingerprint, nonce and validity window. Maximum lifetime 300 seconds. Do not reuse legacy signatures. |
| Challenge registry | Use the trusted local caller to issue and consume challenges. The pure policy functions do not enforce single use; database deletion, rollback and post-consumption revocation remain outside this guarantee. |
| Changesets | Require config version 2 and explicit `path_semantics: segment-v2`; regenerate plan and approvals. v1 receipts can be verified historically, not executed. Changeset approvals do not yet use the single-candidate registry. |
| GitHub preflight | Normalized policy digest changes. Reissue any dependent assertions and receipts under a reviewed policy. CLI publication requires `--app-id`, `--installation`, `--app-key`. Keep the key outside the workspace; read-only access uses `ITM_GITHUB_TOKEN`. |
| Audit | `audit` is synthetic historical replay. `audit-anchored` requires independently obtained anchor and public trust-store SHA-256 pins; does not confer current authority. |
| Errors | CLI execution failures emit redacted structured JSON and exit nonzero. `NOT_CONFIRMED` means remote state must be reconciled, not blindly retried. |

Retain the signed v1.0.0 tag, source archive, lock, and exact trust anchors. Do not change the historical AMGB reports or keys. Reproduce them with the documented historical verifier. Do not treat the new package version as a new schema version for every evidence profile.

## RC1 remediation compatibility

Fresh PAY-104 evidence uses the default `current` verification profile. It requires
the segment-v2 path contract, the v2 approval envelope and a complete challenge
issue and claim. Each checkpoint records a regular-file Git text diff from the
baseline to `app/payments.py`. The auditor reconciles the patch and tree with
the recorded source and proposal. A refresh can retain a tree under a new
commit. A rejected proposal records its attempted paths before execution.

Choose `historical-v1` only when trust context independently identifies an
archived v1 corpus or run. This selects the archived fnmatch and pre-v2 approval
contract. Evidence metadata must agree with the selected profile. Intermediate
approval-only profiles require their archival verifier or fresh evidence.

- Pass `--profile historical-v1` with archived inputs to `audit`, `verify-bundle`,
  `policy-replay`, `explorer`, `benchmark-replay` or `autonomy-gate`.
- In Python, pass `profile=HISTORICAL_V1` from `intent_merge.evidence_profile` to
  `runner.audit`, `trust.audit_synthetic`, `bundle.verify`, `replay.replay`,
  `explorer.render`, `benchmark.evaluate_corpus` or `autonomy.gate`.
- `audit-anchored`, `trust.audit_anchored` and new bundle packing use the current
  contract. `autonomy-demo` is a study of the archived v1 corpus and fixes its
  verification profile in the study code. Fresh benchmark generation uses current
  verification.
- The DSSE predicate, audit result fields and archived report formats retain their
  existing wire formats. Supply stable evidence directories to offline consumers.

The journaled worker uses the signed assertion expiry by default. The strict
worker also requires independently signed receipts and takes the earliest
expiry. Success requires an ordered clock sample after the journal commit and
before the request, with time strictly earlier than expiry. In Python, `now`
sets the evaluation time. Offline tests can inject an independent
`publication_clock` callable returning integer epoch seconds. A trusted custom
gate must return a supported profile with verified evidence and expiry to
publish success. The CLI uses the wall clock for publication.

A known pre-request denial records `BLOCKED_BEFORE_PUBLICATION`. An attempted
write with an unconfirmed response records `UNCERTAIN` and preserves correlation.
Use read-only reconciliation to resolve a unique matching response. Sweep flags
a known-success row with an invalid stored ID as `REMOTE_STATE_UNKNOWN`. Older
corrupt journals require operator inspection against independently verified
remote state. Expiry or ref changes can occur after the request starts.

Direct `github-preflight --publish` writes the distinct diagnostic
`ITM / PR preflight` check. The evidence-gate expiry contract applies to
`ITM / evidence gate` produced by the journaled worker. Keep diagnostic and
lab transport checks out of required merge controls.

Invalid user TOML and local spec or policy validation return structured
`INVALID_CONFIGURATION`, with `authorized` and `merged` false, and exit 2.
`demo` writes its configuration rejection event when the output directory can
be created. Valid policy blocks exit 0. Unexpected operational failures exit 1.

## Steps

1. Review the candidate on a separate branch and verify its exact inventory. Back up trusted evidence and registry state through an independently administered process.
2. Review patterns and migrate configurations; use fresh output directories and newly issued approvals. Do not import secrets into the candidate workspace.
3. Run both locked installation profiles, replay AMGB and the operational study, and qualify integration, Docker and scans as described in [RC qualification](qualification-v2-rc1.md).
4. Obtain an independent review and explicit maintainer publication decision. A passing scan or test is evidence, not publication approval.

## Detailed contracts

[Paths and schema](policy-hardening-draft.md) · [Approval envelope](approval-envelope-v2-draft.md) · [Registry](approval-challenge-registry-draft.md) · [Changesets](changeset-path-policy-v2-draft.md) · [Trust](trust-profiles-draft.md) · [Operational CLI](operational-hardening-draft.md).

## Resumo em português

Revise todas as regras de escopo: `*` e `?` não atravessam diretórios e `**` representa segmentos recursivos. Emita novas evidências, planos e aprovações; nunca converta artefatos históricos apenas trocando a versão. O CLI de publicação exige credenciais de instalação de GitHub App. Preserve a tag v1.0.0 e os pins históricos. Os perfis de auditoria não concedem autorização atual. A migração não torna o laboratório adequado à produção nem resolve isolamento hostil, independência organizacional ou enforcement de merge queue.
