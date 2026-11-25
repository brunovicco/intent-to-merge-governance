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

## Steps

1. Review the candidate on a separate branch and verify its exact inventory. Back up trusted evidence and registry state through an independently administered process.
2. Review patterns and migrate configurations; use fresh output directories and newly issued approvals. Do not import secrets into the candidate workspace.
3. Run both locked installation profiles, replay AMGB and the operational study, and qualify integration, Docker and scans as described in [RC qualification](qualification-v2-rc1.md).
4. Obtain an independent review and explicit maintainer publication decision. A passing scan or test is evidence, not publication approval.

## Detailed contracts

[Paths and schema](policy-hardening-draft.md) · [Approval envelope](approval-envelope-v2-draft.md) · [Registry](approval-challenge-registry-draft.md) · [Changesets](changeset-path-policy-v2-draft.md) · [Trust](trust-profiles-draft.md) · [Operational CLI](operational-hardening-draft.md).

## Resumo em português

Revise todas as regras de escopo: `*` e `?` não atravessam diretórios e `**` representa segmentos recursivos. Emita novas evidências, planos e aprovações; nunca converta artefatos históricos apenas trocando a versão. O CLI de publicação exige credenciais de instalação de GitHub App. Preserve a tag v1.0.0 e os pins históricos. Os perfis de auditoria não concedem autorização atual. A migração não torna o laboratório adequado à produção nem resolve isolamento hostil, independência organizacional ou enforcement de merge queue.
