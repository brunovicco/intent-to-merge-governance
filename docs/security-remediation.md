# Public source candidate — security remediation 1

Publication HOLD; no merge authority. The maintainer's first 1.0.0 candidate passed 212 tests (79.027s), sealed 662 files and exported a CycloneDX 1.5 runtime SBOM. That result applies to the previous candidate. The dependency audit reported four advisories in cryptography 46.0.7. Bandit 1.8.6 under Python 3.14 failed internally; a separate Python 3.11 run reported no errors, 59 LOW, 5 MEDIUM and 0 HIGH findings. Gitleaks reported four generic-api-key findings.

| Finding | Assessment/action |
|---|---|
| PYSEC-2026-3552, -3553, -3554; GHSA-537c-gmf6-5ccf | Raise cryptography constraint to >=50.0.0,<51. Official changelog documents CVE-2026-69247 fixed in 50.0.0; resolve latest compatible patch and rerun pip-audit. |
| B310, scripts/control_plane.py:12,34 | Replace generic URL opener for health and evaluate requests with direct HTTPConnection, exact loopback or per-control Compose hostname/port, two known routes, no proxy/redirect processing, bounded response bytes. Private lab only; DNS/host compromise, transport authentication and robust total-deadline enforcement remain out of scope. |
| B608, integrated.py:192 | Reviewed: SQL table names and order expressions are fixed source literals. Preserve code. |
| B608, operational.py:93 | Reviewed: allowed column names limited to report/external_id/check_id; values and state/ID use SQL parameters. Preserve code. |
| B108, verification.py:86 | Reviewed: /tmp is a container tmpfs with noexec,nosuid,nodev,size=16m, not a predictable host temporary file. Historical verifier bytes must remain unchanged. Container restrictions do not establish hostile isolation. |
| Gitleaks generic-api-key x4 | Public Ed25519 verifier keys, not secrets: changeset-v1/config.json lines 11,19,29,32. Preserve signed fixture bytes. Scan all distributed files; classify only those lines on the exact fixture SHA-256 and rule. Unexpected findings, scanner errors or a changed fixture block classification. Raw redacted report remains available. |

The 59 LOW findings have not been individually reviewed. No blanket suppression or clean SAST claim. Review the new report including LOW findings before publication. The security script deliberately returns nonzero when Bandit reports findings; successful scanner execution is not manual approval. Gitleaks uses a dedicated exit code for findings rather than treating a scanner error as reviewed. Public keys are excluded only from the unresolved finding count, not from the scanner.

The builder cannot resolve the new lock or run full scanners. Tests use installed cryptography 46.0.4, not the required 50.x. The local synthetic HTTP study matched 15/15 cases. No GitHub publication, production authority or remote changes.

## Maintainer qualification

Extract into a separate clean directory (do not overwrite the prior sealed package). Verify inventory, generate a fresh resolver lock and seal it; follow docs/public-release.md. Verify installed cryptography version, full regression, historical replay and distributed Compose. Preserve scanner and SBOM reports, review results, and confirm licensing and identifiers before signing. The old lock remains evidence of the previous candidate, not a valid lock for this one. This update is not a new published version.
