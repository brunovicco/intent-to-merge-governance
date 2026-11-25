# v2.0.0-rc.1 — qualification record and release gates

**HOLD — unpublished.** `publication_ready: false`, `production_ready: false`, `merge_authority: false`.

## Maintainer-reported qualification before version preparation

The maintainer ran the six hardening increments and the supplementary Bandit review on the local branch `hardening/policy-controls`. The final integration log identifies the 702-file inventory and staged four-file review. These are reported results, not an independently reproduced full suite or evidence bound to a signed RC commit. Version preparation follows these runs.

| Check | Result | Boundary |
| --- | --- | --- |
| Minimal install | 312 passed, 1 expected telemetry skip (313 discovered), 99.516 s | Maintainer Mac |
| Full install | 313 passed, 86.904 s | Maintainer Mac, locked telemetry extra |
| Historical AMGB | byte-identical report | Fixed signed traces; not new live runs |
| Inventory | 702/702, lock check passed | Pre-RC tree |
| Dependency audit | no known vulnerabilities reported | Locked Python runtime, point in time |
| Bandit | 58 reviewed; 0 unresolved/missing; 39 lab residuals remain | 14 import, 2 fixed SQL, 2 nonsecurity, 1 container tmpfs |
| Gitleaks 8.30.1 | 4 public-key fixture findings, 0 remaining; fixture digest matched | Directory scan; not full history |
| Security status | SCANS_COMPLETED_REVIEW_REQUIRED | No publication approval |
| RC1 | 4 local scenarios, 8 API cases; five capture self-tests passed | Synthetic/mock and local probes |
| RC2 fixtures | 5/5 each Claude and Codex | No live agent calls or cost observations |
| RC3 ablation | 20/20, 15/20, 10/20, 0/20 unsafe accepts; 5/5 safe accepted each stage | Curated adversarial candidates, not incident rates |
| RC4 | 15/15 expected outcomes | Local synthetic control processes, no new Compose run |
| Integrated repair | PASSED after 2 attempts; governance BLOCK | Fixture, not live repair |
| Journal checkpoint | digest calculated, `matches_external_pin: null` | No independent pin comparison |
| Changesets | 8 expected scenario outcomes | Local synthetic writes/compensation, not remote transactions |
| Operational study | 6 cases; byte-identical replay | Synthetic transport, not authenticated GitHub |

The v1.0.0 results remain in the original documentation and signed tag. Do not replace historical reports with fresh results or pool the two adversarial studies. No production authorization, live iterative repair, independent organizational signing, hostile isolation or merge queue enforcement has been established.

## Exact RC release gates (pending)

- [ ] Review the RC diff and verify the inventory, lock, and unchanged external dependency graph. Use the maintainer-validated uv version.
- [ ] Run locked minimal and telemetry-enabled suites (313 discovered each; one expected skip only in minimal). Check ResourceWarnings and retain exit codes.
- [ ] Re-run all integration commands from `.github/workflows/ci.yml`, including historical changeset receipt verification, Docker fixtures and offline AMGB/operational comparisons. Run the Compose laboratory with a fresh key directory, verify all receipts against an independently retained lab pin and reject a wrong pin. See [RC4 runbook](rc4-runbook.md). These are still synthetic tests.
- [ ] Run `bash scripts/public_security.sh results/v2-rc1-security` on the exact RC and inspect all reports. Do not change the baseline to hide new findings; review any actual difference. Run a redacted Git history secret scan separately. Never publish raw scanner or agent logs automatically.
- [ ] Confirm private vulnerability reporting, rights, license/attribution, privacy review and acceptance of residual experimental risk for this exact candidate.
- [ ] Commit and verify signature, push the review branch only with maintainer approval; require both CI workflows on the exact signed commit. No implicit merge or publication.
- [ ] If approved, sign an annotated prerelease tag and archive the exact reviewed commit; publish the archive, commit identifier, signed checksum manifest and explicit limitations. Preserve the v1.0.0 tag. Do not mark a prerelease as production-ready or grant merge authority.

## Scope and residual limitations

The core is fixture-specific and assumes a trustworthy specification and verification oracle. The challenge registry is local and per-run; not a distributed revocation or rollback-resistant authority. The changeset protocol remains distinct. Externally supplied trust pins are not proof of independent organizational custody. CLI failures cannot revoke a prior remote check atomically. Docker is not hostile-code isolation. Static analysis review is not security certification. The release is experimental and each profile retains its specific qualification boundary.
