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

## Scope and residual limitations

The core is fixture-specific and assumes a trustworthy specification and verification oracle. The challenge registry is local and per-run; not a distributed revocation or rollback-resistant authority. The changeset protocol remains distinct. Externally supplied trust pins are not proof of independent organizational custody. CLI failures cannot revoke a prior remote check atomically. Docker is not hostile-code isolation. Static analysis review is not security certification. The release is experimental and each profile retains its specific qualification boundary.

## Final implementation and operational qualification

The independently reviewed and locally qualified implementation is commit
`fe7bafc91a6b7c452ef20f2b13afdd1e49aeff7f`, tree
`03a97ab53598ee315db031fe4db795c404325a0c`, on `hardening/rc1-review-remediation`.
The commit signature verified against fingerprint
`595963A633AD2B1C51CEB5128D68A79E8E42285E`. The clean source inventory
matched 720 entries including the lockfile. Git tracks 721 files including
the inventory itself. The stable baseline remains `v1.0.0`. The proposed Git
prerelease tag is `v2.0.0-rc.1` and the Python distribution version is `2.0.0rc1`.

The documentation-only successor has a separate tree identity. Exact-tree
review and operational results below apply to the implementation tree above.
The final merged tree will have to be identified and verified before publication.

### Six remediation rounds

Each row records the implementation at the end of the round. The initial
candidate entered remediation at `238b0abd1bc09a830c2be468cf70ef18babcfc12`
(tree `e99e6626e73374dd60ca5075cbfe268cba93e1a3`), the merge of version
preparation commit `1bdbb8c4e5afe0e7d834a8fd4f1b2f66df7854c1` with the same tree.
The initial candidate and rounds 1–5 did not clear review for release. Their
commits are unpublished candidate history.

| Round | Candidate commit and tree | Invariants established |
| --- | --- | --- |
| 1 | `0acf6b465fd7ef6d84e4ca29445e3e6de99f3b54` · `4e94e5df2ab93c595304a5d56494641d442469de` | Recheck freshness at final publication. Preserve write-intent evidence when changeset state cannot be confirmed. Reconcile signed evidence semantically and return structured CLI rejections. |
| 2 | `c21a6b67c8c0ebf54ec5eeeace40b57080e7c4c1` · `2cbda6106065fa2cbf24d61a78fe8f8ef091b72d` | Bind the candidate patch and the caller-selected evidence profile, validate remote acknowledgements, and enforce input schemas across entry points. |
| 3 | `0d5cd875afceabb615505dfa940c3c95e6144dd0` · `dfab58b62d1baa56576c0dcb449788649e1025d8` | Reconcile observed Git identity with source and tree, preserve immutable publication correlation across restarts, recover uncertain publication and revocation states, and verify the complete evidence inventory. |
| 4 | `dcbbd23d669c81a7c3bbf29b4f581b610e7f7b82` · `8f7fe0d69cfa504117eaa2e5f71bed01198511c5` | Resolve exact Git objects under the trusted bare-repository contract and refresh evidence at the sweep decision boundary. |
| 5 | `da04368edd5148e837382bad847da0635e7774ff` · `853861cab59126b27bfcd33e699d7a8e19cb1ad7` | Validate external responses and isolate recoverable sweep failures per publication while propagating systemic failures. |
| 6 | `fe7bafc91a6b7c452ef20f2b13afdd1e49aeff7f` · `03a97ab53598ee315db031fe4db795c404325a0c` | Require counted pagination, a complete exposed collection and unique, valid check-run identities across the entire collection before consumers use the evidence. |

### Independent AI-assisted review

The reviewer reported `RELEASE_CANDIDATE_ACCEPTABLE`. Both remaining
medium-severity blockers were closed. The reviewer confirmed no new critical,
high or medium defect contradicting the declared guarantees. This was an
independent AI-assisted review with a scoped technical verdict. Human security
audit and certification were outside its remit.

The retained reviewer probes show the rejected round-five candidate accepting
an incomplete collection or contradictory run identity in cases where the
final implementation rejected the observation. The retained collection and
test logs corroborate 56 independent collection payload cases, 121 focused
tests, 426 passes with one expected telemetry skip in minimal mode, and 427
passes with telemetry enabled. No `ResourceWarning` was reported. The reviewer
also reported inventory verification at 720/720 and preservation of historical
compatibility. These are reviewer results. The round-six implementation
transfer record is separate maintainer evidence on the reconstructed candidate
tree.

### Local operational qualification of the signed implementation

The results below are from the saved qualification reports for the signed
implementation. The saved AMGB and operational outputs were also compared
directly with the archived fixtures during documentation consolidation.

| Check | Verified result |
| --- | --- |
| Locked minimal suite | 426 passed, one expected telemetry skip, 427 discovered in 94.631 s. No `ResourceWarning`. |
| Locked telemetry suite | 427 passed, zero skips, 427 discovered in 100.026 s. No `ResourceWarning`. |
| RC1 and workspace capture | Four local scenarios, eight simulated API cases, and five passing workspace capture self-tests. |
| RC2 fixture execution | Passed. Five fixture runs passed for each of the Claude and Codex adapters. |
| RC3 curated ablation | The final stage accepted zero of 20 curated unsafe cases and all five safe cases. |
| RC4 local control plane | 15/15 expected outcomes. |
| Integrated repair and journal | Convergence passed after two attempts and governance returned `BLOCK`. A journal checkpoint was generated with `matches_external_pin: null`. External checkpoint pinning was outside this run. |
| Historical AMGB and operational replay | AMGB JSON, HTML and both CSV files matched byte for byte. Operational JSON and HTML matched byte for byte. |
| Changesets and historical receipts | All eight scenario rows matched. Three signed historical receipts verified integrity and execution replay. |
| Docker fixture | Fixture execution, synthetic audit and exact bare-repository candidate verification passed. Live agent and GitHub App probes were unrun. |
| Compose control plane | No-cache build passed and six services became healthy. The coordinator matched 15/15 outcomes. All 15 reports verified against the retained lab trust pin and a wrong pin was rejected. One synthetic `ALLOW` was current at local replay time with `merge_authority: false`. Teardown completed. |
| Dependency advisory scan | Fresh pip-audit examined seven locked runtime dependencies and reported no known vulnerabilities at scan time. |
| Static analysis | Fresh Bandit matched all 58 reviewed findings with zero unresolved and zero missing. Maintainer review of dispositions remains pending. |
| Secret scans | Fresh Gitleaks scans of the source snapshot and history reachable from the implementation commit found only the four reviewed public fixture keys. |
| Source integrity | Inventory verification with the lockfile and `uv lock --check` passed before and after qualification. The implementation commit and tree were unchanged. |

The run used host Python **3.14.7** and selected **CPython 3.11.11** for the
locked qualification environment. It recorded **Git 2.49.0**, **uv 0.12.13**
and **Docker Compose 5.2.0**. The security script used **pip-audit 2.9.0**,
**Bandit 1.8.6** under Python 3.11 and **Gitleaks 8.30.1**. CI pins **uv
0.12.10**. The saved reports do not record the Docker Engine or Docker CLI
version.

The fixture used the mutable `python:3.11-slim` tag. The recorded pull
resolved to
`sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c`.
The Compose control-plane build uses a separate digest-pinned base in
[its Dockerfile](../Dockerfile.control-plane).

### Final scope and residual limitations

- The reference verification oracle is fixture-specific. Agent execution and repair qualification used fixtures, with live autonomous agents outside the run. The curated studies measure their fixed cases.
- Check enumeration validates up to 3,000 exposed runs and rejects refs advertising 1,000 or more check suites. Consistent collections do not establish atomic GitHub snapshots. GitHub can omit older suites from a ref-level listing or delete older same-name runs under its documented API behavior. [Operational boundaries](operational-integration.md#github-check-collection-limits)
- Exact Git object verification assumes a trusted self-contained bare repository and a trusted Git executable.
- Publication and merge are not atomic. True merge-queue enforcement and live GitHub App transport and revocation remain unqualified for this candidate.
- Docker and same-host control services do not establish hostile-code isolation or organizational independence. Local trust pins do not establish independent organizational key custody.
- Dependency advisory results are point-in-time observations. Reviewed static-analysis findings still carry residual security risk.

### CI command compatibility

The AMGB step selects `--profile historical-v1` explicitly for the archived
corpus. The Docker job audits fresh fixture output using the default
`current` profile. The historical changeset verifier selects its legacy contract
through the archived configuration and expected digest. There is no replay
profile discrepancy in these commands. CI compares only the JSON AMGB and
operational outputs and verifies one historical changeset receipt. The saved
local qualification additionally compared HTML and CSV outputs and verified
three receipts. Exact-commit CI for the documentation successor remains a
separate publication gate.

### Publication gates

| Gate | State |
| --- | --- |
| Implementation hardening and independent AI-assisted review | Complete for the signed implementation. |
| Local operational qualification and fresh scanner runs | Complete for the signed implementation. |
| Documentation-only successor validation | Pending maintainer review of the exact documentation diff and verified successor identity. |
| Maintainer review of security dispositions | Pending. |
| Private vulnerability reporting verification | Pending. |
| Rights, license, attribution and privacy review | Pending. |
| Signed documentation commit | Pending. |
| Pull request and exact-commit CI | Pending. |
| CodeQL and dependency graph verification | Pending. |
| Final merge-tree verification | Pending. The final merged tree is unavailable. |
| Explicit maintainer release authorization | Pending. |
| Signed prerelease tag and archive verification | Pending. Verify both against the approved commit and verify the separately signed archive checksum if distributing a ZIP. |
