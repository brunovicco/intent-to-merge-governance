# RC.6 — Security hardening and release qualification

New bounded executor for the RC6 integrated runtime, exact Git candidate binding checks, journal v2 revocation fences and externally pinned checkpoint verification. The signed historical benchmark corpus is intentionally preserved unchanged. Other legacy execution paths do not inherit RC6's bounded capture automatically. No new production authority, remote publication, mTLS or hostile isolation is claimed.

```sh
uv sync --extra telemetry
uv run python -m unittest discover -s tests -p 'test_rc6.py' -v
uv run python -m unittest discover -s tests -v
uv run python scripts/integrated_runtime.py run --fixture repair --out results/rc6-repair
uv run python scripts/journal_checkpoint.py --db results/rc6-repair/lifecycle.sqlite
```

The repair fixture should converge in two attempts, with governance BLOCK and `merge_authority: false`. Journal checkpoint is for offline comparison, not authorizing evidence. Save the printed digest to a trusted, separately administered location; then compare explicitly:

```sh
uv run python scripts/journal_checkpoint.py --db results/rc6-repair/lifecycle.sqlite --expected-digest "$EXPECTED_JOURNAL_DIGEST"
```

Do not re-pin a mismatching journal until the change is independently reconciled. A legitimate journal update changes the digest too. Old schema v1 journals are historical only: use fresh RC6 output directories. Do not delete prior results.

To qualify Docker on your Mac, run the existing opt-in integrated live pilot in a disposable separate OS account or VM with Docker and no privileged credentials; see [RC5 runbook](rc5-runbook.md). Change output directories to `results/rc6-claude` and `results/rc6-codex`. No provider token limits beyond observed admission are implied.

For the complete threat register and outstanding production criteria see [security review](rc6-security-review.md). Full supply-chain vulnerability analysis and SBOM generation are deferred until a network-enabled, controlled release pipeline is available.

## Offline release inventory

```sh
uv run python scripts/release_inventory.py verify
```

The shipped `release-inventory.json` lists file SHA-256 digests, declared direct dependencies and builder-observed versions. It is not a signed release or a complete transitive SBOM. The ZIP hash must be compared against an independently trusted reference. The verifier expects the unmodified release tree (ignores local results, environment, caches and Git metadata). Do not regenerate the inventory merely to make unexpected changes pass.
