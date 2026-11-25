# AMGB v1 — benchmark protocol

## Research question
Which additional governance gates change eligibility decisions on the same evidence? AMGB v1 is a paired, cumulative, decision-only ablation, not a trial of independent agent workflows or a vendor benchmark.

## Dataset and labels
The catalog in `src/intent_merge/benchmark.py` declares 19 labels before classification. Four fixtures are intended valid (happy, safe-first, safe-refactor, safe-delayed); 15 are intended blocked, including missing/stale/self approvals, stale base/eval, protected/out-of-scope proposals, repeated or regressing candidates, budget exhaustion, unmet functional requirements, drift and property violations. Labels include governance violations even if the code itself is correct. All fixtures are in the synthetic payments domain and equally weighted. No sampling or statistical generalization is implied. Several fixtures share code, so they are not independent real-world observations.

The full runner executes each fixture in a separate local Git repository using trusted synthetic Python, seeded verification cases, simulated agents/reviewers and actual cryptographic signatures. It signs the portable bundle using an ephemeral demo signer; only public keys are included. The bundled key is a demo trust root, not an organizational identity. Replay verifies signature, inventory and deterministic audit before reading the scenario. Catalog membership and spec/policy digests are fixed for v1; the harness digest must be consistent and is validated by the existing audit. The report includes catalog/configuration hashes and per-scenario ledger roots. The original policy includes Engineering and Security approvals. A modified policy requires a new benchmark catalog/version or the separate policy replay feature, not relabeling this suite.

## Strategies

- S0: four original acceptance gates.
- S1: S0 + extended property, differential, contract, mutation checks.
- S2: S1 + scope, trusted harness, structural intent drift, requirement coverage, checkpoint binding.
- S3: S2 + successful convergence termination.
- S4: full independently replayed authorization engine, including exact evaluation/base/head binding, approval authenticity, role and author separation, and all required gates.

No hypothetical merge is executed during ablation. The local merges in the corpus are those produced by the full fixture runner. Scope rejections occur before candidate execution; S0 and S1 block because evidence is absent, not because acceptance tests identify protected-file changes. Every strategy fails closed on missing required observations. We expose the number of scenarios with missing checks explicitly. On the 13 blocked scenarios with recorded acceptance evidence, S0 would allow 10; on the full 15 it would allow 10. Neither denominator represents a production rate.

## Metrics

- True allow = expected allow and hypothetical allow.
- True block = expected block and hypothetical block.
- Unsafe allow = expected block but hypothetical allow (includes policy violations; does not assert a known runtime exploit).
- False block = expected allow but hypothetical block.
- Unsafe allow rate = unsafe allows / all expected blocks.
- False block rate = false blocks / all expected allows.
- Unsafe share of allows = unsafe allows / all hypothetical allows.
- Accuracy = correct decisions / all scenarios. Zero denominators are null.
- Missing evidence scenarios = number of scenarios missing one or more required checks.
- Observed work = actual proposals, candidate evaluations, governed iterations, successful worker case observations, planned candidate cases, requirement coverage and simulated approval counts. These are shared trace measurements, not per-strategy workload. Candidate cases exclude baseline and mutation work. The case counts report the expected observation inventory for successful executions, not a hardware or runtime trace.

## Reproduction and limitations

Run `intent-merge benchmark-replay --profile historical-v1` with the shipped bundles and separately supplied demo public key. A fresh `intent-merge benchmark` generates new signed traces. Exact replay of a corpus is deterministic; fresh evidence hashes differ. Signed evidence authenticates recorded observations relative to a trusted key, not the truth of every observation. The fixture worker is not an adversarial execution sandbox. There are no real LLM, reviewer, API, latency, cost or production measurements. Full-harness trace collection has selection/termination bias: alternative workflows could produce different candidates. Results are illustrative of mechanisms on this suite only; test diversity, independently authored held-out fixtures, live experiments and prospective validation are future work.
