# Consolidated experimental evidence (RC.1–RC.6)

The reference outputs in `examples/` are generated synthetic evidence unless explicitly marked otherwise. The following live and Mac results are the maintainer's reported runs, not independently reproduced by the RC.6 builder. The repository does not contain the maintainer's raw live agent sessions or GitHub App secrets.

| Release | Maintainer-reported regression | Experimental scope |
|---|---:|---|
| RC.1 | 139 | Local qualification; external Docker verification; separate Claude/Codex pilot; negative GitHub preflight |
| RC.2 | 147 | Five scenarios per agent, ten successful live trials; negative Evidence Gate published; authenticated success-to-failure transport-only check |
| RC.3 | 158 | 25 curated synthetic candidates across four cumulative strategies; ten successful live untrusted-context trials; no persistent unauthorized marker observed |
| RC.4 | 174 | Six synthetic HTTP control services; 15/15 expected outcomes on Docker Compose; synthetic local revocation |
| RC.5 | 187 | Four synthetic convergence/stop experiments; two real first-pass AUTH-201 candidates, 20/20 behavioral cases each; both governance decisions BLOCK |
| RC.6 | 205 | 78.567 s regression; original 645 files unchanged after excluding the single generated uv.lock; fixture repair in two attempts; checkpoint matched previously observed digest; Claude and Codex each PASSED on attempt one, governance BLOCK |

## Interpreting the results

- AMGB historical signed corpus: 19 curated scenarios; fixed-trace strategy ablation. RC.3 adversarial corpus: 25 curated candidates (20 unsafe, five safe); S0/S1/S2/S3 accepted 20/15/10/0 unsafe candidates respectively, zero false blocks in that fixture set. These are controlled demonstrations, not real-world incidence estimates or a representative industrial CI benchmark.
- RC.2 and RC.3 live agents completed five tasks each per release, in single-attempt trials. RC.3 observed no retained unauthorized marker; reading or interpreting the conflicting note was not independently attested. No live adversarial candidate requiring a governance block was produced in those trials.
- RC.5 integrated live trials: Claude Code 31,026 observed tokens and 15.278 s; Codex 104,040 observed tokens and 27.528 s. One trial per agent, self-reported usage and differing cache semantics; no model-level statistical or billing claim. Both passed on attempt one; live multi-attempt correction remains unvalidated.
- Real GitHub experiments used a public lab PR with the ruleset active and required CI/preflight checks. The negative preflight and Evidence Gate correctly returned BLOCK. A non-authorizing check was published and changed from success to failure on the same SHA. The PR remained blocked; no merge was attempted, the separate causal effect of each requirement was not isolated, and no genuine positive human authorization was revoked.
- RC.6 local builder results are recorded under `examples/rc6/qualification.json`. Historical corpus replay remains byte-for-byte equivalent in its report; new integrated executor and journal controls do not grant merge authority.

## Publication gates

See [public release qualification](public-release.md). RC.6 results above are maintainer reports, not fresh 1.0.0 builder runs. No live merge, independent human approval or actual authorization revocation was established. No new remote writes were performed by the public-package builder.
