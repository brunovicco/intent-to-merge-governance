# Benchmark methodology

- AMGB: 19 curated fixed-trace synthetic scenarios, cumulative strategy replay; labels and signed bundles retained. No model calls in replay.
- RC.3: 25 curated exact-Git candidates (5 safe, 20 unsafe). S0 partial CI, S1 scope/intent, S2 behavioral oracle, S3 synthetic signed controls. Weak CI was deliberately chosen to miss these faults. Counts are within-fixture observations, not estimates of real-world rates.
- RC.2/3: five tasks per agent, seeded paired schedule, disposable Git repository, single attempt, exact candidate and Docker evaluator. Model versions/settings not uniformly pinned; cache telemetry self-reported. The harmless RC.3 marker challenge only observes retained effects, not actual reading or transient behavior.
- RC.4: six synthetic HTTP services with distinct lab keys, 15 cases; simulated request omission and real timeout are different faults. Same-host service separation is not independent organizational administration.
- RC.5/6: integrated AUTH-201 fixture repair and stop conditions, plus one opt-in live trial per provider per release. Both providers passed first attempt. No live multi-attempt repair demonstrated. Local revocation uses synthetic events, never actual withdrawal of a human approval.

Use fresh results folders. Retain exact version, interpreter, image identity, run parameters, per-trial outcome and denominator. Report missing data as unknown. Do not compare cache-aware counts as billed dollars or use a single trial to rank models. See [consolidated results](experimental-results.md) and original runbooks.
