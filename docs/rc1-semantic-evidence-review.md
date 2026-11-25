# RC review remediation 03 — semantic evidence consistency

The current challenge-registry-backed PAY-104 profile reconciles the decision with the recorded candidate, checkpoint scope, configuration, approval event, history and terminal result. The runner's audit is shared by pinned historical audit and DSSE bundle packing/verification. A valid signature on contradictory records is insufficient. The checks are deliberately single-file: the auditor rejects checkpoint inventories outside its observed `app/payments.py` fixture. Earlier evidence profiles retain their historical replay semantics; no historic artifacts are rewritten.

Regression tests create fresh synthetic records, recompute the ledger chain, graph, manifest and anchor, and in one case sign a new DSSE envelope. These tests distinguish internal semantic consistency from byte integrity. The new checks do not independently reconstruct Git objects, attest real refs or externally establish the provenance of observations. No live authority is granted. External pins and bundle signatures are still required as appropriate to the selected audit profile.

Re-run locked tests, AMGB replay and scanners before publication. Previous Bandit call-site reviews in runner.py were retained only after confirming their exact line hashes are unchanged; fresh scanner results are required.
