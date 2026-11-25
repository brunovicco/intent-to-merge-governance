# RC1 follow-up: strict publication freshness

**HOLD — not approved for publication.** This follow-up is based on the previously qualified RC tree `e99e6626e73374dd60ca5075cbfe268cba93e1a3`. It addresses finding 1 only. Changeset compensation and anchored-audit semantic consistency remain release blockers.

The journaled strict worker now rechecks the earliest evidence expiry and the ordered evaluation timestamps after its write-ahead journal commit and immediately before starting a success POST. The `now` override is retained for trusted deterministic tests. Missing or elapsed expiry and a regressed clock deny the attempt. A known pre-request denial records `BLOCKED_BEFORE_PUBLICATION`, clears the unused external ID and records `publication_attempted: false`; a new delivery is needed to evaluate again. It neither sends a failure check nor revokes any previous remote success. Ambiguous actual requests retain the existing UNCERTAIN/reconciliation contract. This does not make network completion, remote revocation or merge atomic; expiry may still occur in transit.

Regression tests advance the clock after the second gate refresh and after the PUBLISHING journal commit, test the last valid second of the assertion lifetime, and reject clock regression. Three tests failed against the original RC, all four pass after the fix. The legacy synthetic operational study remains unchanged.

The existing B608 review of the journal transition's fixed SQL was re-pinned only after checking that the exact line and its allowlisted field construction are unchanged. The previous report digest remains historical. Fresh actual scanner results are required before release.
