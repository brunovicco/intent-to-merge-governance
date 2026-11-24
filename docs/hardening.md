# v0.10 — Operational hardening

This release narrows the trust boundary. It is still a reference implementation, not an atomic remote merge controller or a general-purpose secure sandbox.

## Independent control evidence

The `itm-ops worker` CLI now requires `--receipts` and `--control-trust` in addition to the original aggregate assertion directory and verifier public key. The legacy Python gate remains available for historical fixture replay only. Do not deploy it as a live gate.

Each PR/head file `<pr>-<head>.json` in the receipt directory is a JSON array of six envelopes. Each envelope contains `statement`, `artifact`, `signature`. The trusted control services own separate Ed25519 keys. The externally provisioned trust file maps exactly `intent`, `provenance`, `verification`, `convergence`, `authorization`, `operational_autonomy` to lowercase raw Ed25519 public keys (64 hex digits). The aggregate verifier key must be distinct. Store keys, trust and evidence outside agent workspaces.

The statement has `profile: external-control-v1`, `control`, `repository`, `pr`, `head`, `base`, `policy_digest`, `issued_at`, `expires_at`, `artifact_digest`, `passed`. The signature is base64 of Ed25519 over `b'ITM-control-receipt-v1\0' + canonical(statement)`. `artifact_digest` is SHA-256 of canonical artifact JSON. The aggregate assertion must reference `digest({control: digest(envelope)})`. All bindings and both expiry windows must match. Missing, duplicate, tampered, expired or incorrectly signed receipts fail closed. `canonical` and `digest` are defined in `intent_merge.core`.

This authenticates and binds the supplied artifacts; it does not prove the truth of arbitrary observations or infer that separately keyed services are operationally independent. External control implementations remain necessary. There is no bundled service that signs fabricated successful live assertions.

## Exact Git candidate verification

```sh
itm-ops verify-candidate --repo /trusted/checkout.git --base BASE_SHA --head HEAD_SHA \
  --spec /trusted/spec.toml --backend docker
```

This is a read-only verification of the PAY-104 demonstration contract from a trusted bare clone, against exact commit objects. It recomputes scope, AST invariants, 37 behavioral checks, coverage and mutation adequacy. Local execution explicitly requires `--trusted-fixture`; use it only for the project's synthetic sources. Docker absence is an error, not a fallback. Results never confer merge authority or automatically mint a live control receipt. The container limits exposure but is not a hostile-code isolation guarantee. Candidate code can interfere with observations within its process; independent production verification remains outstanding.

## Revocation

Configure a periodic invocation of the following command in a trusted runner, and run it after relevant webhooks and policy/key changes. Supply the same arguments as the strict worker, including `--receipts`, `--control-trust`, and `--verifier-key`. Without `--publish` the sweep only reports proposed revocations.

```sh
itm-ops sweep --db /trusted/jobs.sqlite --policy /trusted/github-policy.toml \
  --app-id APP_ID --installation INSTALLATION_ID --app-key /trusted/app.pem \
  --assertions /trusted/assertions --verifier-key /trusted/verifier.pub \
  --receipts /trusted/receipts --control-trust /trusted/control-trust.json --publish
```

For journal-known successes, the sweep checks remote identity, refreshes preflight and independent receipts, and revokes obsolete success using a PATCH to the existing check. A lost response is reported as uncertain; rerun the sweep to inspect current remote state. A missing remote record or mismatch is never reported as successful revocation. Uncertain states exit nonzero. Reconcile uncertain publication jobs before sweeping. Legacy successes are revoked rather than grandfathered. The sweep never grants success.

GitHub check conclusions are attached to a commit, not an atomic PR authorization transaction. A periodic sweep can race with a merge, a check can be shared by PRs with the same head, events can be missed and a service outage can leave a previously successful check in GitHub. Therefore this is an additional control, not a sole merge gate. Use strict native branch protections, expected check source App, stale review dismissal, no bypass, and a merge queue with separately verified merge-group commits before enabling automation. The merge-group event and final atomic enforcement are not implemented here. See [GitHub required checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) and [merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).

## Durable local Change Sets

```sh
itm-ops changeset-recover --db /trusted/changeset.sqlite --config /trusted/config.json \
  --plan /trusted/plan.json --approvals /trusted/approvals.json \
  --repos /trusted/repos.json --executor-key /trusted/executor.pem
```

`repos.json` maps the component names to explicitly trusted local bare repositories. The original signed exact-plan approvals are mandatory. The first invocation starts a local execution, and subsequent invocations with the same inputs reopen the journal. The journal binds the complete configuration, plan, approvals and resolved repo paths. An executor-signed state is durably persisted before each CAS and after acknowledgement. Recovery distinguishes the expected before and after ref vectors; unexplained drift stops for manual intervention. Add `--compensate` to reverse completed updates during an interrupted execution. Terminal states are historical observations, not refreshed snapshots. The journal is trusted local storage; signatures detect unauthorized modification but cannot prevent replay of an older valid snapshot. Protect the database, locks and key; do not use a shared filesystem with unreliable locking. External writers can still race with the local coordinator. No atomic distributed transaction or remote rollback is provided.

## Validation

Run `python -m unittest discover -s tests -v`. Docker fixture tests are additionally defined in CI. The hardening tests use synthetic Git repositories, mock GitHub APIs and locally generated keys. No real GitHub credentials or vendor CLI accounts are required for those tests. The project has no automatic remote merge endpoint.
