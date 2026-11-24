# RC.4 — distributed synthetic control plane

This release adds a **lab-only** control plane. It does not replace or weaken the existing GitHub preflight or strict evidence gate. The lab uses separate cryptographic domains, a synthetic profile and candidate content digests (not Git commit SHAs). The six HTTP services accept only built-in AUTH-201 fixture IDs and a nonce. They derive observations independently from trusted fixture code; only verification executes the built-in candidate. Authorization is a synthetic review record, provenance is a synthetic trace, and autonomy is a fixture policy. No service accepts arbitrary source, caller-supplied pass flags or live credentials. The coordinator pins seven distinct public keys, checks the complete inventory, nonce, candidate/base/fixture/policy binding, signature, digest and freshness; any missing, denied or invalid receipt blocks. The aggregate signs both ALLOW and BLOCK decisions. Transport timing and error labels are diagnostic metadata, not signed evidence. Historical replay does not consult the revocation journal; current decision in replay refers only to cryptographic validity and time, not operational authority.

## Local reproduction

```sh
uv sync --extra telemetry
uv run python -m unittest discover -s tests -v
uv run python scripts/control_plane.py demo --out results/rc4-local
```

The demo launches six separate loopback HTTP processes with ephemeral keys, executes 15 cases and tears down the services. It writes public trust, signed reports, JSONL and a local SQLite lifecycle journal. The console prints the trust digest; retain this separately from the report for offline verification. Never publish the private keys. The `unavailable` case simulates an unavailable endpoint by skipping a request; `delayed` exercises a real HTTP timeout. Wrong identity and duplicate receipts are injected in the coordinator transport; unit tests additionally validate an otherwise correctly bound statement signed with the wrong key. Local processes run under the same OS user, so key directories are not an OS-level trust boundary.

```sh
uv run python scripts/control_plane.py verify \
  --report results/rc4-local/report.json \
  --trust results/rc4-local/trust.json \
  --expected-trust-digest '<digest printed by demo>'
```

Historical signatures can be replayed after expiry; expired ALLOW is no longer current. For the bundled example, the trust digest is `1d75c466bb30be3ef69e942cd2f064fa41cffbcc090363e27058fb6d22308fe1` (a demonstration anchor, not a production trust root).

## Compose reproduction (not validated in authoring environment)

Run on a trusted disposable host, without real GitHub App or agent credentials. Docker Compose mounts each service's own key read-only, runs non-root with dropped capabilities, no published ports, internal network, read-only filesystem and resource limits. The coordinator receives only its own signing key and public inventory. The image build uses network access to install dependencies; runtime services are internal. Container isolation is not proof of hostile-code safety or organizational independence. Do not expose the HTTP endpoints; they have no TLS or client authentication.

```sh
export ITM_UID=$(id -u) ITM_GID=$(id -g)
export ITM_LAB_KEYS="$PWD/.itm-lab-keys"
export ITM_LAB_RESULTS="$PWD/results/rc4-compose"
mkdir -p "$ITM_LAB_RESULTS"
uv run python scripts/control_plane.py init --keys "$ITM_LAB_KEYS"
docker compose -f compose.control-plane.yaml --profile run config --quiet
docker compose -f compose.control-plane.yaml build
docker compose -f compose.control-plane.yaml up -d --wait
docker compose -f compose.control-plane.yaml run --rm coordinator
docker compose -f compose.control-plane.yaml down
```

The key directory must not already exist; use a new directory for each run and do not reuse production keys. The coordinator output directory must not already exist. Read `results/rc4-compose/compose-study/report.json` and `report.html`. If startup fails, inspect `docker compose -f compose.control-plane.yaml ps` and `logs`; no automatic fallback to local execution is performed.

## Other RC.4 additions and limits

- `budget.py`: provider-aware observed usage normalization and deterministic admission state machine. Stops on missing usage, scope failure, repeat tree, or exceeded observed limits; cannot impose a provider-side hard cap or cancel in-flight calls. Not yet integrated with real multi-attempt agent execution. No inferred billing values.
- `LabRevocations`: synthetic local SQLite lifecycle; register, revoke, expire, restart, no restoration of a revoked report. No authenticated event ingress or remote publication in this lab. Existing `hardening.sweep` remains the live check reconciliation path; true authorization revocation is still unqualified.
- `merge_group.py`: isolated HMAC-verified payload parser and candidate binding; returns `BLOCK_PENDING_FRESH_GROUP_VERIFICATION`. Not wired to the PR webhook worker, does not fetch queue commits or publish checks. No real merge queue validation.
- No production promotion: independent human approval, independent operational services, real authorization revocation, hostile candidate isolation, merge queue verification, and live convergence remain open. The GitHub lab ruleset and remote PR were not changed.
