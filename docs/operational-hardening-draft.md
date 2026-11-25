# Operational hardening (development increment)

The `intent-merge` and `itm-ops` command dispatch boundaries emit a redacted
JSON error on stderr and exit nonzero for execution exceptions. These errors
never grant authority. `NOT_CONFIRMED` is conservative for a request with
`--publish`: a remote check may already have been written. Inspect and reconcile
remote state; never blindly retry. Argument parsing and process interruption
remain separate; this does not create a persistent error receipt for every
failure or atomically revoke previously published checks.

`github-preflight` without `--publish` uses `ITM_GITHUB_TOKEN` for reading.
Publishing now requires `--app-id`, `--installation`, and `--app-key` together;
the existing installation client requests repository-scoped contents/read,
pull_requests/read, and checks/write permissions. Keep the key outside the
candidate workspace. Use only an isolated lab. This is a CLI authentication
contract, not a change to the underlying GitHub API or a guarantee of merge
authority. Existing scripts calling the Python API directly retain their own
credential responsibilities. This is a breaking change to the old CLI publish
invocation; do not silently migrate existing deployments.

CI exercises the locked minimal installation and then the telemetry-enabled
installation. Only the telemetry-specific test may skip when the optional
package is absent; `ITM_REQUIRE_TELEMETRY=1` requires it to execute. Explicitly
requesting console telemetry without the SDK is an error, not a silent downgrade.

The previous Bandit review is not a new scanner qualification. Run the pinned
security pipeline and review new, missing, and changed findings against the
exact source. Do not rebind findings solely to make the baseline pass. All
results remain experimental; production_ready and merge_authority are false.

The maintainer's increment-6 qualification log reports 313 tests discovered
in both environments (one expected skip without telemetry, none with telemetry),
an identical historical AMGB replay, and a dependency audit with no known
vulnerabilities reported. The Bandit summary reports 57 reviewed findings and
one new B404 LOW/HIGH-confidence finding at cli_errors.py:4. The import of
subprocess is used only to classify SubprocessError; no process is launched
by that module. The exact import and source hash are added to the reviewed
baseline without suppressing B404 or changing earlier dispositions. The
historical source_report_sha256 is intentionally retained. A fresh scan of
the updated tree and review of its actual output are still required. The four
raw Gitleaks findings in the maintainer log have not been individually verified
in this review. This is not publication approval.
