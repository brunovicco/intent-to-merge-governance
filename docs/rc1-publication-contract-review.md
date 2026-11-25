# RC review remediation: diagnostic publication and configuration failures

Installation authentication rejects missing, empty, non-string, oversized or whitespace/control-containing token responses before constructing the client. It never falls back to `ITM_GITHUB_TOKEN`. Token syntax is intentionally opaque; the token endpoint and subsequent API responses remain the trust boundary.

Direct `github-preflight --publish` requires the expected installation App identity on the client. A successful response must match the positive check ID, App ID, check name, head SHA, status, conclusion and external ID. Mismatched or lost responses emit `NOT_CONFIRMED` with non-secret correlation fields; do not blindly retry. `RESPONSE_MATCHED` means the create response matched, not independently observed current remote state. Direct publication remains diagnostic, non-journaled and non-authorizing. Use the journaled worker for recoverable automation. A process crash can lose the diagnostic correlation; no remote atomic authorization or automatic revocation is established.

`demo` emits the original structured configuration rejection and exits 2 on `INVALID_CONFIGURATION`. Ordinary completed synthetic BLOCK decisions remain successful executions (exit 0). Infrastructure errors exit 1. No change to historical evidence or dependency lock.

The existing B404 import-only and B608 fixed SQL findings have unchanged call-site text; only source pins/line location are updated. Fresh scans and independent qualification remain required.
