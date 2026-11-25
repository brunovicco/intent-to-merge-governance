# Trust profiles (development increment)

`intent-merge audit` is explicitly a synthetic historical audit. Its output
includes `trust_profile: synthetic-historical-v1`, `current_authorization: false`,
`organizational_authority_verified: false` and `merge_authority: false`. The
`merged` field is a recorded local fixture outcome, not a permission.

`intent-merge audit-anchored` requires the exact SHA-256 pins of the anchor and
public approval trust store, obtained and retained through a trusted channel
outside the candidate's control. It checks both pinned inputs, strict public
Ed25519 key inventory, the manifest and every artifact, then replays a temporary
copy of the checked bytes. Only segment-v2, approval-envelope-v2 and challenge
registry evidence is accepted. Legacy bundles keep their historical replay path.

```sh
intent-merge audit-anchored --out results/example \
  --anchor /trusted/anchor.json --trust /trusted/approval-trust.json \
  --expected-anchor-sha256 "$TRUSTED_ANCHOR_SHA256" \
  --expected-trust-sha256 "$TRUSTED_KEYS_SHA256"
```

The paths and variables are illustrative. Obtain the pins independently; hashing
an untrusted run's own anchor and key file and immediately passing those hashes
back does **not** establish independent trust. A different directory is not a
privilege boundary. A hash matches bytes, not the operator's identity, key
custody, or organizational role. This mode still verifies a synthetic lab profile;
it neither issues approvals nor consumes live challenges. Its result explicitly
marks current authorization, organizational authority and merge authority false.

The temporary snapshot reduces accidental source changes between integrity checks
and replay; it is not a same-user or hostile-filesystem sandbox. The input must
be a completed stable run and the verifier must execute outside the agent trust
zone. No independent organizational signer infrastructure, current revocation
check or remote enforcement is established. The signed bundle and historical
AMGB formats are unchanged.
