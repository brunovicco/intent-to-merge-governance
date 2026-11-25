# Changeset scope hardening (development increment 4)

New synthetic multi-repository runs require configuration version 2 and an explicit `path_semantics: segment-v2`. The shared path policy matches complete repository-relative paths. `*` and `?` match within one segment; `**` matches zero or more segments. Invalid paths cannot satisfy the allowlist. Invalid patterns are rejected before collecting a new plan. This is not gitignore or CODEOWNERS syntax.

The configuration digest binds the semantics to each plan and approval. Plans and receipts now use version 2 for new runs. Their existing signature framing (`ITM-CHANGESET-V1`) is unchanged; signed plan and configuration digests bind the new version. Existing v1 artifacts remain unchanged: offline receipt verification uses the original historical matcher and the supplied trusted configuration digest. New plan generation, approval and local execution reject v1. Historical verification remains non-authorizing. Do not relabel or re-sign legacy artifacts as v2; review patterns and generate a new plan and approvals.

The local fixture coordinator still assumes trusted repositories, OS identity, Git executable and configuration. It does not provide distributed transactions, real remote enforcement, hostile-code isolation, or independently administered trust. The changeset approval protocol is distinct from the local single-candidate Approval Envelope v2 and challenge registry; this increment does not add freshness or single-use enforcement to changeset approvals.

The test that deliberately modifies the registry schema now explicitly closes its SQLite connection; Python's connection context manager handles transactions but does not close the connection. Other SQLite consumers have not been exhaustively leak-tested.
