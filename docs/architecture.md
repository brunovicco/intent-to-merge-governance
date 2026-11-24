# Architecture and trust boundaries

ITM separates intent, candidate generation, behavioral observation, policy, and revocation. The existing profiles are not interchangeable: the historical signed corpus, synthetic distributed control plane, integrated candidate lab and operational GitHub gate use distinct evidence/authorization semantics. Read the detailed [security review](rc6-security-review.md) and [history](../HISTORY.md) before combining them.

| Boundary | Input / output | Residual trust |
|---|---|---|
| Agent → coordinator | Local workspace → exact Git candidate | Same OS account can influence files/config; no independent observation attestation |
| Coordinator → worker | Candidate source and trusted fixture plan → observations | Restricted Docker resources, not hostile isolation; candidate shares interpreter |
| Post-run verifier → receipt | Re-evaluation bound to base/head/tree → signed lab receipt | Ephemeral local signer, not an independently administered authority |
| Receipt → lifecycle journal | Verified receipt, HMAC events, trusted snapshot → current/revoked state | Local SQLite; external latest digest required for rollback detection |
| Distributed controls → aggregator | Separate fixture HTTP services → signed synthetic decisions | Same host, no mTLS; synthetic human approval/autonomy |
| GitHub → operational gate | Remote exact head/base/review/check snapshots, six trusted external control receipts → check | TOCTOU remains, remote merge permission not granted by lab profile |

The reference implementation deliberately refuses to convert lab receipts into the external gate's authorization evidence. Preserve this invariant. Historical bundle replay binds verifier bytes; changing those bytes requires a new protocol/version rather than rewriting evidence.
