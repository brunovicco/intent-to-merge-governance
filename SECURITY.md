# Security policy

Intent-to-Merge Governance is an experimental research/reference implementation. No supported production deployment, safety certification, or authority to merge is claimed. Never provide production credentials or sensitive data to its demos. Run real agent experiments only in a disposable separate OS identity or VM with no access to privileged credentials, control-plane keys or sensitive files. Docker here is a resource-limited lab execution adapter, not a proven hostile-code sandbox.

Report suspected vulnerabilities privately to the repository maintainer using a private security advisory if enabled. Do not post credentials, raw agent logs, exploit details or sensitive repository data in public issues. A reporting contact and supported-version policy should be established before public release.

See [security review and threat model](docs/rc6-security-review.md) for the scoped controls, residual risks and production qualification gates.

For the 1.0.0 public source candidate, the maintainer must enable and verify a private vulnerability-reporting channel before publication. The package does not configure one automatically. No security response SLA is promised.
