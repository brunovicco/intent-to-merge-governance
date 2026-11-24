# Sample excerpts

Recorded v0.3 local fixture evidence excerpts. Not a complete auditable bundle; generate a fresh run with the CLI.

## v0.4 signed demonstration

`policy-replay-v04.json` records the eight-scenario study executed for this release. `signed-demo-bundle/` is one complete portable happy-path bundle. `demo-signer.pub` is a public key distributed here for demonstration only, not an organizational trust root. Its private counterpart is not shipped.

```bash
uv run intent-merge verify-bundle --bundle examples/sample-evidence/signed-demo-bundle --public-key examples/sample-evidence/demo-signer.pub
```
