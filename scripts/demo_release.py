"""Generate signed demo bundles and compare two policies. Run from repo root."""
import argparse, json
from pathlib import Path
from intent_merge.runner import run, write_json
from intent_merge.bundle import keygen, pack, verify
from intent_merge.replay import replay

p=argparse.ArgumentParser(); p.add_argument('--out',type=Path,required=True); a=p.parse_args()
root=a.out.resolve(); root.mkdir(parents=True,exist_ok=False)
private=root/'demo-signer.pem'; public=root/'demo-signer.pub'; keygen(private,public)
bundles=[]
try:
    for scenario in ('happy','missing-approval','intent-drift','stale-approval','property-regression','stale-eval','stale-base','scope-violation'):
        output=root/'runs'/scenario; run(scenario,output,Path('examples/spec.toml'),Path('examples/policy.toml'))
        bundle=root/'bundles'/scenario; pack(output,bundle,private); verify(bundle,public); bundles.append(bundle)
    report=replay(bundles,public,Path('examples/policy-proposed.toml')); write_json(root/'replay.json',report)
    print(json.dumps(report['transitions'],indent=2))
finally:
    private.unlink(missing_ok=True) # ephemeral demo signer, never distribute a private key
