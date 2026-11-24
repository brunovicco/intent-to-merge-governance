import argparse, json
from pathlib import Path
from .runner import run, audit, SCENARIOS
from .checkpoints import normalize_session
from .bundle import keygen, pack, verify
from .replay import replay
from .github import GitHub, policy_from, preflight
from .agent_import import import_agent
from .explorer import render
from .benchmark import generate, evaluate_corpus, write_reports
from .autonomy import replay as replay_operations, gate as autonomy_gate
from .operations_demo import study
from .changeset_demo import study as changeset_study
from .changeset import verify_receipt

def main():
    p = argparse.ArgumentParser(description='Intent-to-Merge Governance reference harness')
    sub = p.add_subparsers(dest='cmd',required=True)
    d = sub.add_parser('demo'); d.add_argument('--scenario',choices=SCENARIOS,default='happy'); d.add_argument('--out',type=Path,required=True); d.add_argument('--spec',type=Path,default=Path('examples/spec.toml')); d.add_argument('--policy',type=Path,default=Path('examples/policy.toml')); d.add_argument('--executor',choices=['local','docker'],default='local'); d.add_argument('--image',default='python:3.11-slim')
    a = sub.add_parser('audit'); a.add_argument('--out',type=Path,required=True); a.add_argument('--anchor',type=Path,required=True); a.add_argument('--trust',type=Path,required=True)
    n = sub.add_parser('normalize-session', help='Normalize a portable, self-reported session export'); n.add_argument('--input',type=Path,required=True)
    g = sub.add_parser('inspect', help='Inspect recorded intent evidence (not an audit)'); g.add_argument('--out',type=Path,required=True); g.add_argument('--requirement')
    k=sub.add_parser('keygen',help='Generate an external evidence signing key'); k.add_argument('--private-key',type=Path,required=True); k.add_argument('--public-key',type=Path,required=True)
    b=sub.add_parser('bundle',help='Create a signed portable evidence bundle'); b.add_argument('--out',type=Path,required=True); b.add_argument('--bundle',type=Path,required=True); b.add_argument('--private-key',type=Path,required=True)
    v=sub.add_parser('verify-bundle',help='Verify offline with externally trusted signer'); v.add_argument('--bundle',type=Path,required=True); v.add_argument('--public-key',type=Path,required=True)
    r=sub.add_parser('policy-replay',help='Counterfactual decision-only replay'); r.add_argument('--bundle',type=Path,action='append',required=True); r.add_argument('--public-key',type=Path,required=True); r.add_argument('--policy',type=Path,required=True)
    gh=sub.add_parser('github-preflight',help='Inspect a live PR and optionally publish a preflight check'); gh.add_argument('--repo',required=True); gh.add_argument('--pr',type=int,required=True); gh.add_argument('--policy',type=Path,required=True); gh.add_argument('--publish',action='store_true')
    ag=sub.add_parser('import-agent',help='Normalize native agent JSONL stream'); ag.add_argument('--provider',choices=['claude','codex'],required=True); ag.add_argument('--input',type=Path,required=True); ag.add_argument('--head'); ag.add_argument('--agent-id',default='coding-agent')
    ex=sub.add_parser('explorer',help='Export a verified offline HTML dashboard'); ex.add_argument('--bundle',type=Path,action='append',required=True); ex.add_argument('--public-key',type=Path,required=True); ex.add_argument('--output',type=Path,required=True); ex.add_argument('--pr-report',type=Path,action='append',default=[]); ex.add_argument('--session',type=Path,action='append',default=[])
    bm=sub.add_parser('benchmark',help='Generate signed synthetic AMGB traces and a paired ablation report'); bm.add_argument('--out',type=Path,required=True); bm.add_argument('--spec',type=Path,default=Path('examples/spec.toml')); bm.add_argument('--policy',type=Path,default=Path('examples/policy.toml')); bm.add_argument('--workers',type=int,default=4)
    br=sub.add_parser('benchmark-replay',help='Reproduce AMGB from signed traces without running candidates'); br.add_argument('--bundles',type=Path,required=True); br.add_argument('--public-key',type=Path,required=True); br.add_argument('--output',type=Path,required=True)
    od=sub.add_parser('autonomy-demo',help='Run synthetic incident-to-eval recovery study'); od.add_argument('--bundles',type=Path,default=Path('examples/amgb-v1/bundles')); od.add_argument('--public-key',type=Path,default=Path('examples/amgb-v1/signer.pub')); od.add_argument('--out',type=Path,required=True)
    op=sub.add_parser('autonomy-replay',help='Replay signed operational events using a pinned config and latest external root'); op.add_argument('--config',type=Path,required=True); op.add_argument('--events',type=Path,required=True); op.add_argument('--expected-root',required=True)
    og=sub.add_parser('autonomy-gate',help='Evaluate extra eligibility gate on a signed synthetic bundle'); og.add_argument('--config',type=Path,required=True); og.add_argument('--events',type=Path,required=True); og.add_argument('--expected-root',required=True); og.add_argument('--bundle',type=Path,required=True); og.add_argument('--public-key',type=Path,required=True)
    cs=sub.add_parser('changeset-demo',help='Run local multi-repository contract and compensation study'); cs.add_argument('--out',type=Path,required=True)
    cv=sub.add_parser('changeset-verify',help='Verify signed local change-set receipt offline'); cv.add_argument('--config',type=Path,required=True); cv.add_argument('--receipt',type=Path,required=True); cv.add_argument('--expected-config-digest',required=True)
    args = p.parse_args()
    try:
        if args.cmd=='demo': result = run(args.scenario,args.out,args.spec,args.policy,args.executor,args.image)
        elif args.cmd=='audit': result = audit(args.out,args.anchor,args.trust)
        elif args.cmd=='normalize-session': result = normalize_session(json.loads(args.input.read_text()))
        elif args.cmd=='keygen': result=keygen(args.private_key,args.public_key)
        elif args.cmd=='bundle': result=pack(args.out,args.bundle,args.private_key)
        elif args.cmd=='verify-bundle': result=verify(args.bundle,args.public_key)
        elif args.cmd=='policy-replay': result=replay(args.bundle,args.public_key,args.policy)
        elif args.cmd=='github-preflight': result=preflight(GitHub(),args.repo,args.pr,policy_from(args.policy),publish=args.publish)
        elif args.cmd=='import-agent': result=import_agent(args.provider,args.input,args.agent_id,args.head)
        elif args.cmd=='explorer': result=render(args.bundle,args.public_key,args.output,pr_reports=args.pr_report,sessions=args.session)
        elif args.cmd=='changeset-demo': result=changeset_study(args.out)
        elif args.cmd=='changeset-verify': result=verify_receipt(json.loads(args.config.read_text()),json.loads(args.receipt.read_text()),args.expected_config_digest)
        elif args.cmd=='autonomy-demo': result=study(args.bundles,args.public_key,args.out)
        elif args.cmd=='autonomy-replay': result=replay_operations(json.loads(args.config.read_text()),json.loads(args.events.read_text()),args.expected_root).summary()
        elif args.cmd=='autonomy-gate': result=autonomy_gate(json.loads(args.config.read_text()),json.loads(args.events.read_text()),args.expected_root,args.bundle,args.public_key)
        elif args.cmd=='benchmark': result=generate(args.out,args.spec,args.policy,args.workers)
        elif args.cmd=='benchmark-replay':
            result=evaluate_corpus(args.bundles,args.public_key); args.output.mkdir(parents=True,exist_ok=False); write_reports(result,args.output)
        else:
            ev=args.out/'evidence'; report=json.loads((ev/'report.json').read_text()); coverage=report['requirement_coverage']
            if args.requirement:
                coverage=[r for r in coverage if r['id']==args.requirement]
                if not coverage: raise ValueError('unknown requirement')
            result={'verified_requirements':coverage,'drift':json.loads((ev/'intent-drift.json').read_text()),'decision':report['decision'],'note':'Recorded evidence; run audit for integrity verification.'}
        print(json.dumps(result,indent=2))
    except (ValueError, OSError, KeyError, TypeError) as e: p.exit(1,f'error: {e}\n')
if __name__ == '__main__': main()
