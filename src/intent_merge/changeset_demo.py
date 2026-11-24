"""Reproducible local Git change-set experiment. Never touches external repositories."""
from __future__ import annotations
import json, subprocess, html
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .core import digest
from .changeset import plan, approve, execute, verify_receipt, git, ref

SCENARIOS=('compatible','incompatible-final','incompatible-prefix','partial-failure','compensation-conflict','stale-plan','missing-approval','scope-violation')


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


def config_keys():
    keys={n:Ed25519PrivateKey.generate() for n in ('payments','checkout','portal','executor')}
    config={'version':1,'profile':'local-synthetic','intent_id':'payment-contract-v2','executor_key':public(keys['executor']),'components':{n:{'depends_on':d,'allowed_paths':['contract.json','app.txt'],'reviewer_key':public(keys[n])} for n,d in [('payments',[]),('checkout',['payments']),('portal',['checkout'])]}}
    return config,keys


def command(*args,cwd=None):
    return subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,check=True,capture_output=True,timeout=15).stdout.decode().strip()


def write(path,data):
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def fixture(root,scenario):
    root.mkdir(parents=True,exist_ok=False); repos={}
    base={'payments':{'provides':['v1'],'requires':{}},'checkout':{'provides':['v1'],'requires':{'payments':'v1'}},'portal':{'provides':['v1'],'requires':{'checkout':'v1'}}}
    head={'payments':{'provides':['v1','v2'],'requires':{}},'checkout':{'provides':['v1','v2'],'requires':{'payments':'v2'}},'portal':{'provides':['v1','v2'],'requires':{'checkout':'v2'}}}
    if scenario=='incompatible-final': head['portal']['requires']['checkout']='v3'
    if scenario=='incompatible-prefix': head['payments']['provides']=['v2']
    for name in base:
        work=root/(name+'-work'); work.mkdir(); command('init','-b','main',cwd=work); command('config','user.name','ITM fixture',cwd=work); command('config','user.email','fixture@example.invalid',cwd=work)
        write(work/'contract.json',base[name]); (work/'app.txt').write_text('baseline\n'); command('add','.','--',cwd=work); command('commit','-m','Baseline',cwd=work)
        command('checkout','-b','candidate',cwd=work); write(work/'contract.json',head[name]); (work/'app.txt').write_text('candidate\n')
        if scenario=='scope-violation' and name=='portal': (work/'policy.toml').write_text('unexpected = true\n')
        command('add','.','--',cwd=work); command('commit','-m','Candidate',cwd=work)
        bare=root/(name+'.git'); command('clone','--bare',str(work.resolve()),str(bare.resolve())); repos[name]=bare
    return repos


def demo_one(root,scenario,config,keys):
    root.mkdir(parents=True,exist_ok=False); repos=fixture(root/'repositories',scenario)
    p=plan(config,repos); write(root/'plan.json',p)
    approvals=[approve(config,p,n,keys[n]) for n in p['order']]
    if scenario=='missing-approval': approvals.pop()
    if scenario=='stale-plan':
        c=p['components']['portal']; git(repos['portal'],'update-ref','refs/heads/main',c['head'],c['base'])
    def fault(stage,n,rs):
        if scenario in ('partial-failure','compensation-conflict') and stage=='before_merge' and n=='checkout': raise ValueError('synthetic merge failure')
        if scenario=='compensation-conflict' and stage=='before_compensate' and n=='payments':
            # Simulate external movement to a distinct commit (the base) in another repo's ref.
            c=p['components']['portal']; git(rs['portal'],'update-ref','refs/heads/main',c['head'],c['base'])
    if not p['eligible']:
        return {'scenario':scenario,'status':'BLOCKED','issues':p['issues'],'final_compatible':not p['stages'][-1]['violations'],'prefix_compatible':all(not s['violations'] for s in p['stages']),'receipt_verified':False,'writes_by_coordinator':0}
    try: receipt=execute(config,p,approvals,repos,keys['executor'],fault=fault)
    except ValueError as exc:
        if scenario not in ('stale-plan','missing-approval'): raise
        return {'scenario':scenario,'status':'BLOCKED','issues':[str(exc)],'final_compatible':True,'prefix_compatible':True,'receipt_verified':False,'writes_by_coordinator':0}
    write(root/'receipt.json',receipt); check=verify_receipt(config,receipt,digest(config))
    return {'scenario':scenario,'status':check['status'],'issues':[],'final_compatible':True,'prefix_compatible':True,'receipt_verified':True,'writes_by_coordinator':sum(e['kind'] in ('merged','compensated') for e in receipt['events'])}


def study(out):
    out=Path(out); out.mkdir(parents=True,exist_ok=False); config,keys=config_keys(); write(out/'config.json',config); write(out/'anchor.json',{'config_digest':digest(config)})
    rows=[demo_one(out/s,s,config,keys) for s in SCENARIOS]
    report={'profile':'local-synthetic','merge_authority':False,'config_digest':digest(config),'scenarios':rows}
    write(out/'report.json',report)
    h=lambda v:html.escape(str(v))
    table=''.join('<tr>'+''.join('<td>'+h(x)+'</td>' for x in (r['scenario'],r['status'],r['final_compatible'],r['prefix_compatible'],r['writes_by_coordinator'],r['receipt_verified'],'; '.join(r['issues'])))+'</tr>' for r in rows)
    (out/'report.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ITM Change Set Study</title><style>body{font:16px system-ui;background:#f6f8fa;color:#172b35;max-width:1120px;margin:40px auto;padding:0 20px}h1{font-size:32px}table{border-collapse:collapse;width:100%;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #dbe4e8}th{background:#e1efed}code{color:#086f64}.scroll{overflow:auto}</style><h1>Intent-to-Merge · Multi-repository governance</h1><p>One intent, three local Git repositories. Provider-first compatibility checks, exact-plan approvals and compensating ref updates.</p><p><code>payments → checkout → portal</code></p><div class="scroll"><table><thead><tr><th>Scenario</th><th>Outcome</th><th>Final compatible</th><th>All prefixes compatible</th><th>Coordinator writes</th><th>Signed receipt verified</th><th>Blocking issues</th></tr></thead><tbody>'''+table+'''</tbody></table></div><p>Compatibility columns describe the planned rollout, not the actual state after an external conflict. Local synthetic fixtures only; no remote authority, atomic cross-repository transaction, production rollback or behavioral contract proof.</p></html>''')
    return report
