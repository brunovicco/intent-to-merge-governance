#!/usr/bin/env python3
"""Release-candidate validation, never a live authorization issuer.

All signing keys and simulated live-profile receipts stay in a temporary directory.
No GitHub client, credentials, or real agents are used by this local harness.
"""
import argparse, base64, copy, hashlib, hmac, html, json, shutil, subprocess, tempfile, tomllib
from functools import partial
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from intent_merge.evidence_profile import HISTORICAL_V1
from intent_merge import runner, bundle, autonomy, benchmark, changeset
from intent_merge.core import canonical, digest, load_config
from intent_merge.github import policy_from
from intent_merge.hardening import strict_gate, verify_payment_candidate, sweep, RECEIPT_DOMAIN
from intent_merge.operational import delivery, Journal, work_once, reconcile, DOMAIN, CONTROLS, NAME

ROOT = Path(__file__).resolve().parents[1]
NOW = 1900000000  # fixture clock, not current validity
APP = 789
REPO = 'OWNER/REPO'


def require(condition, msg):
    if not condition:
        raise RuntimeError(msg)


def read(path):
    return json.loads(Path(path).read_text())


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


class FixtureRemote:
    """In-memory GitHub API boundary. No network, no remote writes."""
    installation_app_id = APP
    installation_id = 1
    installation_repository = REPO

    def __init__(self, head, base):
        self.pr = {'head': {'sha': head, 'repo': {'full_name': REPO}},
                   'base': {'sha': base, 'ref': 'main', 'repo': {'full_name': REPO}},
                   'state': 'open', 'draft': False, 'changed_files': 1, 'user': {'id': 99}}
        self.reviews = [{'id': i, 'user': {'id': uid, 'type': 'User'}, 'state': 'APPROVED', 'commit_id': head}
                        for i, uid in [(1, 10001), (2, 10002)]]
        self.checks = [{'id': 3, 'name': 'trusted-ci', 'app': {'id': 12345}, 'head_sha': head,
                        'status': 'completed', 'conclusion': 'success'}]
        self.posts = 0
        self.lose_response = False

    def request(self, path, payload=None, *, method=None):
        if path == f'/repos/{REPO}/pulls/1' and payload is None:
            return copy.deepcopy(self.pr)
        if path == f'/repos/{REPO}/check-runs' and payload is not None:
            self.posts += 1
            row = {**payload, 'id': 100+self.posts, 'app': {'id': APP}}
            self.checks.append(row)
            if self.lose_response:
                raise ValueError('fixture response lost')
            return copy.deepcopy(row)
        if path.startswith(f'/repos/{REPO}/check-runs/'):
            row = next(c for c in self.checks if str(c['id']) == path.rsplit('/', 1)[-1])
            if method == 'PATCH': row.update(payload)
            return copy.deepcopy(row)
        raise ValueError('unexpected fixture API route')

    def pages(self, path, key=None):
        if path.endswith('/files'): return iter([{'filename':'app/payments.py','status':'modified'}])
        if path.endswith('/reviews'): return iter(copy.deepcopy(self.reviews))
        if '/check-runs?' in path: return iter(copy.deepcopy(self.checks))
        raise ValueError('unexpected fixture collection')


def simulate_gate(temp, local_report, verified, exact, operational, mode):
    """Bridge real *synthetic* observations into an isolated API contract test.

    The wire profile names intentionally match production schemas, but ephemeral
    keys never leave the temporary directory and the mock cannot make network calls.
    """
    temp.mkdir()
    policy = policy_from(ROOT/'examples/github-policy.toml')
    head, base = local_report['candidate'], local_report['base']
    bind = {'repository': REPO, 'pr': 1, 'head': head, 'base': base, 'policy_digest': digest(policy)}
    controls = {
        'intent': exact['intent']['passed'] and all(r['verified'] for r in exact['coverage']),
        'provenance': verified['checkpoint_contract'] == 'verified' and verified['candidate'] == head,
        'verification': exact['passed'],
        'convergence': local_report['termination'] == 'passed' and verified['convergence_replay'] == 'verified',
        'authorization': local_report['decision']['authorized'] and verified['policy_replay'] == 'verified',
        'operational_autonomy': operational['status'] == 'ELIGIBLE',
    }
    # Compact, concrete artifacts derived from the preceding steps, not free-form boolean fixtures.
    artifacts = {
        'intent': {'result': exact['intent'], 'coverage': exact['coverage']},
        'provenance': {'candidate': head, 'bundle_root': verified['ledger_root'], 'profile': verified['profile']},
        'verification': exact,
        'convergence': {'termination': local_report['termination'], 'history': local_report['history']},
        'authorization': {'decision': local_report['decision'], 'policy_replay': verified['policy_replay']},
        'operational_autonomy': operational,
    }
    keys = {c: Ed25519PrivateKey.generate() for c in CONTROLS}; agg = Ed25519PrivateKey.generate()
    trust = {c: public(k) for c,k in keys.items()}
    a=temp/'assertions'; r=temp/'receipts'; a.mkdir(); r.mkdir(); name=f'1-{head}.json'
    receipts=[]
    for c in sorted(CONTROLS):
        s={**bind,'control':c,'profile':'external-control-v1','issued_at':NOW-1,'expires_at':NOW+60,
           'passed':controls[c],'artifact_digest':digest(artifacts[c])}
        receipts.append({'statement':s,'artifact':artifacts[c],'signature':base64.b64encode(keys[c].sign(RECEIPT_DOMAIN+canonical(s))).decode()})
    root=digest({x['statement']['control']:digest(x) for x in receipts})
    s={**bind,'schema_version':1,'profile':'live-external-verifier','issued_at':NOW-1,'expires_at':NOW+60,
       'controls':controls,'evidence_digest':root}
    (a/name).write_text(json.dumps({'statement':s,'signature':base64.b64encode(agg.sign(DOMAIN+canonical(s))).decode()}))
    if mode=='tamper': receipts[0]['artifact']['unexpected']='altered'
    (r/name).write_text(json.dumps(receipts))
    api=FixtureRemote(head,base); api.lose_response=mode=='lost-response'
    if mode=='stale-review': api.reviews[-1]['commit_id']=base
    raw=canonical({'action':'opened','repository':{'full_name':REPO},'installation':{'id':1},'pull_request':{'number':1}})
    secret=b'rc1-test-secret-not-for-deployment!!'; signature='sha256='+hmac.new(secret,raw,hashlib.sha256).hexdigest()
    job=delivery(raw,signature,'pull_request','rc1-test',secret,REPO,1)
    gate=partial(strict_gate,receipt_dir=r,control_trust=trust)
    j=Journal(temp/'jobs.sqlite')
    try:
        j.enqueue(job); j.enqueue(job); require(len(j.list())==1,'dedup failed')
        try:
            result=work_once(j,api,policy,a,agg.public_key(),app_id=APP,now=NOW,publication_clock=lambda: NOW,publish=True,gate_fn=gate)
        except ValueError:
            require(mode=='lost-response' and j.get(job['id'])['state']=='UNCERTAIN','unexpected publication failure')
            j.close(); j=Journal(temp/'jobs.sqlite')
            require(reconcile(j,api,job['id'],APP)['state']=='DONE','reconciliation failed')
            result=json.loads(j.get(job['id'])['report'])
        expected='PASS' if all(controls.values()) and mode not in ('tamper','stale-review') else 'BLOCK'
        require(result['decision']==expected and not result['merge_authority'],'unexpected gate decision')
        require(api.posts==1 and j.get(job['id'])['state']=='DONE','unexpected publication state')
        require(api.checks[-1]['head_sha']==head,'check binding mismatch')
        revoked=None
        if expected=='PASS':
            revoked=sweep(j,api,policy,a,agg.public_key(),r,trust,APP,now=NOW+60,apply=True)[0]['status']
            require(revoked=='REVOKED' and api.checks[-1]['conclusion']=='failure','expiry not revoked')
        return {'mode':mode,'expected':expected,'observed':result['decision'],'controls':controls,
                'reasons':result['reasons'],'publication_count':api.posts,'journal_state':j.get(job['id'])['state'],
                'expired_check':revoked,'merge_authority':False}
    finally: j.close()


def local(out):
    out.mkdir(parents=True,exist_ok=False)
    rows=[]; ops=[]
    with tempfile.TemporaryDirectory(prefix='itm-rc1-') as t:
        tmp=Path(t); private=tmp/'signer.pem'; pub=tmp/'signer.pub'; bundle.keygen(private,pub)
        for name,expected in [('happy',True),('intent-drift',False),('property-regression',False),('missing-approval',False)]:
            run=tmp/name
            report=runner.run(name,run,ROOT/'examples/spec.toml',ROOT/'examples/policy.toml')
            require(report['merged']==expected,'unexpected local merge')
            bare=tmp/(name+'.git'); subprocess.run(['git','clone','--bare',str(run/'repo'),str(bare)],check=True,capture_output=True)
            exact=verify_payment_candidate(bare,report['base'],report['candidate'],load_config(ROOT/'examples/spec.toml'),backend='local',trusted_fixture=True)
            b=tmp/(name+'-bundle'); bundle.pack(run,b,private)
            # Remove both Git copies before offline evidence validation.
            shutil.rmtree(run/'repo'); shutil.rmtree(bare)
            v=bundle.verify(b,pub); require(v['merged']==expected and v['signature']=='verified','offline verification failed')
            first=json.loads((b/'evidence/ledger.jsonl').read_text().splitlines()[0])['payload']
            keys={role:Ed25519PrivateKey.generate() for role in set(autonomy.ROLES.values())}
            cfg={'version':1,'scope':{'repository':'demo/payments','agent':'coding-agent','model':'fixture-v1','profile':v['profile'],'bundle_signer':v['key_id'],**{k:first[k] for k in ('harness','policy','spec')}},'keys':{r:public(k) for r,k in keys.items()},'initial_level':2,'max_level':2,'risk_ceiling':'high','clean_required':2,'window':2,'adverse_limit':2}
            op=autonomy.gate(cfg,[],autonomy.ZERO,b,pub)
            require((op['status']=='ELIGIBLE')==expected,'operational gate mismatch')
            rows.append({'scenario':name,'expected_merge':expected,'local_merge':report['merged'],'exact_verification':exact['passed'],
                         'cases':len(exact['verification']['outcomes']),'signed_bundle':v['signature'],'offline_after_git_removed':True,
                         'autonomy':op['status'],'head':report['candidate'],'base':report['base']})
            modes=['normal','tamper','stale-review','lost-response'] if name=='happy' else ['normal']
            for mode in modes:
                ops.append({'scenario':name,**simulate_gate(tmp/(name+'-'+mode),report,v,exact,op,mode)})
            if name=='happy':
                e=autonomy.sign_event(cfg,[],'incident',{'id':'RC-INC','severity':'critical'},keys[autonomy.ROLES['incident']]); blocked=autonomy.gate(cfg,[e],e['hash'],b,pub)
                require(blocked['status']=='BLOCKED','incident did not block')
                ops.append({'scenario':name,**simulate_gate(tmp/'incident-gate',report,v,exact,blocked,'incident')})
    corpus=benchmark.evaluate_corpus(ROOT/'examples/amgb-v1/bundles',ROOT/'examples/amgb-v1/signer.pub', profile=HISTORICAL_V1)
    require(corpus==read(ROOT/'examples/amgb-v1/report.json'),'AMGB replay diverged')
    cfg=read(ROOT/'examples/changeset-v1/config.json'); anchor=read(ROOT/'examples/changeset-v1/anchor.json')
    receipts=[]
    for n in ['compatible','partial-failure','compensation-conflict']:
        receipts.append({'scenario':n,**changeset.verify_receipt(cfg,read(ROOT/f'examples/changeset-v1/{n}/receipt.json'),anchor['config_digest'])})
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    report={'release':version,'profile':'local-synthetic-e2e','production_ready':False,
            'publication_ready':False,'merge_authority':False,'remote_writes':0,
            'scenarios':rows,'api_contract_cases':ops,'amgb_replay':'verified','changeset_receipts':receipts,
            'limitations':['GitHub API simulated, signing identities ephemeral, no live agents or production events.','Worker snapshot is not atomic merge authorization; merge_group enforcement is not implemented.','Local executor is trusted fixture only.']}
    runner.write_json(out/'report.json',report); return report


def render(report, path):
    esc=lambda s:html.escape(str(s))
    rows=''.join('<tr>'+''.join(f'<td>{esc(v)}</td>' for v in (s['scenario'],s['expected_merge'],s['local_merge'],s['exact_verification'],s['signed_bundle'],s['autonomy']))+'</tr>' for s in report['scenarios'])
    ops=''.join('<tr>'+''.join(f'<td>{esc(v)}</td>' for v in (s['scenario'],s['mode'],s['expected'],s['observed'],s['publication_count'],s['expired_check'] or '—'))+'</tr>' for s in report['api_contract_cases'])
    Path(path).write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ITM RC.1 validation</title><style>body{{font:15px system-ui;color:#e9f0f5;background:#101c27;margin:0}}main{{max-width:1050px;margin:auto;padding:36px 20px}}h1{{font-size:36px}}p{{color:#b8c8d4}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;text-align:left;border-bottom:1px solid #385064}}.scroll{{overflow:auto}}small{{color:#63d6c3}}strong{{color:#f5be78}}</style><main><small>ITM / RELEASE QUALIFICATION</small><h1>{esc(report['release'])}</h1><p><strong>Production promotion: HOLD</strong> · local synthetic validation only · no remote writes</p><h2>Fresh Git changes → signed evidence</h2><div class="scroll"><table><tr><th>Scenario</th><th>Expected merge</th><th>Local merge</th><th>Exact verifier</th><th>Signature</th><th>Autonomy</th></tr>{rows}</table></div><h2>Isolated GitHub API contract</h2><div class="scroll"><table><tr><th>Scenario</th><th>Mode</th><th>Expected</th><th>Observed</th><th>Mock writes</th><th>Expiry</th></tr>{ops}</table></div><p>AMGB replay: {report['amgb_replay']} · Change set receipts: {len(report['changeset_receipts'])} verified.</p><h2>Remaining limits</h2>{''.join('<p>'+esc(x)+'</p>' for x in report['limitations'])}</main></html>''')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    result=local(a.out);render(result,a.out/'report.html');print(json.dumps({'local_scenarios':len(result['scenarios']),'api_cases':len(result['api_contract_cases']),'production_ready':False}))
