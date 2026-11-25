#!/usr/bin/env python3
"""Explicit lab-only GitHub writes, never a synthetic evidence authorization."""
import argparse,json,os,time,uuid
from pathlib import Path
from functools import partial
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from intent_merge.core import digest
from intent_merge.github import policy_from,preflight,validate_check_response,positive_id
from intent_merge.operational import CONTROLS,NAME,Journal,installation_client,work_once
from intent_merge.hardening import strict_gate

LAB='brunovicco/intent-to-merge-governance-lab'
TRANSPORT='ITM / lab transport only (non-authorizing)'

def save(path,data):
    with path.open('x') as f:json.dump(data,f,indent=2);f.flush();os.fsync(f.fileno())

def verify_remote(c,app_id,head,name,external,conclusion,id=None):
    expected = {'head_sha': head, 'name': name, 'external_id': external,
                'status': 'completed', 'conclusion': conclusion}
    validate_check_response(c, expected, app_id, check_id=id)
    return {k:c.get(k) for k in ('id','name','head_sha','external_id','status','conclusion','html_url')}|{'app_id':app_id}

def lab_negative(client,policy,pr,app_id,out,publish):
    # Generate only public trust pins for an explicitly empty evidence inventory.
    # No signed claims are manufactured and private keys are not retained.
    a=out/'assertions';r=out/'receipts';a.mkdir();r.mkdir()
    key=Ed25519PrivateKey.generate().public_key();trust={c:Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() for c in sorted(CONTROLS)}
    (out/'verifier.pub').write_bytes(key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));save(out/'control-trust.json',trust)
    j=Journal(out/'jobs.sqlite');job={'id':'lab-negative-'+uuid.uuid4().hex,'repo':LAB,'pr':pr};job['body_sha256']=digest(job);j.enqueue(job)
    def negative_gate(*args,**kwargs):
        report=strict_gate(*args,**kwargs,receipt_dir=r,control_trust=trust)
        if report['decision']!='BLOCK' or not {'trusted_live_assertion_missing_or_invalid','independent_control_evidence_missing_or_invalid'}.issubset(report['reasons']):raise ValueError('expected missing evidence block')
        return report
    try:
        report=work_once(j,client,policy,a,key,app_id=app_id,publish=publish,gate_fn=negative_gate)
        row=j.get(job['id']);remote=None
        if publish:remote=verify_remote(client.request(f"/repos/{LAB}/check-runs/{row['check_id']}"),app_id,report['head'],NAME,row['external_id'],'failure',row['check_id'])
        return {'status':'PASS','profile':'live-negative-evidence-gate','report':report,'journal_state':row['state'],'remote':remote,'merge_authority':False}
    finally:j.close()

def transport(client,policy,pr,app_id,out):
    pre=preflight(client,LAB,pr,policy);head=pre['head'];prefix=f'/repos/{LAB}';external='lab-transport-'+uuid.uuid4().hex
    if pre['decision']!='BLOCK':raise ValueError('transport probe requires blocked PR')
    # Guard against accidentally making this check required in an active ruleset.
    # Public repository ruleset reads require no administration write permission.
    for item in client.pages(prefix+'/rulesets'):
        if not isinstance(item, dict) or not positive_id(item.get('id')):
            raise ValueError('invalid ruleset identity')
        rule=client.request(prefix+'/rulesets/'+str(item['id']))
        for entry in rule.get('rules',[]):
            if entry.get('type')=='required_status_checks' and any(c.get('context')==TRANSPORT for c in entry['parameters']['required_status_checks']):raise ValueError('transport check must never be required')
    save(out/'publication-intent.json',{'repository':LAB,'pr':pr,'head':head,'app_id':app_id,'name':TRANSPORT,'external_id':external,'scope':'transport only; never authorization'})
    payload={'name':TRANSPORT,'head_sha':head,'external_id':external,'status':'completed','conclusion':'success','output':{'title':'Transport probe created (not authorization)','summary':'Synthetic transport test only. Never an evidence gate, required check or merge authorization.'}}
    response=client.request(prefix+'/check-runs',payload);created=verify_remote(response,app_id,head,TRANSPORT,external,'success');path=prefix+'/check-runs/'+str(created['id']);created=verify_remote(client.request(path),app_id,head,TRANSPORT,external,'success',created['id']);save(out/'created.json',created)
    save(out/'revocation-intent.json',{'id':created['id'],'external_id':external,'head':head,'app_id':app_id})
    client.request(path,{'status':'completed','conclusion':'failure','output':{'title':'Transport probe revoked','summary':'Transport-only success-to-failure transition. No merge authorization was granted.'}},method='PATCH')
    revoked=verify_remote(client.request(path),app_id,head,TRANSPORT,external,'failure',created['id']);return {'status':'PASS','profile':'live-check-transport-only','created':created,'revoked':revoked,'merge_authority':False,'authorization_revocation_validated':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['negative','transport']);p.add_argument('--policy',type=Path,required=True);p.add_argument('--pr',type=int,default=1);p.add_argument('--app-id',type=int,required=True);p.add_argument('--installation',type=int,required=True);p.add_argument('--app-key',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--publish',action='store_true');a=p.parse_args()
    policy=policy_from(a.policy)
    if policy['repository']!=LAB:p.error('only dedicated public ITM lab permitted')
    if a.mode=='transport' and not a.publish:p.error('transport requires explicit --publish')
    a.out.mkdir(parents=True,exist_ok=False);client=installation_client(a.app_id,a.installation,a.app_key,LAB)
    try:result=lab_negative(client,policy,a.pr,a.app_id,a.out,a.publish) if a.mode=='negative' else transport(client,policy,a.pr,a.app_id,a.out)
    except Exception as e:
        result={'status':'ERROR_OR_UNCERTAIN','error_type':type(e).__name__,'merge_authority':False,'note':'Inspect journal/intents and remote checks before any retry; do not blindly repeat.'};save(a.out/'report.json',result);print(json.dumps(result,indent=2));return 2
    save(a.out/'report.json',result);print(json.dumps(result,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
