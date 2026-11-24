#!/usr/bin/env python3
"""RC5 integrated candidate lab, no merge authority, no remote writes."""
import argparse,hashlib,hmac,json,os,subprocess,sys,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intent_merge.core import canonical,digest
from intent_merge.integrated import run,attest,decision,check_receipt,Lifecycle,PROFILE
from intent_merge.budget import Limits
from intent_merge.control_plane import read_key,public
from intent_merge.secure_executor import Executor
from intent_merge.hardening import verify_control_receipts
from intent_merge.operational import CONTROLS, require

SCRIPT=Path(__file__).resolve()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2)

def complete(out,r,image):
    if r['status']!='PASSED':return {'profile':PROFILE,'status':r['status'],'decision':'BLOCK','merge_authority':False,'production_ready':False,'convergence':r}
    # Key generation strictly after agent execution. Separate verifier process.
    with tempfile.TemporaryDirectory(prefix='itm-rc5-verifier-') as tmp:
        k=Ed25519PrivateKey.generate();key=Path(tmp)/'key.pem';fd=os.open(key,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as f:f.write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        pub=public(k);save(out/'verifier-trust.json',{'profile':PROFILE,'verification':pub})
        subprocess.run([sys.executable,str(SCRIPT),'verify-worker','--out',str(out),'--key',str(key),'--image',image],check=True,timeout=90)
    receipt=json.loads((out/'verification-receipt.json').read_text());now=int(time.time());gate=decision(receipt,pub,r,now);require(gate['candidate_verified'],'independent receipt not verified')
    # The real gate's receipt validator must reject the lab profile. Six distinct
    # public pins are generated; no external-control signatures are manufactured.
    pins={c:public(Ed25519PrivateKey.generate()) for c in CONTROLS};pins['verification']=pub
    try:
        verify_control_receipts([receipt]+[{} for _ in range(5)],pins,{'head':r['head'],'base':r['base']},now)
    except ValueError:bridge='REJECTED_LAB_PROFILE'
    else:raise RuntimeError('lab evidence accepted by external validator')
    # Exercise the durable local lifecycle; not remote check revocation.
    db=out/'lifecycle.sqlite';j=Lifecycle(db);i=j.register(receipt,pub,r,now);before=j.state(i)
    secret=os.urandom(32);raw=canonical({'id':'lab-review-withdrawn','kind':'review_withdrawn','head':r['head'],'base':r['base'],'at':now});sig=hmac.new(secret,raw,hashlib.sha256).hexdigest();applied=j.event(raw,sig,secret);duplicate=j.event(raw,sig,secret);after=j.state(i);j.register(receipt,pub,r,now);no_restore=j.state(i);j.close();j=Lifecycle(db);restart=j.state(i);j.close()
    ok=all(v['state']=='REVOKED' for v in (after,no_restore,restart)) and before['state']=='CURRENT' and applied=='APPLIED' and duplicate=='DUPLICATE'
    return {'profile':PROFILE,'status':'PASS' if ok else 'FAIL','decision':'BLOCK','merge_authority':False,'production_ready':False,'convergence':r,'gate':gate,'external_gate_compatibility':bridge,'lifecycle':{'before':before,'after':after,'duplicate':duplicate,'no_restore':no_restore,'restart':restart}}

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('run');a.add_argument('--out',type=Path,required=True);a.add_argument('--provider',choices=['claude','codex'],default='claude');a.add_argument('--image',default='python:3.11-slim');a.add_argument('--attempts',type=int,default=3);a.add_argument('--tokens',type=int,default=400000);a.add_argument('--seconds',type=int,default=180);m=a.add_mutually_exclusive_group(required=True);m.add_argument('--fixture',choices=['first','repair','repeat','budget','scope']);m.add_argument('--allow-agent-execution',action='store_true')
    a=sub.add_parser('verify-worker');a.add_argument('--out',type=Path,required=True);a.add_argument('--key',type=Path,required=True);a.add_argument('--image',required=True)
    a=sub.add_parser('replay');a.add_argument('--out',type=Path,required=True);a.add_argument('--expected-verifier-key',required=True)
    a=p.parse_args();out=a.out.resolve()
    if a.cmd=='replay':
        r=json.loads((out/'convergence.json').read_text());rec=json.loads((out/'verification-receipt.json').read_text());check_receipt(rec,a.expected_verifier_key,r,rec['statement']['issued_at']);print(json.dumps({'historical_verification':'PASS','current_gate':decision(rec,a.expected_verifier_key,r,int(time.time())),'merge_authority':False,'note':'Historical replay is not current authorization; lifecycle journal not replayed.'},indent=2));return 0
    if a.cmd=='verify-worker':
        r=json.loads((out/'convergence.json').read_text());ex=Executor('local' if r['mode']=='synthetic_fixture' else 'docker',image=a.image);save(out/'verification-receipt.json',attest(out/'repo',r,ex,read_key(a.key)));return 0
    limits=Limits(a.attempts,a.tokens,a.seconds*1000);r=run(out,a.provider,limits,fixture=a.fixture,image=a.image)
    try:report=complete(out,r,a.image)
    except Exception as e:report={'profile':PROFILE,'status':'ERROR','error_type':type(e).__name__,'decision':'BLOCK','merge_authority':False,'production_ready':False,'convergence':r}
    save(out/'report.json',report);print(json.dumps({'status':report['status'],'convergence':r['status'],'attempts':len(r['attempts']),'decision':report['decision'],'merge_authority':False},indent=2));return 0 if report['status']=='PASS' else 2
if __name__=='__main__':raise SystemExit(main())
