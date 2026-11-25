"""Local deterministic transport fixture; no network, credentials or real PRs."""
import argparse,base64,json,tempfile,html
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from intent_merge.operational import Journal,work_once,reconcile,DOMAIN,CONTROLS
from intent_merge.core import canonical,digest
from intent_merge.github import policy_from

HEAD='a'*40;BASE='b'*40;APP=789;NOW=1900000000
class Fixture:
    installation_app_id = APP
    installation_id = 1
    installation_repository = 'OWNER/REPO'
    def __init__(self):
        self.posts=[];self.lose=False;self.pr={'head':{'sha':HEAD,'repo':{'full_name':'OWNER/REPO'}},'base':{'sha':BASE,'ref':'main','repo':{'full_name':'OWNER/REPO'}},'state':'open','draft':False,'changed_files':1,'user':{'id':99}}
        self.checks=[{'id':3,'name':'trusted-ci','app':{'id':12345},'head_sha':HEAD,'status':'completed','conclusion':'success'}]
        self.reviews=[{'id':i,'user':{'id':u,'type':'User'},'state':'APPROVED','commit_id':HEAD} for i,u in [(1,10001),(2,10002)]]
    def request(self,path,payload=None):
        if payload is None:return self.pr
        r={**payload,'id':len(self.posts)+44,'app':{'id':APP}};self.posts.append(r);self.checks.append(r)
        if self.lose:raise ValueError('fixture: response lost after remote write')
        return r
    def pages(self,path,key=None):
        return iter([{'filename':'app/payments.py','status':'modified'}] if path.endswith('/files') else self.reviews if path.endswith('/reviews') else self.checks)

def study(out):
    out.mkdir(parents=True,exist_ok=False);policy=policy_from(Path('examples/github-policy.toml'));rows=[]
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);key=ed25519.Ed25519PrivateKey.generate();assertions=root/'assertions';assertions.mkdir();path=assertions/f'1-{HEAD}.json'
        body={'schema_version':1,'profile':'live-external-verifier','repository':'OWNER/REPO','pr':1,'head':HEAD,'base':BASE,'policy_digest':digest(policy),'issued_at':NOW-10,'expires_at':NOW+60,'controls':dict.fromkeys(CONTROLS,True),'evidence_digest':'c'*64}
        def write(b):path.write_text(json.dumps({'statement':b,'signature':base64.b64encode(key.sign(DOMAIN+canonical(b))).decode()}))
        for scenario in ('trusted-snapshot','missing-assertion','expired-assertion','synthetic-profile','lost-response','unresolved-publication'):
            path.unlink(missing_ok=True);api=Fixture();db=root/(scenario+'.sqlite');j=Journal(db);j.enqueue({'id':scenario,'repo':'OWNER/REPO','pr':1,'body_sha256':digest(scenario)})
            if scenario!='missing-assertion':write({**body,**({'expires_at':NOW} if scenario=='expired-assertion' else {'profile':'synthetic-demo'} if scenario=='synthetic-profile' else {})})
            if scenario in ('lost-response','unresolved-publication'):api.lose=True
            try:work_once(j,api,policy,assertions,key.public_key(),app_id=APP,publish=True,now=NOW,publication_clock=lambda: NOW)
            except ValueError:
                if not api.lose:raise
            initial=j.get(scenario)['state'];j.close();j=Journal(db)
            if scenario=='unresolved-publication':api.checks=api.checks[:1]
            if initial=='UNCERTAIN':reconcile(j,api,scenario,APP)
            row=j.get(scenario);report=json.loads(row['report']);rows.append({'scenario':scenario,'decision':report['decision'],'initial_state':initial,'recovered_state':row['state'],'remote_writes':len(api.posts),'reasons':report['reasons']});j.close()
    report={'profile':'synthetic-transport-fixture','merge_authority':False,'scenarios':rows,'note':'No authenticated GitHub or agent calls; the external-verifier profile is signed using an ephemeral fixture key, never a live trust root.'}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    trs=''.join('<tr>'+''.join(f'<td>{html.escape(str(r[k]))}</td>' for k in ('scenario','decision','initial_state','recovered_state','remote_writes'))+'</tr>' for r in rows)
    (out/'report.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ITM v0.9 Operational Study</title><style>body{font:16px system-ui;background:#f4f5f7;color:#172033;margin:5vw}main{max-width:1000px;margin:auto}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;padding:12px;border-bottom:1px solid #dce1e6}th{background:#173548;color:white}small{color:#475569}h1{font-size:32px}section{overflow:auto}</style><main><small>INTENT-TO-MERGE / v0.9 / SYNTHETIC TRANSPORT FIXTURE</small><h1>Operational recovery and evidence gates</h1><p>Durable publication journal. No blind retries after an ambiguous write. No real merge authority.</p><section><table><thead><tr><th>Scenario</th><th>Gate</th><th>After attempt</th><th>After restart</th><th>Writes</th></tr></thead><tbody>'''+trs+'</tbody></table></section><p>Fixture-only results, not a live GitHub deployment.</p></main></html>')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);print(json.dumps(study(p.parse_args().out),indent=2))
