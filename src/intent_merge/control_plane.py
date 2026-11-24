"""Distributed synthetic governance lab. Never compatible with live gate signatures.
Only built-in, trusted fixtures are executable. HTTP endpoints are private lab
interfaces, not general signing or execution services. No GitHub credentials.
"""
from __future__ import annotations
import base64, concurrent.futures, hashlib, html, json, os, re, sqlite3, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.client import HTTPConnection
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .core import canonical, digest
from .operational import CONTROLS, require
from .live_benchmark import SCENARIOS, structural, evaluate
from .verification import Executor
from .convergence import Governor

CONTROL_NAMES=tuple(sorted(CONTROLS))
RECEIPT=b'ITM-distributed-lab-receipt-v1\0'
AGGREGATE=b'ITM-distributed-lab-aggregate-v1\0'
PROFILE='distributed-synthetic-lab-v1'
POLICY={'profile':PROFILE,'required':list(CONTROL_NAMES),'ttl_seconds':30,'scope':['app/solution.py'],'max_attempts':3}
CASES={'happy':'ALLOW','scope':'BLOCK','behavior':'BLOCK','provenance':'BLOCK','loop':'BLOCK','missing_approval':'BLOCK','circuit_open':'BLOCK','unavailable':'BLOCK','delayed':'BLOCK','wrong_candidate':'BLOCK','wrong_nonce':'BLOCK','wrong_identity':'BLOCK','expired':'BLOCK','tampered':'BLOCK','duplicate':'BLOCK'}
MAX=262144


def fixture(case):
    require(case in CASES,'unknown fixture')
    s=SCENARIOS['AUTH-201']; source=s['base'] if case=='behavior' else s['fixed']
    return {'source':source,'base':s['base'],'paths':['app/solution.py','tests/unauthorized.py'] if case=='scope' else ['app/solution.py'],'trace_source_digest':'0'*64 if case=='provenance' else digest(source),'synthetic_review':{'author':'fixture-author','reviewer':'fixture-author' if case=='missing_approval' else 'fixture-reviewer','approved':case!='missing_approval','candidate_digest':digest(source)},'autonomy_level':0 if case=='circuit_open' else 2,'repeat':case=='loop'}


def binding(case,nonce):
    require(isinstance(nonce,str) and re.fullmatch(r'[0-9a-f]{32}',nonce),'invalid nonce')
    f=fixture(case)
    return {'profile':PROFILE,'case':case,'nonce':nonce,'candidate_digest':digest(f['source']),'base_digest':digest(f['base']),'fixture_digest':digest(f),'policy_digest':digest(POLICY)}


def observe(control,case):
    f=fixture(case);s=SCENARIOS['AUTH-201']
    if control=='intent':return {'passed':f['paths']==POLICY['scope'] and structural(f['source'],s),'paths':f['paths'],'structural':structural(f['source'],s)}
    if control=='provenance':return {'passed':f['trace_source_digest']==digest(f['source']),'observed_digest':f['trace_source_digest'],'source_digest':digest(f['source']),'trust':'synthetic_observation'}
    if control=='verification':return evaluate(f['source'],s,Executor('local',timeout=5))
    if control=='convergence':
        g=Governor({'max_iterations':3,'max_no_progress':2});r=None
        for i in range(1,3 if f['repeat'] else 2):
            r=g.observe(iteration=i,tree=digest(f['source']),checks={'intent_drift':True,'behavior':not f['repeat']},required=['behavior'],paths=f['paths'],case_count=20,diff_bytes=len(f['source']))
        return {'passed':r['action']=='passed','history':g.history,'trust':'synthetic_trace'}
    if control=='authorization':
        a=f['synthetic_review'];return {'passed':a['approved'] and a['author']!=a['reviewer'] and a['candidate_digest']==digest(f['source']),'review':a,'trust':'synthetic_not_human'}
    if control=='operational_autonomy':return {'passed':f['autonomy_level']>=2,'level':f['autonomy_level'],'trust':'synthetic_policy'}
    raise ValueError('unknown control')


def public(key):return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def sign(key,domain,body):return base64.b64encode(key.sign(domain+canonical(body))).decode()
def verify_sig(pub,domain,body,sig):Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(base64.b64decode(sig,validate=True),domain+canonical(body))
def read_key(path):
    key=serialization.load_pem_private_key(Path(path).read_bytes(),password=None);require(isinstance(key,Ed25519PrivateKey),'wrong key type');return key


def init(root):
    root=Path(root);root.mkdir(mode=0o700,parents=True,exist_ok=False);trust={}
    for n in (*CONTROL_NAMES,'aggregate'):
        d=root/n;d.mkdir(mode=0o700);k=Ed25519PrivateKey.generate();p=d/'key.pem'
        with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        trust[n]=public(k)
    (root/'trust.json').write_text(json.dumps(trust,indent=2));return trust


def receipt(control,case,nonce,key,now=None):
    b=binding(case,nonce);now=int(time.time()) if now is None else now
    artifact=observe(control,case)
    if control=='verification' and case=='wrong_candidate':b['candidate_digest']='f'*64
    if control=='verification' and case=='wrong_nonce':b['nonce']='f'*32
    s={**b,'control':control,'issued_at':now-60 if control=='verification' and case=='expired' else now,'expires_at':now-30 if control=='verification' and case=='expired' else now+POLICY['ttl_seconds'],'passed':artifact['passed'] is True,'artifact_digest':digest(artifact)}
    return {'statement':s,'artifact':artifact,'signature':sign(key,RECEIPT,s)}


def serve(control,key_path,host,port):
    require(control in CONTROL_NAMES,'unknown control');key=read_key(key_path)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send_json(self,status,data):
            raw=canonical(data);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            if self.path=='/health':self.send_json(200,{'control':control,'profile':PROFILE,'key':public(key)})
            else:self.send_json(404,{'error':'not_found'})
        def do_POST(self):
            try:
                require(self.path=='/evaluate','unknown endpoint');self.connection.settimeout(5);length=int(self.headers.get('Content-Length','0'));require(0<length<=4096,'invalid size');q=json.loads(self.rfile.read(length));require(set(q)=={'case','nonce'},'invalid request');binding(q['case'],q['nonce'])
                if control=='verification' and q['case']=='delayed':time.sleep(3)
                self.send_json(200,receipt(control,q['case'],q['nonce'],key))
            except Exception:self.send_json(400,{'error':'request_failed'})
    server=ThreadingHTTPServer((host,port),Handler);server.daemon_threads=True
    try:server.serve_forever()
    finally:server.server_close()


def check_trust(trust):
    require(set(trust)==set(CONTROL_NAMES)|{'aggregate'},'trust inventory mismatch');require(all(isinstance(v,str) and re.fullmatch(r'[0-9a-f]{64}',v) for v in trust.values()) and len(set(trust.values()))==7,'distinct pinned keys required')


def verify_receipt(r,control,b,trust,now):
    require(set(r)=={'statement','artifact','signature'} and len(canonical(r))<=MAX,'invalid envelope');s=r['statement'];a=r['artifact'];require(set(s)==set(b)|{'control','issued_at','expires_at','passed','artifact_digest'},'invalid statement');require(all(s[k]==v for k,v in b.items()) and s['control']==control,'binding mismatch');require(type(s['issued_at']) is int and type(s['expires_at']) is int and s['issued_at']<=now<s['expires_at']<=s['issued_at']+POLICY['ttl_seconds'],'expired or invalid lifetime');require(isinstance(a,dict) and s['artifact_digest']==digest(a) and type(s['passed']) is bool and a.get('passed') is s['passed'],'artifact mismatch');verify_sig(trust[control],RECEIPT,s,r['signature']);return s['passed']


def evaluate_receipts(b,receipts,trust,now):
    check_trust(trust);require(set(receipts)<=set(CONTROL_NAMES),'unknown control');results={}
    for c in CONTROL_NAMES:
        if c not in receipts:results[c]='MISSING';continue
        try:results[c]='PASS' if verify_receipt(receipts[c],c,b,trust,now) else 'DENIED'
        except Exception:results[c]='INVALID'
    return results


def lab_http(control, endpoint, route, *, data=None, timeout=3):
    """Direct HTTP only to the configured lab service or IPv4 loopback.

    No proxy or redirect handling. This is not service authentication.
    """
    require(control in CONTROL_NAMES and route in ('/health','/evaluate'), 'invalid lab target')
    require(isinstance(endpoint,str) and re.fullmatch(r'http://[a-z0-9.-]+:[0-9]{1,5}',endpoint), 'invalid lab endpoint')
    target=urlsplit(endpoint)
    port=target.port
    require(port is not None and 0<port<=65535, 'invalid lab port')
    require(target.hostname=='127.0.0.1' or (target.hostname==control.replace('_','-') and port==8080), 'non-lab endpoint')
    require(0<timeout<=10, 'invalid timeout')
    require((route=='/health' and data is None) or (route=='/evaluate' and isinstance(data,bytes) and len(data)<=4096), 'invalid lab request')
    start=time.monotonic(); connection=HTTPConnection(target.hostname,port,timeout=timeout)
    try:
        connection.request('GET' if data is None else 'POST',route,body=data,headers={'Content-Type':'application/json'})
        with connection.getresponse() as response:
            require(response.status==200,'unexpected lab response status')
            raw=response.read(MAX+1)
        require(len(raw)<=MAX and time.monotonic()-start<=timeout,'response limit')
        return json.loads(raw)
    finally:
        connection.close()


def collect(case,urls,trust,key,timeout=1.5):
    check_trust(trust);require(public(key)==trust['aggregate'],'aggregate key mismatch');require(set(urls)==set(CONTROL_NAMES) and 0<timeout<=10,'invalid endpoints or timeout');nonce=uuid.uuid4().hex;b=binding(case,nonce);start=time.monotonic();receipts={};errors={}
    def fetch(c):
        if c=='verification' and case=='unavailable':return None,'simulated_unavailable'
        try:
            return lab_http(c,urls[c],'/evaluate',data=canonical({'case':case,'nonce':nonce}),timeout=timeout),None
        except Exception as e:return None,type(e).__name__
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for c,(r,err) in zip(CONTROL_NAMES,pool.map(fetch,CONTROL_NAMES)):
            if err:errors[c]=err
            else:receipts[c]=r
    if case=='wrong_identity' and 'intent' in receipts:receipts['verification']=receipts['intent']
    if case=='duplicate' and 'intent' in receipts:receipts['provenance']=receipts['intent']
    if case=='tampered' and 'verification' in receipts:receipts['verification']['artifact']['cases']=-1
    now=int(time.time());results=evaluate_receipts(b,receipts,trust,now);allow=all(v=='PASS' for v in results.values());expires=min((r['statement']['expires_at'] for r in receipts.values()),default=now) if allow else now
    statement={**b,'evaluated_at':now,'expires_at':expires,'controls':results,'receipt_root':digest(receipts),'trust_digest':digest(trust),'decision':'ALLOW' if allow else 'BLOCK','merge_authority':False,'production_ready':False}
    return {'statement':statement,'signature':sign(key,AGGREGATE,statement),'receipts':receipts,'transport_errors':errors,'elapsed_seconds':round(time.monotonic()-start,4)}


def replay(report,trust,now=None):
    check_trust(trust);s=report['statement'];b=binding(s['case'],s['nonce']);require(all(s[k]==v for k,v in b.items()),'aggregate binding mismatch');require(s['merge_authority'] is False and s['production_ready'] is False and s['trust_digest']==digest(trust),'aggregate profile mismatch');verify_sig(trust['aggregate'],AGGREGATE,s,report['signature']);rs=report['receipts'];require(s['receipt_root']==digest(rs),'receipt root mismatch');r=evaluate_receipts(b,rs,trust,s['evaluated_at']);require(r==s['controls'],'control replay mismatch');allow=all(v=='PASS' for v in r.values());require(s['decision']==('ALLOW' if allow else 'BLOCK'),'decision mismatch');require(s['expires_at']==(min(x['statement']['expires_at'] for x in rs.values()) if allow else s['evaluated_at']),'expiry mismatch');now=int(time.time()) if now is None else now
    return {'verified':True,'historical_decision':s['decision'],'current_decision':'ALLOW' if allow and s['evaluated_at']<=now<s['expires_at'] else 'BLOCK','merge_authority':False}


class LabRevocations:
    """Durable local decision lifecycle; no remote network calls or restoration."""
    def __init__(self,path):
        self.db=sqlite3.connect(path);self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, expires INTEGER, state TEXT, reason TEXT)');self.db.commit()
    def close(self):self.db.close()
    def register(self,report,trust,now):
        require(replay(report,trust,now)['current_decision']=='ALLOW','not a current lab allow');i=digest(report['statement']);s=report['statement']
        with self.db:self.db.execute('INSERT OR IGNORE INTO decisions VALUES(?,?,?,?)',(i,s['expires_at'],'CURRENT',None))
        return i
    def revoke(self,i,reason):
        require(reason in ('synthetic_review_withdrawn','synthetic_circuit_open','expired'),'unknown lab event')
        with self.db:self.db.execute("UPDATE decisions SET state='REVOKED',reason=? WHERE id=? AND state='CURRENT'",(reason,i))
        return self.state(i)
    def sweep(self,now):
        with self.db:self.db.execute("UPDATE decisions SET state='REVOKED',reason='expired' WHERE state='CURRENT' AND expires<=?",(now,))
    def state(self,i):
        row=self.db.execute('SELECT state,reason FROM decisions WHERE id=?',(i,)).fetchone();require(row is not None,'unknown decision');return {'state':row[0],'reason':row[1],'merge_authority':False}


def render(report):
    rows=''.join('<tr><td>'+html.escape(r['statement']['case'])+'</td>'+''.join('<td>'+r['statement']['controls'][c]+'</td>' for c in CONTROL_NAMES)+'<td>'+r['statement']['decision']+'</td></tr>' for r in report['runs'])
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>ITM distributed lab</title><style>body{font:15px system-ui;margin:2rem;color:#182b3e}table{border-collapse:collapse;width:100%}td,th{padding:.7rem;border-bottom:1px solid #ddd;text-align:left}th{background:#eaf0f5}</style><h1>Distributed governance control plane</h1><p>Synthetic lab only; no merge authority. Separate HTTP processes and ephemeral keys, not independent organizations.</p><table><tr><th>Case</th>'+''.join('<th>'+c+'</th>' for c in CONTROL_NAMES)+'<th>Decision</th></tr>'+rows+'</table></html>'
