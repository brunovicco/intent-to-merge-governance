"""Durable single-worker GitHub App gate. No remote merge authority."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re, sqlite3, time, fcntl
from collections import Counter
from contextlib import contextmanager, nullcontext
from pathlib import Path
from urllib.request import Request, build_opener
from urllib.error import HTTPError, URLError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.exceptions import InvalidSignature
from .core import canonical, digest
from .github import (
    CheckPublicationUnconfirmed, GitHub, NoRedirect, REPO, preflight, valid_token,
    positive_id, validate_check_response,
)

NAME='ITM / evidence gate'
CONTROLS={'intent','provenance','verification','convergence','authorization','operational_autonomy'}
DOMAIN=b'ITM-live-verifier-v1\x00'
MAX_BODY=2*1024*1024

def require(ok,msg):
    if not ok: raise ValueError(msg)

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def app_jwt(app_id,key,now=None):
    require(type(app_id) is int and app_id>0,'invalid app ID')
    require(isinstance(key,rsa.RSAPrivateKey) and key.key_size>=2048,'RSA >=2048 required')
    now=int(time.time() if now is None else now)
    body=b64(canonical({'alg':'RS256','typ':'JWT'}))+'.'+b64(canonical({'iat':now-30,'exp':now+540,'iss':str(app_id)}))
    return body+'.'+b64(key.sign(body.encode(),padding.PKCS1v15(),hashes.SHA256()))

def installation_client(app_id, installation_id, private_key, repository):
    require(type(installation_id) is int and installation_id>0 and REPO.fullmatch(repository),'invalid installation/repository')
    key=serialization.load_pem_private_key(Path(private_key).read_bytes(),password=None)
    token=app_jwt(app_id,key)
    req=Request(f'https://api.github.com/app/installations/{installation_id}/access_tokens',data=canonical({'repositories':[repository.split('/')[1]],'permissions':{'contents':'read','pull_requests':'read','checks':'write'}}),headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'intent-to-merge/0.9'})
    try:
        with build_opener(NoRedirect()).open(req,timeout=30) as response: raw=response.read(65537)
    except (HTTPError,URLError): raise ValueError('installation authentication failed') from None
    require(len(raw)<=65536,'token response too large')
    body = json.loads(raw)
    require(isinstance(body, dict) and valid_token(body.get('token')), 'invalid installation token response')
    return GitHub(body['token'], installation_app_id=app_id)

def delivery(raw,signature,event,delivery_id,secret,repo,installation):
    require(len(raw)<=MAX_BODY,'webhook too large')
    require(isinstance(secret,bytes) and len(secret)>=32,'webhook secret must have at least 32 bytes')
    expected='sha256='+hmac.new(secret,raw,hashlib.sha256).hexdigest()
    require(isinstance(signature,str) and hmac.compare_digest(expected,signature),'invalid webhook signature')
    require(isinstance(delivery_id,str) and re.fullmatch(r'[A-Za-z0-9-]{1,80}',delivery_id),'invalid delivery ID')
    data=json.loads(raw)
    require(isinstance(data,dict),'invalid webhook payload')
    if event not in ('pull_request','pull_request_review'): return None
    require(data['repository']['full_name'].lower()==repo.lower() and data['installation']['id']==installation,'untrusted repository or installation')
    actions={'pull_request':{'opened','reopened','synchronize','ready_for_review','converted_to_draft','edited','closed'},'pull_request_review':{'submitted','dismissed'}}
    if data.get('action') not in actions[event]: return None
    number=data['pull_request']['number']
    require(type(number) is int and number>0,'invalid PR number')
    return {'id':delivery_id,'repo':repo,'pr':number,'body_sha256':hashlib.sha256(raw).hexdigest()}

class Journal:
    """SQLite commit before network side effects; never blindly retry ambiguous writes."""
    def __init__(self,path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(self.path,timeout=10); self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,repo TEXT NOT NULL,pr INTEGER NOT NULL,body_sha256 TEXT NOT NULL,state TEXT NOT NULL,report TEXT,external_id TEXT,check_id INTEGER)'''); self.db.commit()
    def close(self): self.db.close()
    def enqueue(self,job):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO jobs(id,repo,pr,body_sha256,state) VALUES(:id,:repo,:pr,:body_sha256,\'QUEUED\')',job)
            row=self.get(job['id']); require(all(row[k]==job[k] for k in ('repo','pr','body_sha256')),'delivery ID collision')
        return row['state']
    def get(self,id):
        row=self.db.execute('SELECT * FROM jobs WHERE id=?',(id,)).fetchone(); return dict(row) if row else None
    def list(self): return [dict(r) for r in self.db.execute('SELECT * FROM jobs ORDER BY rowid')]
    @contextmanager
    def worker_lock(self):
        with open(str(self.path)+'.worker.lock','a') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try: yield
            finally: fcntl.flock(f,fcntl.LOCK_UN)
    def recover(self):
        with self.db:
            self.db.execute("UPDATE jobs SET state='QUEUED' WHERE state='RUNNING'")
            self.db.execute("UPDATE jobs SET state='UNCERTAIN' WHERE state='PUBLISHING'")
    def claim(self):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE'); r=self.db.execute("SELECT id FROM jobs WHERE state='QUEUED' ORDER BY rowid LIMIT 1").fetchone()
            if not r:return None
            self.db.execute("UPDATE jobs SET state='RUNNING' WHERE id=?",(r['id'],))
            return self.get(r['id'])
    def transition(self,id,old,new,**fields):
        require(set(fields)<= {'report','external_id','check_id'},'invalid journal field')
        if 'check_id' in fields:
            require(positive_id(fields['check_id']), 'invalid journal check ID')
        with self.db:
            result=self.db.execute('UPDATE jobs SET state=?'+''.join(', '+k+'=?' for k in fields)+' WHERE id=? AND state=?',(new,*fields.values(),id,old))
            require(result.rowcount==1,'invalid job transition')


def verify_assertion(envelope,key,report,now):
    """Trusted external verifier statement, not a claim that ITM executed live tests."""
    require(isinstance(key,ed25519.Ed25519PublicKey),'Ed25519 verifier required')
    body=envelope['statement']; require(set(envelope)=={'statement','signature'},'invalid envelope')
    try: key.verify(base64.b64decode(envelope['signature'],validate=True),DOMAIN+canonical(body))
    except (InvalidSignature,ValueError): raise ValueError('invalid verifier signature') from None
    require(body['profile']=='live-external-verifier' and body['schema_version']==1,'synthetic or unsupported verifier profile')
    for k in ('repository','pr','head','base','policy_digest'):
        require(body[k]==report[k],'verifier binding mismatch: '+k)
    require(type(body['issued_at']) is int and type(body['expires_at']) is int and body['issued_at']<=now<body['expires_at']<=body['issued_at']+900,'verifier assertion expired or invalid lifetime')
    require(set(body['controls'])==CONTROLS and all(v is True for v in body['controls'].values()),'required verifier controls not satisfied')
    require(re.fullmatch(r'[0-9a-f]{64}',body['evidence_digest']),'invalid evidence digest')
    return digest(envelope)

def gate(client,job,policy,assertion_dir,verifier_key,now=None):
    require(policy['repository'].lower()==job['repo'].lower(),'job policy mismatch')
    require(all(c['name']!=NAME for c in policy['required_checks']),'gate cannot require itself')
    p=preflight(client,job['repo'],job['pr'],policy)
    now=int(time.time() if now is None else now)
    reasons=list(p['reasons']); assertion_digest=None; expires_at=None
    try:
        path=Path(assertion_dir)/(str(job['pr'])+'-'+p['head']+'.json')
        require(not path.is_symlink() and path.is_file() and path.stat().st_size<=65536,'missing or invalid verifier assertion')
        assertion = json.loads(path.read_text())
        assertion_digest = verify_assertion(assertion, verifier_key, p, now)
        expires_at = assertion['statement']['expires_at']
    except (ValueError,KeyError,TypeError,OSError): reasons.append('trusted_live_assertion_missing_or_invalid')
    return {**p,'profile':'github-app-snapshot','decision':'PASS' if not reasons else 'BLOCK','reasons':reasons,'assertion_digest':assertion_digest,'expires_at':expires_at,'evaluated_at':now,'merge_authority':False,'note':'Snapshot only; external verifier is trusted. Not full live ITM execution or merge permission.'}

def span(tracer,name): return tracer.start_as_current_span(name) if tracer else nullcontext(None)

def publication_block(report, latest, checked_at):
    first = report.get('evaluated_at')
    refreshed = latest.get('evaluated_at')
    expiry = latest.get('expires_at')
    if (any(type(t) is not int for t in (first, refreshed, checked_at))
            or not 0 <= first <= refreshed <= checked_at):
        return 'evidence_clock_invalid_before_publication'
    profile = latest.get('profile')
    assertion = latest.get('assertion_digest')
    receipts = latest.get('control_receipts')
    if (profile not in ('github-app-snapshot', 'github-strict-snapshot')
            or not isinstance(assertion, str) or not re.fullmatch(r'[0-9a-f]{64}', assertion)
            or type(expiry) is not int or expiry <= 0
            or (profile == 'github-strict-snapshot'
                and (not isinstance(receipts, dict) or type(receipts.get('expires_at')) is not int
                     or expiry > receipts['expires_at']))):
        return 'verified_evidence_expiry_missing_or_invalid'
    if checked_at >= expiry:
        return 'evidence_expired_before_publication'
    return None


def work_once(journal,client,policy,assertion_dir,verifier_key,*,app_id,tracer=None,now=None,publish=False,gate_fn=gate,publication_clock=None):
    """Process a delivery. Gate and clock injection are trusted caller inputs.

    The evaluation override now only affects evaluation. The publication clock
    returns epoch seconds and defaults to a new sample after the durable transition.
    """
    require(not publish or positive_id(app_id), 'invalid publication App ID')
    installation_app_id = getattr(client, 'installation_app_id', None)
    if publish and installation_app_id is not None:
        require(positive_id(installation_app_id) and installation_app_id == app_id,
                'publication App identity mismatch')
    with journal.worker_lock(),span(tracer,'itm.worker') as s:
        journal.recover(); job=journal.claim()
        if not job:return None
        id=job['id']
        try:
            with span(tracer,'itm.evaluate'):
                report=gate_fn(client,job,policy,assertion_dir,verifier_key,now)
            if s: s.set_attribute('itm.decision',report['decision'])
            if not publish:
                journal.transition(id,'RUNNING','DRY_RUN',report=json.dumps(report)); return report
            # Refresh all preflight inputs before publication, not only the head SHA.
            latest=gate_fn(client,job,policy,assertion_dir,verifier_key,now)
            for k in ('profile','head','base','policy_digest','decision','gates','reasons','assertion_digest','control_receipts','expires_at'):
                require(latest.get(k)==report.get(k),'PR evidence changed; retry with fresh delivery')
        except Exception:
            journal.transition(id,'RUNNING','QUEUED'); raise
        external=digest({'delivery':id,'report':latest,'app_id':app_id})
        payload={'name':NAME,'head_sha':latest['head'],'external_id':external,'status':'completed','conclusion':'success' if latest['decision']=='PASS' else 'failure','output':{'title':'ITM '+latest['decision'],'summary':'Snapshot gate; no merge authority. '+', '.join(latest['reasons'])[:1000]}}
        journal.transition(id,'RUNNING','PUBLISHING',report=json.dumps(latest),external_id=external)
        attempted = False
        try:
            with span(tracer,'itm.publish'):
                if latest['decision'] == 'PASS':
                    try:
                        checked_at = int(time.time()) if publication_clock is None else publication_clock()
                    except (OSError, ValueError, TypeError, OverflowError):
                        checked_at = None
                    if type(checked_at) is not int:
                        checked_at = None
                    reason = publication_block(report, latest, checked_at)
                    if reason is not None:
                        blocked = {**latest, 'decision': 'BLOCK',
                                   'reasons': [*latest['reasons'], reason],
                                   'publication_checked_at': checked_at,
                                   'publication_attempted': False}
                        journal.transition(id, 'PUBLISHING', 'BLOCKED_BEFORE_PUBLICATION',
                                           report=json.dumps(blocked), external_id=None)
                        return blocked
                attempted = True
                result=client.request('/repos/'+job['repo']+'/check-runs',payload)
            check_id = validate_check_response(result, payload, app_id)
            journal.transition(id,'PUBLISHING','DONE',check_id=check_id)
        except Exception:
            if attempted:
                journal.transition(id, 'PUBLISHING', 'UNCERTAIN')
                raise CheckPublicationUnconfirmed(job['repo'], app_id, payload) from None
            if journal.get(id)['state'] == 'PUBLISHING':
                blocked = {**latest, 'decision': 'BLOCK',
                           'reasons': [*latest['reasons'], 'publication_preparation_failed'],
                           'publication_attempted': False}
                journal.transition(id, 'PUBLISHING', 'BLOCKED_BEFORE_PUBLICATION',
                                   report=json.dumps(blocked), external_id=None)
            raise
        return latest

def reconcile(journal,client,id,app_id):
    with journal.worker_lock():
        journal.recover(); job=journal.get(id); require(job and job['state']=='UNCERTAIN','job not uncertain')
        r = json.loads(job['report'])
        expected = {'external_id': job['external_id'], 'name': NAME, 'head_sha': r['head'],
                    'status': 'completed', 'conclusion': 'success' if r['decision'] == 'PASS' else 'failure'}
        require(isinstance(job['external_id'], str) and bool(job['external_id'])
                and positive_id(app_id), 'invalid publication correlation')
        route = '/repos/' + job['repo'] + '/commits/' + r['head'] + '/check-runs?filter=all'
        matches = []
        check_ids = Counter()
        ambiguous = False
        for row in client.pages(route, 'check_runs'):
            if not isinstance(row, dict):
                ambiguous = True
                continue
            if positive_id(row.get('id')):
                check_ids[row['id']] += 1
            external = row.get('external_id')
            if external == expected['external_id']:
                matches.append(row)
            elif ((not isinstance(external, str) or not external)
                  and (not isinstance(row.get('name'), str) or not row['name'] or row['name'] == NAME)):
                ambiguous = True
        if len(matches) == 1 and not ambiguous:
            try:
                check_id = validate_check_response(matches[0], expected, app_id)
            except ValueError:
                pass
            else:
                if check_ids[check_id] == 1 and check_id <= 2**63 - 1:
                    journal.transition(id, 'UNCERTAIN', 'DONE', check_id=check_id)
                    return {'state': 'DONE', 'check_id': check_id}
        return {'state': 'UNCERTAIN', 'matches': len(matches),
                'note': 'No automatic retry; inspect remote state.'}
