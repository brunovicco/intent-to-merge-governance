"""v0.10 trust-boundary hardening. No remote merge permission.

External receipts are authenticated claims, not proof of semantic correctness.
The local coordinator only operates on explicitly configured bare fixture repos.
"""
from __future__ import annotations
import base64, json, time, sqlite3, re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from .core import canonical, digest
from .github import positive_id, validate_check_response
from .policy_schema import InvalidConfiguration
from .operational import (
    CONTROLS, require, gate, checked_publication, correlated_check, reconciliation_required,
    validate_gate_policy,
)
from .changeset import verify_plan, repos_checked, plan, ref, git, verify_sig, sign, OBSERVATION_ERRORS

RECEIPT_DOMAIN = b'ITM-control-receipt-v1\0'
BINDINGS = ('repository','pr','head','base','policy_digest')


def validate_control_trust(trust):
    require(isinstance(trust, dict) and set(trust) == CONTROLS
            and all(isinstance(k, str) and re.fullmatch(r'[0-9a-f]{64}', k) for k in trust.values())
            and len(set(trust.values())) == len(CONTROLS), 'independent control keys required')


def verify_control_receipts(receipts, trust, report, now):
    """Require one independent, pinned signer per control; recompute artifact digests.

    Artifact contents are bounded structured observations supplied by trusted control
    services. The caller must pin trust outside agent-controlled storage.
    """
    validate_control_trust(trust)
    require(isinstance(receipts,list) and len(receipts)==len(CONTROLS),'complete control inventory required')
    seen=set(); roots={}
    for r in receipts:
        require(set(r)=={'statement','artifact','signature'},'invalid receipt envelope')
        s=r['statement']; artifact=r['artifact']; control=s.get('control')
        require(control in CONTROLS and control not in seen,'unknown or duplicate control')
        require(set(s)==set(BINDINGS)|{'control','profile','issued_at','expires_at','artifact_digest','passed'},'invalid statement fields')
        require(s['profile']=='external-control-v1' and s['passed'] is True,'control failed or synthetic profile')
        require(positive_id(s['pr']) and all(s[k]==report[k] for k in BINDINGS), 'control binding mismatch')
        require(type(s['issued_at']) is int and type(s['expires_at']) is int and s['issued_at']<=now<s['expires_at']<=s['issued_at']+900,'control expired')
        require(isinstance(artifact,dict) and 0<len(canonical(artifact))<=262144,'invalid artifact size')
        require(s['artifact_digest']==digest(artifact),'artifact digest mismatch')
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust[control])).verify(base64.b64decode(r['signature'],validate=True), RECEIPT_DOMAIN+canonical(s))
        except (ValueError,TypeError,InvalidSignature): raise ValueError('invalid control signature') from None
        seen.add(control); roots[control]=digest(r)
    return {'controls':sorted(seen),'evidence_digest':digest(roots),'expires_at':min(r['statement']['expires_at'] for r in receipts),'merge_authority':False}


def strict_gate(client,job,policy,assertion_dir,verifier_key,now=None,*,receipt_dir,control_trust):
    """A fresh preflight + legacy assertion + matching independent artifact receipts."""
    now=int(time.time() if now is None else now)
    report=gate(client,job,policy,assertion_dir,verifier_key,now)
    report['profile']='github-strict-snapshot'; report['control_receipts']=None
    try:
        filename=f"{job['pr']}-{report['head']}.json"
        path=Path(receipt_dir)/filename
        require(path.is_file() and not path.is_symlink() and path.stat().st_size<=2_000_000,'missing control evidence')
        require(verifier_key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() not in control_trust.values(),'aggregate and control keys must differ')
        result=verify_control_receipts(json.loads(path.read_text()),control_trust,report,now)
        assertion=json.loads((Path(assertion_dir)/filename).read_text())
        require(digest(assertion)==report['assertion_digest'],'assertion changed')
        require(assertion['statement']['evidence_digest']==result['evidence_digest'],'aggregate evidence binding mismatch')
        report['control_receipts']=result
        report['expires_at']=min(result['expires_at'],report['expires_at'])
    except (ValueError,KeyError,TypeError,OSError,AttributeError):
        report['reasons'].append('independent_control_evidence_missing_or_invalid')
    report['decision']='PASS' if not report['reasons'] else 'BLOCK'
    report['merge_authority']=False
    return report


BLOCKED_CONCLUSIONS = {'failure', 'action_required', 'cancelled', 'timed_out', 'stale', 'startup_failure'}


def sweep(journal, client, policy, assertion_dir, verifier_key, receipt_dir, control_trust,
          app_id, *, installation_id=None, now=None, apply=False):
    """Reconcile recoverable writes and revoke stale successes by exact check ID."""
    validate_gate_policy(policy)
    now = int(time.time() if now is None else now)
    results = []
    with journal.worker_lock():
        journal.recover()
        for row in journal.list():
            state = row['state']
            if (state not in ('DONE', 'UNCERTAIN', 'REVOCATION_UNCERTAIN')
                    or row['repo'].lower() != policy['repository'].lower()):
                continue
            job_id = row['id']
            try:
                intent, old = checked_publication(row, client, app_id, installation_id)
            except (ValueError, KeyError, TypeError):
                results.append({'id': job_id, **reconciliation_required(
                    row, 'publication_identity_unavailable_or_mismatched')})
                continue

            expiry = old.get('expires_at')
            timing = {'expired': now >= expiry, 'expires_at': expiry} if type(expiry) is int else {}
            check_id = row['check_id']
            if state == 'UNCERTAIN':
                try:
                    check_id, matches = correlated_check(client, intent)
                    checked_publication(row, client, app_id, installation_id)
                except Exception:
                    results.append({'id': job_id, **reconciliation_required(
                        row, 'remote_observation_unavailable', **timing)})
                    continue
                if check_id is None:
                    results.append({'id': job_id, **reconciliation_required(
                        row, 'no_unique_matching_check', matches=matches, **timing)})
                    continue
                if apply:
                    journal.transition(job_id, 'UNCERTAIN', 'DONE', check_id=check_id)
            if intent['conclusion'] == 'failure':
                if state == 'UNCERTAIN':
                    results.append({'id': job_id, 'status': 'RECONCILED' if apply else 'WOULD_RECONCILE'})
                continue

            path = f"/repos/{intent['repository']}/check-runs/{check_id}"
            try:
                require(positive_id(check_id), 'invalid stored check ID')
                remote = client.request(path)
                validate_check_response(remote, intent, intent['app_id'], check_id=check_id,
                                        conclusions=BLOCKED_CONCLUSIONS | {'success'})
            except Exception:
                results.append({'id': job_id, 'status': 'REMOTE_STATE_UNKNOWN',
                                'external_id': intent['external_id'], **timing,
                                'action': 'Inspect the correlated check before revocation.'})
                continue

            if remote['conclusion'] in BLOCKED_CONCLUSIONS:
                if state == 'REVOCATION_UNCERTAIN' and apply:
                    journal.transition(job_id, state, 'DONE')
                results.append({'id': job_id, 'status': 'ALREADY_BLOCKED'})
                continue

            valid = False
            if (state != 'REVOCATION_UNCERTAIN' and old.get('profile') == 'github-strict-snapshot'
                    and type(old.get('expires_at')) is int and now < old['expires_at']):
                try:
                    current = strict_gate(client, row, policy, assertion_dir, verifier_key, now,
                                          receipt_dir=receipt_dir, control_trust=control_trust)
                    valid = (current['decision'] == 'PASS' and all(old.get(k) == current.get(k)
                                     for k in (*BINDINGS, 'assertion_digest', 'control_receipts', 'gates')))
                except (ValueError, KeyError, TypeError, OSError):
                    pass
            if valid:
                status = 'WOULD_RECONCILE' if state == 'UNCERTAIN' and not apply else 'CURRENT'
            elif not apply:
                status = 'WOULD_REVOKE'
            else:
                prior = 'REVOCATION_UNCERTAIN' if state == 'REVOCATION_UNCERTAIN' else 'DONE'
                try:
                    checked_publication(row, client, app_id, installation_id)
                except (ValueError, KeyError, TypeError):
                    results.append({'id': job_id, **reconciliation_required(
                        journal.get(job_id), 'publication_identity_unavailable_or_mismatched', **timing)})
                    continue
                journal.transition(job_id, prior, 'REVOKING')
                try:
                    response = client.request(path, {
                        'status': 'completed', 'conclusion': 'failure',
                        'output': {'title': 'ITM evidence revoked',
                                   'summary': 'Evidence no longer current; fresh evaluation required.'},
                    }, method='PATCH')
                    validate_check_response(response, {**intent, 'conclusion': 'failure'},
                                            intent['app_id'], check_id=check_id)
                except Exception:
                    journal.transition(job_id, 'REVOKING', 'REVOCATION_UNCERTAIN')
                    results.append({'id': job_id, 'status': 'REVOCATION_UNCERTAIN',
                                    'external_id': intent['external_id'], **timing,
                                    'action': 'Observe the same check before confirming revocation.'})
                    continue
                journal.transition(job_id, 'REVOKING', 'DONE')
                status = 'REVOKED'
            results.append({'id': job_id, 'status': status})
    return results


class DurableChangeSet:
    """Persist intent before each local ref CAS; reconcile uncertain operations.

    Stop on unexplained reference drift. Explicit compensation uses the same
    write-ahead journal. No remote or production rollback authority.
    """
    def __init__(self,path):
        self.db=sqlite3.connect(path,timeout=10); self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS execution (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)');self.db.commit()
    def close(self): self.db.close()
    def load(self):
        r=self.db.execute('SELECT payload FROM execution WHERE id=1').fetchone();return json.loads(r[0]) if r else None
    def save(self,s):
        self.db.execute('INSERT OR REPLACE INTO execution VALUES(1,?)',(json.dumps(s,sort_keys=True),))
    def run(self,config,p,approvals,repos,key,*,compensate=False,fault=None):
        verify_plan(config,p,approvals);repos=repos_checked(config,repos)
        probe={'config_digest':digest(config)};verify_sig('probe',probe,sign('probe',probe,key),config['executor_key'])
        identity=digest({'config':config,'plan':p,'approvals':approvals,'repos':{n:str(r) for n,r in repos.items()}})
        def snapshot():return {n:ref(r,'refs/heads/main') for n,r in repos.items()}
        bases={n:c['base'] for n,c in p['components'].items()}; heads={n:c['head'] for n,c in p['components'].items()}
        # Serialize local coordinators using a separate advisory lock, while SQLite
        # commits each intent before the external CAS.
        import fcntl
        dbpath=self.db.execute('PRAGMA database_list').fetchone()[2]
        require(bool(dbpath),'durable file database required')
        with open(dbpath+'.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            s=self.load()
            def persist():
                s.pop('signature',None)
                s['signature']=sign('durable-state',s,key)
                with self.db:self.save(s)
            if s is None:
                require(plan(config,repos)==p,'stale plan')
                s={'identity':identity,'status':'RUNNING','completed':[],'pending':None,'events':[],'mode':'forward'};persist()
            require(s['identity']==identity,'journal binding mismatch')
            verify_sig('durable-state',{k:v for k,v in s.items() if k!='signature'},s['signature'],config['executor_key'])
            if s['status'] in ('COMPLETED','COMPENSATED','MANUAL_INTERVENTION'):return s
            def expected():return {n:heads[n] if n in s['completed'] else bases[n] for n in bases}
            def stop(reason):
                s['status']='MANUAL_INTERVENTION';s['events'].append({'event':'manual','reason':reason});persist();return s
            def observe():
                try:
                    return snapshot()
                except OBSERVATION_ERRORS:
                    return None
            # If the process died between CAS and its acknowledgement, check the
            # complete ref vector against the before and after states.
            if s['pending']:
                pending=s['pending'];n=pending['component'];before=expected();after={**before,n:pending['new']};actual=observe()
                if actual is None:return stop('refs unknown during recovery')
                if actual==after:
                    if pending['direction']=='forward':s['completed'].append(n)
                    else:s['completed'].remove(n)
                    s['events'].append({'event':'reconciled_applied','component':n})
                elif actual==before:s['events'].append({'event':'reconciled_not_applied','component':n})
                else:return stop('unexpected refs during recovery')
                s['pending']=None;persist()
            actual=observe()
            if actual is None:return stop('refs unknown before execution')
            if actual!=expected():return stop('unexpected refs before execution')
            if compensate:s['mode']='compensate';persist()
            for n in (list(reversed(s['completed'])) if s['mode']=='compensate' else [n for n in p['order'] if n not in s['completed']]):
                actual=observe()
                if actual is None:return stop('refs unknown before CAS')
                if actual!=expected():return stop('unexpected refs before CAS')
                if s['mode']=='forward':
                    try:
                        candidate=ref(repos[n],'refs/heads/candidate')
                    except OBSERVATION_ERRORS:
                        return stop('candidate ref unknown')
                    if candidate!=heads[n]:return stop('candidate drift')
                old=expected()[n];new=bases[n] if s['mode']=='compensate' else heads[n]
                s['pending']={'component':n,'old':old,'new':new,'direction':s['mode']};persist()
                if fault:fault('before_cas',n,repos)
                try:
                    result=git(repos[n],'update-ref','refs/heads/main',new,old,check=False)
                except OBSERVATION_ERRORS:
                    return stop('CAS outcome unknown')
                if result.returncode:return stop('CAS failed')
                if fault:fault('after_cas',n,repos)
                actual=observe()
                if actual is None:return stop('refs unknown after CAS')
                if actual!={**expected(),n:new}:return stop('unexpected refs after CAS')
                if s['mode']=='forward':s['completed'].append(n)
                else:s['completed'].remove(n)
                s['pending']=None;s['events'].append({'event':'cas_applied','component':n,'direction':s['mode']});persist()
            s['status']='COMPENSATED' if s['mode']=='compensate' else 'COMPLETED';persist();return s


def verify_payment_candidate(repo,base,head,spec,*,backend='docker',trusted_fixture=False,image='python:3.11-slim'):
    """Recompute PAY-104 verification from exact Git objects, not self-reported flags.

    Explicitly limited to the demo contract; never issues a live assertion. Local
    execution is only for trusted synthetic source. Docker is not a hostile-code
    security boundary or an independent proof of worker observations.
    """
    from .changeset import hexstr
    from .verification import Executor, WORKER, plan as verification_plan, evaluate, mutation_report
    from .fixtures import FIXED
    from .intent import validate_spec, drift, requirement_coverage
    require(hexstr(base,40) and hexstr(head,40) and base!=head,'invalid commit binding')
    require(backend=='docker' or (backend=='local' and trusted_fixture),'local execution restricted to trusted fixtures')
    try:
        validate_spec(spec)
    except ValueError:
        raise InvalidConfiguration('invalid_spec') from None
    if spec['id'] != 'PAY-104' or spec['allowed_paths'] != ['app/payments.py']:
        raise InvalidConfiguration('unsupported_demo_spec')
    repo=Path(repo).resolve(strict=True)
    require(git(repo,'rev-parse','--is-bare-repository').stdout.strip()==b'true','trusted bare Git clone required')
    require(git(repo,'merge-base','--is-ancestor',base,head,check=False).returncode==0,'candidate not descended from base')
    paths=sorted(x.decode() for x in git(repo,'diff','--no-renames','--name-only','-z',base,head,'--').stdout.split(b'\0') if x)
    require(paths==['app/payments.py'],'candidate outside demo scope')
    def source(sha):
        raw=git(repo,'show',sha+':app/payments.py').stdout
        require(len(raw)<=131072,'candidate source too large');return raw.decode()
    b,h=source(base),source(head)
    d=drift(spec,{'app/payments.py':b},{'app/payments.py':h},paths)
    ex=Executor(backend,image);vp=verification_plan(); baseline=ex.execute(b,WORKER,vp); candidate=ex.execute(h,WORKER,vp)
    result=evaluate(vp,candidate,baseline); mutations=mutation_report(vp,ex,WORKER,FIXED,baseline)
    coverage=requirement_coverage(spec,result['checks'],paths)
    passed=d['passed'] and all(result['checks'].values()) and all(m['killed'] for m in mutations) and all(r['verified'] for r in coverage)
    return {'profile':'exact-git-payment-verification','merge_authority':False,'base':base,'head':head,'spec_digest':digest(spec),'source_digest':digest(h),'paths':paths,'executor':ex.metadata(),'intent':d,'coverage':coverage,'verification':result,'mutation_adequacy':all(m['killed'] for m in mutations),'passed':passed}
