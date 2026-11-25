"""RC5 bounded candidate lab: actual Git objects, isolated verifier process, no merge authority.
Only built-in AUTH-201 is supported. A local process is not an organizational authority.
"""
from __future__ import annotations
import hashlib, hmac, json, math, os, re, sqlite3, subprocess, sys, time, uuid
from pathlib import Path
from .core import canonical, digest
from .operational import require
from .budget import BudgetController, Limits
from .capture import run_agent
from .live_benchmark import SCENARIOS, structural, evaluate
from .secure_executor import Executor
from .control_plane import sign, verify_sig, public, read_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROFILE='integrated-candidate-lab-v1'
DOMAIN=b'ITM-integrated-candidate-lab-v1\0'
TARGET='app/solution.py'
SCENARIO=SCENARIOS['AUTH-201']
SHA=re.compile(r'[0-9a-f]{40}')
HEX=re.compile(r'[0-9a-f]{64}')

def git(repo,*args,bare=False):
    # Ignore inherited Git selectors and replace refs. Repo metadata itself
    # is still same-user writable; this is not a sandbox boundary.
    env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0')
    location = ['-C', str(repo)]
    if bare:
        env.update(GIT_GRAFT_FILE=os.devnull, GIT_NO_LAZY_FETCH='1')
        location = ['--git-dir', str(repo), '-c', 'core.commitGraph=false']
    return subprocess.check_output(
        ['git', '--no-replace-objects', *location, '-c', 'core.hooksPath=/dev/null', *args],
        env=env, stderr=subprocess.DEVNULL, timeout=30,
    )

def text_git(repo,*args):return git(repo,*args).decode().strip()

def setup(repo):
    repo.mkdir();git(repo,'init','-b','main');git(repo,'config','user.name','ITM lab');git(repo,'config','user.email','lab@example.invalid');git(repo,'config','commit.gpgsign','false');git(repo,'config','core.hooksPath','/dev/null')
    p=repo/TARGET;p.parent.mkdir();p.write_text(SCENARIO['base']);git(repo,'add','--','.');git(repo,'commit','-m','baseline');return text_git(repo,'rev-parse','HEAD')

def candidate(repo,base,head):
    require(all(isinstance(s,str) and SHA.fullmatch(s) for s in (base,head)),'invalid SHA')
    require(text_git(repo,'rev-parse',base)==base and text_git(repo,'rev-parse',head)==head,'object mismatch')
    require(git(repo,'show',f'{base}:{TARGET}').decode()==SCENARIO['base'],'baseline mismatch')
    require(git(repo,'ls-tree','-r','--name-only','-z',base)==(TARGET+'\0').encode() and git(repo,'ls-tree','-r','--name-only','-z',head)==(TARGET+'\0').encode(),'fixture tree inventory mismatch')
    require(git(repo,'ls-tree',base,'--',TARGET).startswith(b'100644 blob '),'baseline mode mismatch')
    require(text_git(repo,'merge-base',base,head)==base,'candidate not descended from baseline')
    require(git(repo,'diff','--no-ext-diff','--no-textconv','--name-only','-z',base,head)==(TARGET+'\0').encode(),'scope mismatch')
    require(git(repo,'ls-tree',head,'--',TARGET).startswith(b'100644 blob '),'not regular blob')
    source=git(repo,'show',f'{head}:{TARGET}');require(len(source)<=65536,'candidate too large')
    return source.decode(),text_git(repo,'rev-parse',head+'^{tree}')

def scope(repo,previous,observation):
    p=repo/TARGET
    return (text_git(repo,'rev-parse','HEAD')==previous and observation['before']['head']==previous and observation['after']['head']==previous and git(repo,'status','--porcelain=v1','-z','--untracked-files=all','--ignored') in (b'',(' M '+TARGET+'\0').encode()) and p.is_file() and not p.is_symlink() and not p.parent.is_symlink())

def verify_candidate(repo,base,head,executor):
    source,tree=candidate(repo,base,head)
    require(structural(source,SCENARIO),'intent mismatch')
    return {'base':base,'head':head,'tree':tree,'source_digest':hashlib.sha256(source.encode()).hexdigest(),'scenario_digest':digest(SCENARIO),'verification':evaluate(source,SCENARIO,executor)}

def run(out,provider,limits,*,fixture=None,image='python:3.11-slim',agent=run_agent):
    """Agents run before signing keys are generated. No key or GitHub calls here."""
    require(provider in ('claude','codex'),'unknown provider');require(fixture in (None,'first','repair','repeat','budget','scope'),'unknown fixture')
    out.mkdir(parents=True,exist_ok=False);repo=out/'repo';base=setup(repo);previous=base;controller=BudgetController(limits);start=time.monotonic();rows=[];final=None
    executor=Executor('local' if fixture else 'docker',image=image,timeout=15)
    status='STOP_ERROR';error=None
    try:
        while controller.admit():
            i=len(rows)+1;remaining=limits.elapsed_ms-int((time.monotonic()-start)*1000)
            if remaining<1000:status='STOP_BUDGET';break
            prompt=out/f'prompt-{i}.txt';feedback=''
            if rows and rows[-1]['verification']:
                v0=rows[-1]['verification']['verification'];feedback=f' Prior independent verification passed {v0["passed_cases"]} of {v0["cases"]} cases; reconsider the implementation against the stated requirements.'
            prompt.write_text('Modify only app/solution.py. '+SCENARIO['prompt']+' Preserve signature. No new imports. Do not stage, commit or access other repositories.'+feedback)
            if fixture:
                if fixture=='scope':(repo/'unexpected.txt').write_text('synthetic')
                (repo/TARGET).write_text(SCENARIO['fixed'] if fixture in ('first','budget','scope') or (fixture=='repair' and i>1) else SCENARIO['base']+'\n# incomplete implementation\n')
                usage={'input_tokens':100,'output_tokens':20,'cache_creation_input_tokens':0,'cache_read_input_tokens':0,'cached_input_tokens':0}
                obs={'before':{'head':previous},'after':{'head':previous},'session':{'telemetry':usage},'trust':'synthetic_fixture'}
            else:
                obs=agent(provider,repo,prompt,out/f'observation-{i}.json',timeout=min(300,remaining//1000));usage=obs.get('session',{}).get('telemetry')
            valid=scope(repo,previous,obs);v=None;tree='scope-invalid';head=previous
            if valid:
                git(repo,'add','--',TARGET)
                if git(repo,'diff','--cached','--name-only'):git(repo,'commit','-m',f'candidate {i}')
                head=text_git(repo,'rev-parse','HEAD');tree=text_git(repo,'rev-parse',head+'^{tree}')
                if head==base:
                    v={'base':base,'head':head,'tree':tree,'verification':{'passed':False,'structural_passed':True,'cases':0,'passed_cases':0}}
                else:
                    source,_=candidate(repo,base,head)
                    if not structural(source,SCENARIO):valid=False
                    else:
                        if fixture:require(source in (SCENARIO['fixed'],SCENARIO['base']+'\n# incomplete implementation\n'),'untrusted local candidate')
                        v=verify_candidate(repo,base,head,executor)
                previous=head
            elapsed=max(0,int((time.monotonic()-start)*1000)-controller.elapsed)
            row=controller.record(provider=provider,telemetry=usage,elapsed_ms=elapsed,tree=tree,passed=bool(v and v['verification']['passed']),scope_valid=valid)
            status=row['state'];row.update({'head':head,'base':base,'scope_valid':valid,'verification':v,'observation_digest':digest(obs),'telemetry_trust':'synthetic' if fixture else 'self_reported'});rows.append(row)
            with (out/'attempts.jsonl').open('a') as f:f.write(json.dumps(row)+'\n');f.flush()
            if status=='PASSED':final=head
            if status!='READY':break
    except Exception as e:error=type(e).__name__;status='STOP_ERROR';final=None
    report={'profile':PROFILE,'mode':'synthetic_fixture' if fixture else 'live','fixture':fixture,'provider':provider,'base':base,'head':final,'status':status,'attempts':rows,'limits':vars(limits),'error_type':error,'merge_authority':False,'production_ready':False,'executor':executor.metadata()}
    (out/'convergence.json').write_text(json.dumps(report,indent=2));return report

def attest(repo,report,executor,key,now=None):
    """Re-evaluate the exact candidate; never sign a claim of human approval."""
    require(report['profile']==PROFILE and report['status']=='PASSED' and report['merge_authority'] is False,'candidate not converged')
    require(report['mode'] in ('live','synthetic_fixture') and (executor.backend=='docker' or report['mode']=='synthetic_fixture'),'live verification requires Docker')
    if executor.backend=='local':require(git(repo,'show',f"{report['head']}:{TARGET}").decode()==SCENARIO['fixed'],'local execution restricted to exact trusted reference')
    observed=verify_candidate(repo,report['base'],report['head'],executor)
    last=report['attempts'][-1]; prior=last['verification']
    require(last['state']=='PASSED' and last['scope_valid'] is True and all(prior[k]==observed[k] for k in ('base','head','tree','source_digest','scenario_digest')) and last['tree']==observed['tree'],'convergence candidate mismatch')
    now=int(time.time()) if now is None else now
    s={'profile':PROFILE,'control':'verification','base':observed['base'],'head':observed['head'],'tree':observed['tree'],'artifact_digest':digest(observed),'convergence_digest':digest(report),'issued_at':now,'expires_at':now+60,'passed':observed['verification']['passed'],'merge_authority':False}
    return {'statement':s,'artifact':observed,'signature':sign(key,DOMAIN,s)}

def check_receipt(receipt,pub,report,now):
    s=receipt['statement'];a=receipt['artifact'];verify_sig(pub,DOMAIN,s,receipt['signature']);require(s['profile']==PROFILE and s['control']=='verification' and s['merge_authority'] is False and s['convergence_digest']==digest(report),'wrong profile or report');require(s['head']==report['head']==a['head'] and s['base']==report['base']==a['base'] and s['tree']==a['tree'] and s['artifact_digest']==digest(a),'candidate binding');require(type(s['issued_at']) is int and type(s['expires_at']) is int and s['issued_at']<=now<s['expires_at']<=s['issued_at']+60,'expired receipt');require(s['passed'] is True and a['verification']['passed'] is True,'failed verification');return True

def decision(receipt,pub,report,now):
    try:check_receipt(receipt,pub,report,now);verified=True
    except Exception:verified=False
    return {'profile':PROFILE,'candidate_verified':verified,'decision':'BLOCK','reasons':([] if verified else ['verification_missing_or_invalid'])+['independent_human_approval_missing','external_control_inventory_missing'],'merge_authority':False,'production_ready':False}

class Lifecycle:
    """Single-candidate local journal. Explicit denials are permanent per binding.

    Version 2 rejects old journals: a missing event history cannot be reconstructed.
    Snapshot and HMAC trust are caller-owned; not a remote authorization service.
    """
    def __init__(self,path):
        self.db=sqlite3.connect(path);self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        try:
            version=self.db.execute('PRAGMA user_version').fetchone()[0]
            tables=self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            if version==0 and not tables:
                self.db.executescript("BEGIN IMMEDIATE; CREATE TABLE readiness(id TEXT PRIMARY KEY, head TEXT, base TEXT, expires INTEGER, state TEXT, reason TEXT); CREATE TABLE events(id TEXT PRIMARY KEY, digest TEXT); CREATE TABLE denials(head TEXT, base TEXT, reason TEXT, PRIMARY KEY(head,base)); CREATE TABLE snapshot(id INTEGER PRIMARY KEY CHECK(id=1),head TEXT,base TEXT,at INTEGER); CREATE TABLE pending_binding(id INTEGER PRIMARY KEY CHECK(id=1),at INTEGER); PRAGMA user_version=2; COMMIT;")
            else:require(version==2,'unsupported journal version; archive and start fresh')
        except Exception:self.db.close();raise
    def close(self):self.db.close()
    def register(self,receipt,pub,report,now):
        check_receipt(receipt,pub,report,now);s=receipt['statement'];i=digest(s)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            denial=self.db.execute('SELECT reason FROM denials WHERE head=? AND base=?',(s['head'],s['base'])).fetchone()
            snap=self.db.execute('SELECT head,base,at FROM snapshot WHERE id=1').fetchone()
            pending=self.db.execute('SELECT at FROM pending_binding WHERE id=1').fetchone()
            reason=denial[0] if denial else ('binding_changed' if pending or (snap and (s['head'],s['base'])!=snap[:2]) else None)
            require(not snap or now>=snap[2],'clock older than snapshot')
            self.db.execute('INSERT OR IGNORE INTO readiness VALUES(?,?,?,?,?,?)',(i,s['head'],s['base'],s['expires_at'],'REVOKED' if reason else 'CURRENT',reason))
        return i
    def state(self,i):
        r=self.db.execute('SELECT state,reason FROM readiness WHERE id=?',(i,)).fetchone();require(r is not None,'unknown readiness');return {'state':r[0],'reason':r[1],'merge_authority':False}
    def reconcile(self,head,base,now):
        require(all(isinstance(s,str) and SHA.fullmatch(s) for s in (head,base)) and type(now) is int,'invalid snapshot')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            old=self.db.execute('SELECT head,base,at FROM snapshot WHERE id=1').fetchone()
            require(not old or now>old[2] or (now==old[2] and (head,base)==old[:2]),'stale or conflicting snapshot')
            self.db.execute('INSERT OR REPLACE INTO snapshot VALUES(1,?,?,?)',(head,base,now))
            self.db.execute('DELETE FROM pending_binding WHERE at<?',(now,))
            self.db.execute("UPDATE readiness SET state='REVOKED',reason='expired' WHERE state='CURRENT' AND expires<=?",(now,))
            self.db.execute("UPDATE readiness SET state='REVOKED',reason='binding_changed' WHERE state='CURRENT' AND (head!=? OR base!=?)",(head,base))
    def event(self,raw,signature,secret):
        require(isinstance(raw,bytes) and len(raw)<=4096 and isinstance(secret,bytes) and len(secret)>=32,'invalid event');require(isinstance(signature,str) and hmac.compare_digest(signature,hmac.new(secret,raw,hashlib.sha256).hexdigest()),'invalid HMAC')
        def unique(pairs):
            d={}
            for k,v in pairs:
                require(k not in d,'duplicate JSON key');d[k]=v
            return d
        e=json.loads(raw,object_pairs_hook=unique);require(isinstance(e,dict) and set(e)=={'id','kind','head','base','at'} and isinstance(e['id'],str) and re.fullmatch(r'[A-Za-z0-9-]{1,80}',e['id']) and e['kind'] in ('binding_changed','review_withdrawn','circuit_open') and all(isinstance(e[k],str) and SHA.fullmatch(e[k]) for k in ('head','base')) and type(e['at']) is int,'invalid event payload');d=hashlib.sha256(raw).hexdigest()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE');old=self.db.execute('SELECT digest FROM events WHERE id=?',(e['id'],)).fetchone()
            if old:require(old[0]==d,'conflicting delivery');return 'DUPLICATE'
            self.db.execute('INSERT INTO events VALUES(?,?)',(e['id'],d))
            if e['kind']=='binding_changed':
                # Event is a denial hint, not an authoritative fresh snapshot.
                # Invalidate known incompatible bindings; trusted reconcile is
                # still required before admitting a new current binding.
                self.db.execute('INSERT INTO pending_binding VALUES(1,?) ON CONFLICT(id) DO UPDATE SET at=max(at,excluded.at)',(e['at'],))
                self.db.execute("INSERT OR IGNORE INTO denials SELECT DISTINCT head,base,? FROM readiness WHERE (head!=? OR base!=?)",(e['kind'],e['head'],e['base']))
                self.db.execute("UPDATE readiness SET state='REVOKED',reason=? WHERE state='CURRENT' AND (head!=? OR base!=?)",(e['kind'],e['head'],e['base']))
            else:
                self.db.execute('INSERT OR IGNORE INTO denials VALUES(?,?,?)',(e['head'],e['base'],e['kind']))
                self.db.execute("UPDATE readiness SET state='REVOKED',reason=? WHERE state='CURRENT' AND head=? AND base=?",(e['kind'],e['head'],e['base']))
        return 'APPLIED'
    def checkpoint(self):
        """Logical snapshot digest, not an autonomous integrity guarantee.

        Pin the latest digest externally; local rollback including the pin is
        otherwise undetectable. All rows are read in one SQLite transaction.
        """
        with self.db:
            self.db.execute('BEGIN')
            body={'profile':'itm-readiness-checkpoint-v2','tables':{t:self.db.execute(f'SELECT * FROM {t} ORDER BY '+order).fetchall() for t,order in [('readiness','id'),('events','id'),('denials','head,base'),('snapshot','id'),('pending_binding','id')]}}
            return digest(body)
    def verify_checkpoint(self,expected):
        require(isinstance(expected,str) and HEX.fullmatch(expected) and hmac.compare_digest(self.checkpoint(),expected),'journal checkpoint mismatch')
        return True
