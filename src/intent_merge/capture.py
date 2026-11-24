"""Local agent runner and metadata-only hook. Never grants merge authority."""
from __future__ import annotations
import hashlib, json, os, subprocess, tempfile, signal, shutil
from pathlib import Path
from .agent_import import import_agent, MAX_BYTES
from .core import digest

def git(repo,*args):
    return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL,timeout=20)

def snapshot(repo):
    head=git(repo,'rev-parse','HEAD').decode().strip()
    status=git(repo,'status','--porcelain=v1','-z','--untracked-files=all')
    diff=git(repo,'diff','--binary','HEAD','--')
    return {'head':head,'tracked_diff_sha256':hashlib.sha256(diff).hexdigest(),'status_sha256':hashlib.sha256(status).hexdigest(),'clean':not status,'untracked_content_attested':False}

def command(provider,prompt):
    if provider=='claude':return ['claude','-p',prompt,'--output-format','stream-json','--verbose','--permission-mode','acceptEdits','--tools','Read,Edit,Write,Glob,Grep']
    if provider=='codex':return ['codex','exec','--json','--sandbox','workspace-write',prompt]
    raise ValueError('unsupported provider')

def run_agent(provider,repo,prompt_path,output,timeout=300):
    repo=Path(repo).resolve(); output=Path(output).resolve(); prompt_path=Path(prompt_path).resolve()
    if output.is_relative_to(repo) or prompt_path.is_relative_to(repo) or output.exists():raise ValueError('prompt/output must be outside workspace; output must be new')
    if not 1<=timeout<=1800 or prompt_path.stat().st_size>65536:raise ValueError('invalid run limits')
    if not shutil.which(command(provider,'')[0]):raise ValueError('agent CLI not installed')
    before=snapshot(repo)
    if not before['clean']:raise ValueError('start from a clean dedicated workspace')
    # This is a developer-side process, not an isolation boundary. Strip ITM service secrets.
    env={k:v for k,v in os.environ.items() if not k.startswith('ITM_') and k not in {'APP_KEY','APP_ID','INSTALLATION_ID','GITHUB_TOKEN','GH_TOKEN'}}
    with tempfile.TemporaryDirectory() as temp:
        raw=Path(temp)/'session.jsonl'
        with raw.open('wb') as out:
            p=subprocess.Popen(command(provider,prompt_path.read_text()),cwd=repo,env=env,stdout=out,stderr=subprocess.DEVNULL,start_new_session=True)
            import time
            end=time.monotonic()+timeout
            try:
                while p.poll() is None:
                    if time.monotonic()>=end or raw.stat().st_size>MAX_BYTES:raise ValueError('agent execution limit exceeded')
                    time.sleep(.1)
                if p.returncode:raise ValueError('agent CLI failed')
            finally:
                if p.poll() is None:
                    os.killpg(p.pid,signal.SIGKILL); p.wait()
        after=snapshot(repo); metadata=import_agent(provider,raw,head=after['head'])
    result={'schema_version':1,'profile':'local-agent-observation','before':before,'after':after,'session':metadata,'binding':'local_observation_not_attestation','merge_authority':False}
    with output.open('x') as f:json.dump(result,f,indent=2)
    return result

def hook(provider,payload,repo):
    if provider not in ('claude','codex') or not isinstance(payload,dict):raise ValueError('invalid hook')
    name=payload.get('hook_event_name'); sid=payload.get('session_id') or payload.get('thread_id')
    if name not in ('SessionStart','SessionEnd','Stop') or not isinstance(sid,str) or not sid or len(sid)>1024:raise ValueError('unsupported hook event')
    return {'schema_version':1,'provider':provider,'event':name,'session_digest':digest(sid),'git':snapshot(repo),'trust':'local_observation','merge_authority':False}
