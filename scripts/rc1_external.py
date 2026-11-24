#!/usr/bin/env python3
"""Opt-in external qualification probes; no merge or GitHub write operations.

Run agent probes in an isolated disposable environment without unrelated secrets.
The Docker test is a smoke test, not a hostile-code security certification.
"""
import argparse, hashlib, json, shutil, subprocess, tempfile
from pathlib import Path
from intent_merge.capture import run_agent
from intent_merge.fixtures import BASE, FIXED, DRIFTED
from intent_merge.github import policy_from, preflight
from intent_merge.operational import installation_client
from intent_merge.hardening import verify_payment_candidate
from intent_merge.core import load_config

ROOT=Path(__file__).resolve().parents[1]
PROBE_BUILD="rc1-workspace-diagnostics-v3"

def git(repo,*args):
    return subprocess.run(['git','-C',str(repo),*args],check=True,capture_output=True,text=True,timeout=30).stdout.strip()

def init(repo):
    repo.mkdir(); git(repo,'init','-b','main');git(repo,'config','user.name','ITM qualification');git(repo,'config','user.email','rc@example.invalid')
    (repo/'app').mkdir();(repo/'app/payments.py').write_text(BASE);git(repo,'add','app/payments.py');git(repo,'commit','-m','baseline');return git(repo,'rev-parse','HEAD')

def exact(repo,base,temp,image):
    bare=temp/'candidate.git';subprocess.run(['git','clone','--bare',str(repo),str(bare)],check=True,capture_output=True,timeout=30)
    return verify_payment_candidate(bare,base,git(repo,'rev-parse','HEAD'),load_config(ROOT/'examples/spec.toml'),backend='docker',image=image)

def docker_probe(image):
    with tempfile.TemporaryDirectory(prefix='itm-rc-docker-') as t:
        temp=Path(t);repo=temp/'repo';base=init(repo)
        results=[]
        for code,expected in [(FIXED,True),(DRIFTED,False)]:
            (repo/'app/payments.py').write_text(code);git(repo,'commit','-am','candidate');r=exact(repo,base,temp,image);shutil.rmtree(temp/'candidate.git')
            results.append({'expected':expected,'observed':r['passed'],'cases':len(r['verification']['outcomes']),'executor':r['executor']})
        return {'status':'PASS' if all(r['expected']==r['observed'] and r['cases']==37 and r['executor']['backend']=='docker' for r in results) else 'FAIL','results':results,'scope':'trusted fixture smoke test'}

def workspace_diagnostics(repo,base,observation):
    head_before_status=git(repo,'rev-parse','HEAD')
    status_raw=subprocess.check_output(['git','-C',str(repo),'status','--porcelain=v1','-z','--untracked-files=all'],timeout=30)
    head_after_status=git(repo,'rev-parse','HEAD')
    target=repo/'app/payments.py'
    heads={'expected_base':base,'observed_before':observation['before']['head'],'observed_after':observation['after']['head'],'head_before_status':head_before_status,'head_after_status':head_after_status}
    head_changed=any(value!=base for value in heads.values())
    scope_valid=status_raw==b' M app/payments.py\x00'
    diagnostics={**heads,'head_changed':head_changed,'workspace_status':status_raw.decode('utf-8',errors='backslashreplace').replace('\x00','\n'),'scope_valid':scope_valid,'target_is_symlink':target.is_symlink(),'target_is_regular_file':target.is_file() and not target.is_symlink(),'reflog':git(repo,'reflog','-5','--format=%H'),'observation':observation}
    return diagnostics

def agent_probe(provider,image,timeout):
    # The caller explicitly opts in to model execution and possible provider charges.
    # No real project source is sent. No secrets from ITM are needed by the agent.
    with tempfile.TemporaryDirectory(prefix='itm-rc-agent-') as t:
        temp=Path(t);repo=temp/'repo';base=init(repo)
        prompt=temp/'spec.txt';prompt.write_text('Modify only app/payments.py. '+load_config(ROOT/'examples/spec.toml')['intent']+' Reject conflicting payloads for an existing key. Preserve authorize, register signature, and imports. Do not commit or access network/other repositories. Keep all modifications in this workspace.')
        observation=run_agent(provider,repo,prompt,temp/'observation.json',timeout=timeout)
        # Do not stage arbitrary paths or execute candidate code on the host.
        diagnostics=workspace_diagnostics(repo,base,observation)
        if diagnostics['head_changed'] or not diagnostics['scope_valid'] or not diagnostics['target_is_regular_file']:
            return {'status':'FAIL','reason':'unexpected workspace changes','provider':provider,'diagnostics':diagnostics,'merge_authority':False}
        git(repo,'add','--','app/payments.py');git(repo,'commit','-m','qualification candidate');r=exact(repo,base,temp,image)
        return {'status':'PASS' if r['passed'] else 'FAIL','provider':provider,'observation':observation,'diagnostics':diagnostics,'exact_verification':r,'merge_authority':False,'scope':'single synthetic task; no benchmark claim'}

def github_probe(args):
    policy=policy_from(args.policy)
    # Use the existing GitHub App authentication path (token exchange only).
    client=installation_client(args.app_id,args.installation,args.app_key,policy['repository'])
    result=preflight(client,policy['repository'],args.pr,policy,publish=False)
    return {'status':'PASS' if result['decision']==args.expect else 'FAIL','expected':args.expect,'observed':result['decision'],'head':result['head'],'base':result['base'],'gates':result['gates'],'scope':'authenticated read-only PR preflight; no check publication or merge queue enforcement','merge_authority':False}

def self_test():
    results={}
    for name in ('allowed_edit','extra_file','staged_edit','changed_head','wrong_observed_head'):
        with tempfile.TemporaryDirectory(prefix='itm-self-test-') as t:
            repo=Path(t)/'repo';base=init(repo)
            target=repo/'app/payments.py';target.write_text(FIXED)
            if name=='extra_file': (repo/'extra.txt').write_text('unexpected')
            if name=='staged_edit': git(repo,'add','app/payments.py')
            if name=='changed_head': git(repo,'commit','--allow-empty','-m','unexpected')
            observation={'before':{'head':base},'after':{'head':git(repo,'rev-parse','HEAD')}}
            if name=='wrong_observed_head': observation['after']['head']='0'*40
            d=workspace_diagnostics(repo,base,observation)
            allowed=not d['head_changed'] and d['scope_valid'] and d['target_is_regular_file']
            results[name]='PASS' if allowed==(name=='allowed_edit') else 'FAIL'
    print(json.dumps({'probe_build':PROBE_BUILD,'script_path':str(Path(__file__).resolve()),'self_test':results},indent=2))
    return int(any(v!='PASS' for v in results.values()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--self-test',action='store_true');p.add_argument('--out',type=Path);p.add_argument('--image',default='python:3.11-slim');p.add_argument('--docker',action='store_true');p.add_argument('--agent',choices=['claude','codex'],action='append',default=[]);p.add_argument('--allow-agent-execution',action='store_true');p.add_argument('--timeout',type=int,default=300);p.add_argument('--policy',type=Path);p.add_argument('--pr',type=int);p.add_argument('--app-id',type=int);p.add_argument('--installation',type=int);p.add_argument('--app-key',type=Path);p.add_argument('--expect',choices=['PASS','BLOCK']);a=p.parse_args()
    if a.self_test:
        if a.agent or a.docker or a.policy or a.out: p.error('self-test is standalone')
        return self_test()
    if a.out is None:p.error('--out is required for external probes')
    if a.out.exists():p.error('output must not exist')
    if a.agent and not a.allow_agent_execution:p.error('agent execution requires explicit opt-in; may incur provider charges')
    gh=[a.policy,a.pr,a.app_id,a.installation,a.app_key,a.expect]
    if any(x is not None for x in gh) and not all(x is not None for x in gh):p.error('all GitHub App and expectation arguments required')
    probes={}
    def execute(name,enabled,fn):
        if not enabled:probes[name]={'status':'NOT_RUN'};return
        try:probes[name]=fn()
        except Exception as e:probes[name]={'status':'FAIL','error_type':type(e).__name__} # no raw secrets or subprocess logs
    execute('docker',a.docker,lambda:docker_probe(a.image))
    for provider in ('claude','codex'):execute(provider,provider in a.agent,lambda provider=provider:agent_probe(provider,a.image,a.timeout))
    execute('github_app_preflight',all(x is not None for x in gh),lambda:github_probe(a))
    result={'probe_build':PROBE_BUILD,'script_path':str(Path(__file__).resolve()),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'release':'1.0.0-rc.3','profile':'external-qualification-probes','production_ready':False,'probes':probes,'remaining':['merge_group enforcement','live independent control services','hostile-code isolation','authenticated publication/revocation and merge-queue lifecycle','live comparative benchmark']}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    with a.out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({k:v['status'] for k,v in probes.items()}))
    return int(any(v['status']=='FAIL' for v in probes.values()))

if __name__=='__main__':raise SystemExit(main())
