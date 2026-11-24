"""Multi-repository coordination for trusted, local bare Git fixtures.
No remote merge authority. Contracts are explicit declarations, not behavioral proofs.
"""
from __future__ import annotations
import json, re, subprocess, fnmatch
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .core import canonical, digest, Ledger, verify_chain


def require(ok, message):
    if not ok: raise ValueError(message)


def identifier(value):
    return isinstance(value,str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',value) is not None


def hexstr(value, size):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{'+str(size)+'}',value) is not None


def order(config):
    require(set(config)=={'version','profile','intent_id','components','executor_key'},'invalid config fields')
    require(config['version']==1 and config['profile']=='local-synthetic' and identifier(config['intent_id']),'invalid configuration')
    comps=config['components']; require(isinstance(comps,dict) and 1<=len(comps)<=32,'invalid components')
    keys=[config['executor_key']]
    for name,c in comps.items():
        require(identifier(name) and set(c)=={'depends_on','allowed_paths','reviewer_key'},'invalid component')
        deps=c['depends_on']; require(isinstance(deps,list) and len(set(deps))==len(deps) and all(d in comps and d!=name for d in deps),'invalid dependencies')
        paths=c['allowed_paths']; require(isinstance(paths,list) and bool(paths) and all(isinstance(p,str) and p and not p.startswith('/') and '..' not in p.split('/') for p in paths),'invalid path policy')
        keys.append(c['reviewer_key'])
    require(all(hexstr(k,64) for k in keys) and len(set(keys))==len(keys),'independent role keys required')
    pending=set(comps); result=[]
    while pending:
        ready=sorted(n for n in pending if set(comps[n]['depends_on'])<=set(result))
        require(bool(ready),'dependency cycle'); result.extend(ready); pending.difference_update(ready)
    return result


def git(repo,*args,check=True):
    result=subprocess.run(['git','-c','core.hooksPath=/dev/null','--git-dir',str(repo),*args],capture_output=True,timeout=15)
    if check and result.returncode: raise ValueError('local Git operation failed: '+args[0])
    return result


def repos_checked(config,repos):
    require(set(repos)==set(config['components']),'repository mapping mismatch')
    resolved={n:Path(p).resolve(strict=True) for n,p in repos.items()}
    require(len(set(resolved.values()))==len(resolved),'repository aliases prohibited')
    for p in resolved.values():
        require(git(p,'rev-parse','--is-bare-repository').stdout.strip()==b'true','only local bare repositories supported')
    return resolved


def ref(repo,name):
    value=git(repo,'rev-parse','--verify',name).stdout.decode().strip()
    require(hexstr(value,40),'expected SHA-1 fixture commit'); return value


def contract(value, deps):
    require(isinstance(value,dict) and set(value)=={'provides','requires'},'invalid contract schema')
    provides=value['provides']; requires=value['requires']
    require(isinstance(provides,list) and 1<=len(provides)<=32 and all(identifier(v) for v in provides) and len(set(provides))==len(provides),'invalid provided versions')
    require(isinstance(requires,dict) and set(requires)==set(deps) and all(identifier(v) for v in requires.values()),'contract dependencies differ from policy')
    return {'provides':sorted(provides),'requires':requires}


def read_contract(repo,sha,deps):
    raw=git(repo,'show',sha+':contract.json').stdout
    require(len(raw)<=65536,'contract too large'); return contract(json.loads(raw),deps)


def compatibility(state):
    return [f'{name}:requires:{provider}:{version}' for name,c in sorted(state.items()) for provider,version in sorted(c['requires'].items()) if version not in state[provider]['provides']]


def derive(config, components):
    sequence=order(config); require(set(components)==set(sequence),'component inventory mismatch')
    issues=[]; state={}
    for n in sequence:
        c=components[n]; policy=config['components'][n]
        require(set(c)=={'base','head','base_contract','head_contract','paths','fast_forward'},'invalid candidate evidence')
        require(hexstr(c['base'],40) and hexstr(c['head'],40) and c['base']!=c['head'],'invalid commit binding')
        require(type(c['fast_forward']) is bool and isinstance(c['paths'],list) and all(isinstance(p,str) and p for p in c['paths']) and c['paths']==sorted(set(c['paths'])),'invalid diff evidence')
        for k in ('base_contract','head_contract'): require(c[k]==contract(c[k],policy['depends_on']),'noncanonical contract')
        state[n]=c['base_contract']
        if not c['fast_forward']: issues.append(n+':not_fast_forward')
        if not c['paths']: issues.append(n+':empty_change')
        for p in c['paths']:
            if not any(fnmatch.fnmatchcase(p,g) for g in policy['allowed_paths']): issues.append(n+':out_of_scope:'+p)
    stages=[{'after':None,'violations':compatibility(state)}]
    for n in sequence:
        state[n]=components[n]['head_contract']; stages.append({'after':n,'violations':compatibility(state)})
    for stage in stages:
        issues.extend(f'prefix:{stage["after"] or "base"}:{v}' for v in stage['violations'])
    return {'version':1,'config_digest':digest(config),'intent_id':config['intent_id'],'components':components,'order':sequence,'stages':stages,'issues':issues,'eligible':not issues,'merge_authority':False}


def plan(config,repos):
    order(config); repos=repos_checked(config,repos); components={}
    for n,p in repos.items():
        b,h=ref(p,'refs/heads/main'),ref(p,'refs/heads/candidate'); deps=config['components'][n]['depends_on']
        raw=git(p,'diff','--no-renames','--name-only','-z',b,h,'--').stdout
        components[n]={'base':b,'head':h,'base_contract':read_contract(p,b,deps),'head_contract':read_contract(p,h,deps),'paths':sorted(set(x.decode('utf-8') for x in raw.split(b'\0') if x)), 'fast_forward':git(p,'merge-base','--is-ancestor',b,h,check=False).returncode==0}
    return derive(config,components)


def sign(kind,body,key):
    return key.sign(b'ITM-CHANGESET-V1\0'+kind.encode()+b'\0'+canonical(body)).hex()


def verify_sig(kind,body,sig,key):
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(sig),b'ITM-CHANGESET-V1\0'+kind.encode()+b'\0'+canonical(body))
    except (InvalidSignature,ValueError,TypeError) as e: raise ValueError('invalid '+kind+' signature') from e


def approve(config,p,component,key):
    body={'component':component,'plan_digest':digest(p),'config_digest':digest(config)}
    return {**body,'signature':sign('approval',body,key)}


def verify_plan(config,p,approvals):
    require(p==derive(config,p['components']),'plan derivation mismatch')
    require(p['eligible'],'change set blocked by plan')
    seen=set()
    for a in approvals:
        n=a['component']; require(n in config['components'] and n not in seen,'unexpected or duplicate approval')
        body={'component':n,'plan_digest':digest(p),'config_digest':digest(config)}
        require(set(a)==set(body)|{'signature'} and all(a[k]==v for k,v in body.items()),'approval binding mismatch')
        verify_sig('approval',body,a['signature'],config['components'][n]['reviewer_key']); seen.add(n)
    require(seen==set(config['components']),'missing component approval')


def execute(config,p,approvals,repos,key,*,fault=None):
    """Sequential local CAS updates. Fault hook is only for trusted test fixtures."""
    verify_plan(config,p,approvals); repos=repos_checked(config,repos)
    require(plan(config,repos)==p,'stale plan or candidate')
    # Validate signer before any side effect.
    probe={'config_digest':digest(config)}; verify_sig('probe',probe,sign('probe',probe,key),config['executor_key'])
    expected={n:c['base'] for n,c in p['components'].items()}; completed=[]; ledger=Ledger()
    def snapshot(): return {n:ref(repo,'refs/heads/main') for n,repo in repos.items()}
    def record(kind,**data): ledger.add(kind,**data)
    record('start',refs=snapshot()); failed=False
    for n in p['order']:
        try:
            if fault: fault('before_merge',n,repos)
            before=snapshot()
            require(before==expected,'ref drift before merge')
            c=p['components'][n]
            require(ref(repos[n],'refs/heads/candidate')==c['head'],'candidate drift')
            result=git(repos[n],'update-ref','refs/heads/main',c['head'],c['base'],check=False)
            require(result.returncode==0,'merge CAS failed')
        except (ValueError,OSError,subprocess.SubprocessError) as exc:
            record('merge_failed',component=n,reason=str(exc),refs=snapshot()); failed=True; break
        completed.append(n); expected[n]=c['head']; record('merged',component=n,refs=snapshot())
    status='COMPLETED'
    if failed:
        status='COMPENSATED' if completed else 'ABORTED'
        for n in reversed(completed):
            try:
                if fault: fault('before_compensate',n,repos)
                require(snapshot()==expected,'ref drift before compensation')
                c=p['components'][n]
                require(git(repos[n],'update-ref','refs/heads/main',c['base'],c['head'],check=False).returncode==0,'compensation CAS failed')
            except (ValueError,OSError,subprocess.SubprocessError) as exc:
                record('compensation_failed',component=n,reason=str(exc),refs=snapshot()); status='MANUAL_INTERVENTION'; break
            expected[n]=c['base']; record('compensated',component=n,refs=snapshot())
    final=snapshot()
    if final!=expected: status='MANUAL_INTERVENTION'
    record('finish',status=status,refs=final)
    body={'version':1,'config_digest':digest(config),'plan':p,'approvals':approvals,'events':ledger.events,'status':status,'merge_authority':False}
    return {**body,'signature':sign('receipt',body,key)}


def verify_receipt(config,receipt,expected_config_digest):
    require(digest(config)==expected_config_digest,'external config digest mismatch')
    require(set(receipt)=={'version','config_digest','plan','approvals','events','status','merge_authority','signature'},'invalid receipt fields')
    body={k:v for k,v in receipt.items() if k!='signature'}
    verify_sig('receipt',body,receipt['signature'],config['executor_key'])
    require(receipt['version']==1 and receipt['config_digest']==digest(config) and receipt['merge_authority'] is False,'receipt scope mismatch')
    p=receipt['plan']; verify_plan(config,p,receipt['approvals']); events=receipt['events']; root=verify_chain(events)
    expected={n:c['base'] for n,c in p['components'].items()}; completed=[]; failed=False; conflict=False
    require(events[0]['kind']=='start' and events[0]['payload']=={'refs':expected},'invalid start')
    for e in events[1:-1]:
        k=e['kind']; d=e['payload']; n=d.get('component')
        require(not conflict,'event after compensation conflict')
        if k=='merged':
            require(not failed and len(completed)<len(p['order']) and n==p['order'][len(completed)],'invalid merge sequence')
            expected[n]=p['components'][n]['head']; completed.append(n)
            require(d['refs']==expected,'merge observation mismatch')
        elif k=='merge_failed':
            require(not failed and len(completed)<len(p['order']) and n==p['order'][len(completed)],'invalid failure sequence'); failed=True
        elif k=='compensated':
            require(failed and completed and n==completed[-1],'invalid compensation sequence'); completed.pop(); expected[n]=p['components'][n]['base']
            require(d['refs']==expected,'compensation observation mismatch')
        elif k=='compensation_failed':
            require(failed and completed and n==completed[-1],'invalid compensation failure'); conflict=True
        else: raise ValueError('unexpected execution event')
    end=events[-1]; require(end['kind']=='finish' and end['payload']['status']==receipt['status'],'invalid terminal event')
    if conflict or end['payload']['refs']!=expected: status='MANUAL_INTERVENTION'
    elif failed: status='COMPENSATED' if any(e['kind']=='compensated' for e in events) else 'ABORTED'
    else: require(completed==p['order'],'incomplete success'); status='COMPLETED'
    require(status==receipt['status'] and (status=='MANUAL_INTERVENTION' or not failed or not completed),'terminal state mismatch')
    return {'integrity':'verified','execution_replay':'verified','status':status,'ledger_root':root,'merge_authority':False,'profile':config['profile']}
