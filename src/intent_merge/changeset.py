"""Multi-repository coordination for trusted, local bare Git fixtures.
No remote merge authority. Contracts are explicit declarations, not behavioral proofs.
"""
from __future__ import annotations
import json, re, subprocess
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .core import canonical, digest, Ledger, verify_chain
from .path_policy import LEGACY_V1, SEGMENT_V2, matches, validate_patterns


def require(ok, message):
    if not ok: raise ValueError(message)


def identifier(value):
    return isinstance(value,str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',value) is not None


def hexstr(value, size):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{'+str(size)+'}',value) is not None


def _semantics(config, *, historical=False):
    require(isinstance(config, dict) and type(config.get('version')) is int, 'invalid config version')
    fields = {'version', 'profile', 'intent_id', 'components', 'executor_key'}
    if config['version'] == 1 and historical:
        require(set(config) == fields, 'invalid historical config fields')
        return LEGACY_V1
    require(config['version'] == 2, 'changeset v1 is historical replay only')
    require(set(config) == fields | {'path_semantics'}, 'invalid config fields')
    require(config['path_semantics'] == SEGMENT_V2, 'invalid changeset path semantics')
    return SEGMENT_V2


def order(config, *, historical=False):
    semantics = _semantics(config, historical=historical)
    require(config['profile']=='local-synthetic' and identifier(config['intent_id']),'invalid configuration')
    comps=config['components']; require(isinstance(comps,dict) and 1<=len(comps)<=32,'invalid components')
    keys=[config['executor_key']]
    for name,c in comps.items():
        require(identifier(name) and isinstance(c, dict) and set(c)=={'depends_on','allowed_paths','reviewer_key'},'invalid component')
        deps=c['depends_on']; require(isinstance(deps, list) and all(isinstance(d, str) and d in comps and d != name for d in deps) and len(set(deps)) == len(deps),'invalid dependencies')
        paths = c['allowed_paths']
        if semantics == SEGMENT_V2:
            validate_patterns(paths, nonempty=True)
        else:
            require(isinstance(paths,list) and bool(paths) and all(isinstance(p,str) and p and not p.startswith('/') and '..' not in p.split('/') for p in paths),'invalid historical path policy')
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


def derive(config, components, *, historical=False):
    semantics = _semantics(config, historical=historical)
    sequence=order(config, historical=historical); require(set(components)==set(sequence),'component inventory mismatch')
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
            if not matches(p, policy['allowed_paths'], semantics=semantics): issues.append(n+':out_of_scope:'+p)
    stages=[{'after':None,'violations':compatibility(state)}]
    for n in sequence:
        state[n]=components[n]['head_contract']; stages.append({'after':n,'violations':compatibility(state)})
    for stage in stages:
        issues.extend(f'prefix:{stage["after"] or "base"}:{v}' for v in stage['violations'])
    return {'version':config['version'],'config_digest':digest(config),'intent_id':config['intent_id'],'components':components,'order':sequence,'stages':stages,'issues':issues,'eligible':not issues,'merge_authority':False}


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
    order(config)
    require(p.get('version') == config['version'] and p.get('config_digest') == digest(config), 'approval plan profile mismatch')
    body={'component':component,'plan_digest':digest(p),'config_digest':digest(config)}
    return {**body,'signature':sign('approval',body,key)}


def verify_plan(config,p,approvals, *, historical=False):
    require(p==derive(config,p['components'], historical=historical),'plan derivation mismatch')
    require(p['eligible'],'change set blocked by plan')
    seen=set()
    for a in approvals:
        n=a['component']; require(n in config['components'] and n not in seen,'unexpected or duplicate approval')
        body={'component':n,'plan_digest':digest(p),'config_digest':digest(config)}
        require(set(a)==set(body)|{'signature'} and all(a[k]==v for k,v in body.items()),'approval binding mismatch')
        verify_sig('approval',body,a['signature'],config['components'][n]['reviewer_key']); seen.add(n)
    require(seen==set(config['components']),'missing component approval')


RECOVERY_PROFILE = 'changeset-observation-v1'
OBSERVATION_ERRORS = (ValueError, OSError, subprocess.SubprocessError)


def execute(config, p, approvals, repos, key, *, fault=None):
    """Local fixture executor: return a signed manual receipt on unknown refs.

    The in-memory ledger covers handled I/O failures, not process death. Use
    DurableChangeSet for write-ahead persistence across process interruptions.
    """
    verify_plan(config, p, approvals)
    repos = repos_checked(config, repos)
    require(plan(config, repos) == p, 'stale plan or candidate')
    probe = {'config_digest': digest(config)}
    verify_sig('probe', probe, sign('probe', probe, key), config['executor_key'])
    expected = {n: c['base'] for n, c in p['components'].items()}
    completed = []
    ledger = Ledger()

    def snapshot():
        return {n: ref(repo, 'refs/heads/main') for n, repo in repos.items()}

    def finish(status, refs):
        ledger.add('finish', status=status, refs=refs)
        body = {'version': config['version'], 'config_digest': digest(config),
                'plan': p, 'approvals': approvals, 'events': ledger.events,
                'status': status, 'merge_authority': False}
        return {**body, 'signature': sign('receipt', body, key)}

    def unknown(phase, component=None):
        ledger.add('observation_unknown', phase=phase, component=component)
        return finish('MANUAL_INTERVENTION', None)

    initial = snapshot()  # No writes have occurred; preflight may reject.
    require(initial == expected, 'ref drift before start')
    ledger.add('start', refs=initial, recovery_profile=RECOVERY_PROFILE)
    failed = False
    for n in p['order']:
        c = p['components'][n]
        try:
            if fault:
                fault('before_merge', n, repos)
            require(snapshot() == expected, 'ref drift before merge')
            require(ref(repos[n], 'refs/heads/candidate') == c['head'], 'candidate drift')
        except OBSERVATION_ERRORS:
            try:
                observed = snapshot()
            except OBSERVATION_ERRORS:
                return unknown('merge_precheck', n)
            ledger.add('merge_failed', component=n, reason='merge precheck failed', refs=observed)
            failed = True
            break
        ledger.add('write_intent', component=n, direction='forward', old=c['base'], new=c['head'])
        try:
            result = git(repos[n], 'update-ref', 'refs/heads/main', c['head'], c['base'], check=False)
            observed = snapshot()
        except OBSERVATION_ERRORS:
            return unknown('forward_write', n)
        after = {**expected, n: c['head']}
        if result.returncode == 0 and observed == after:
            expected = after
            completed.append(n)
            ledger.add('merged', component=n, refs=observed)
        elif result.returncode != 0 and observed == expected:
            ledger.add('merge_failed', component=n, reason='merge CAS failed', refs=observed)
            failed = True
            break
        else:
            # A write may have happened or an external actor changed refs.
            # Never compensate an unconfirmed write or overwrite drift.
            return unknown('forward_write', n)

    status = 'COMPLETED'
    if failed:
        status = 'COMPENSATED' if completed else 'ABORTED'
        for n in reversed(completed):
            c = p['components'][n]
            try:
                if fault:
                    fault('before_compensate', n, repos)
                observed = snapshot()
                require(observed == expected, 'ref drift before compensation')
            except OBSERVATION_ERRORS:
                try:
                    observed = snapshot()
                except OBSERVATION_ERRORS:
                    return unknown('compensation_precheck', n)
                ledger.add('compensation_failed', component=n, reason='compensation precheck failed', refs=observed)
                return finish('MANUAL_INTERVENTION', observed)
            ledger.add('write_intent', component=n, direction='compensate', old=c['head'], new=c['base'])
            try:
                result = git(repos[n], 'update-ref', 'refs/heads/main', c['base'], c['head'], check=False)
                observed = snapshot()
            except OBSERVATION_ERRORS:
                return unknown('compensation_write', n)
            after = {**expected, n: c['base']}
            if result.returncode == 0 and observed == after:
                expected = after
                ledger.add('compensated', component=n, refs=observed)
            elif result.returncode != 0 and observed == expected:
                ledger.add('compensation_failed', component=n, reason='compensation CAS failed', refs=observed)
                return finish('MANUAL_INTERVENTION', observed)
            else:
                return unknown('compensation_write', n)
    try:
        final = snapshot()
    except OBSERVATION_ERRORS:
        return unknown('finish')
    if final != expected:
        status = 'MANUAL_INTERVENTION'
    return finish(status, final)


def _verify_observation_events(p, events, status):
    """Replay write intents and observations; unknown is never success."""
    expected = {n: c['base'] for n, c in p['components'].items()}
    require(events[0]['payload'] == {'refs': expected, 'recovery_profile': RECOVERY_PROFILE}, 'invalid start')
    completed = []
    failed = conflict = unknown = False
    pending = None
    for e in events[1:-1]:
        k, d = e['kind'], e['payload']
        n = d.get('component')
        require(not (conflict or unknown), 'event after terminal uncertainty')
        forward = p['order'][len(completed)] if not failed and len(completed) < len(p['order']) else None
        reverse = completed[-1] if failed and completed else None
        if k == 'write_intent':
            require(pending is None and n is not None and n in (forward, reverse), 'invalid write intent sequence')
            c = p['components'][n]
            direction = 'compensate' if failed else 'forward'
            new = c['base'] if failed else c['head']
            require(d == {'component': n, 'direction': direction, 'old': expected[n], 'new': new}, 'invalid write intent binding')
            pending = d
        elif k in ('merged', 'compensated'):
            direction = 'forward' if k == 'merged' else 'compensate'
            require(pending is not None and pending['component'] == n and pending['direction'] == direction, 'invalid write outcome sequence')
            expected[n] = pending['new']
            require(d == {'component': n, 'refs': expected}, 'write observation mismatch')
            if k == 'merged':
                completed.append(n)
            else:
                completed.pop()
            pending = None
        elif k in ('merge_failed', 'compensation_failed'):
            require(n is not None and n == (forward if k == 'merge_failed' else reverse), 'invalid failure sequence')
            require(set(d) == {'component', 'reason', 'refs'} and isinstance(d['reason'], str) and isinstance(d['refs'], dict)
                    and set(d['refs']) == set(expected) and all(hexstr(v, 40) for v in d['refs'].values()), 'invalid failure observation')
            if pending is not None:
                require(pending['component'] == n and d['refs'] == expected, 'unconfirmed failed write')
            pending = None
            if k == 'merge_failed':
                failed = True
            else:
                conflict = True
        elif k == 'observation_unknown':
            require(set(d) == {'phase', 'component'}, 'invalid observation event')
            phase = d['phase']
            if pending is not None:
                require(n == pending['component'] and phase == ('forward_write' if pending['direction'] == 'forward' else 'compensation_write'), 'unknown write binding mismatch')
            else:
                require((phase == 'finish' and n is None and (failed and not completed or not failed and forward is None))
                        or (phase == 'merge_precheck' and n is not None and n == forward)
                        or (phase == 'compensation_precheck' and n is not None and n == reverse), 'invalid unknown observation sequence')
            unknown = True
        else:
            raise ValueError('unexpected execution event')
    final = events[-1]['payload']
    require(set(final) == {'status', 'refs'} and final['status'] == status, 'invalid terminal event')
    refs = final['refs']
    if unknown:
        require(refs is None and status == 'MANUAL_INTERVENTION', 'unknown refs require manual intervention')
        return status
    require(pending is None and isinstance(refs, dict) and set(refs) == set(expected)
            and all(hexstr(v, 40) for v in refs.values()), 'invalid terminal observation')
    if conflict or refs != expected:
        derived = 'MANUAL_INTERVENTION'
    elif failed:
        require(not completed, 'incomplete compensation')
        derived = 'COMPENSATED' if any(e['kind'] == 'compensated' for e in events) else 'ABORTED'
    else:
        require(completed == p['order'], 'incomplete success')
        derived = 'COMPLETED'
    require(status == derived, 'terminal state mismatch')
    return status


def verify_receipt(config,receipt,expected_config_digest):
    order(config, historical=True)
    require(digest(config)==expected_config_digest,'external config digest mismatch')
    require(set(receipt)=={'version','config_digest','plan','approvals','events','status','merge_authority','signature'},'invalid receipt fields')
    body={k:v for k,v in receipt.items() if k!='signature'}
    verify_sig('receipt',body,receipt['signature'],config['executor_key'])
    require(type(receipt['version']) is int and receipt['version']==config['version'] and receipt['config_digest']==digest(config) and receipt['merge_authority'] is False,'receipt scope mismatch')
    p=receipt['plan']; verify_plan(config,p,receipt['approvals'], historical=True); events=receipt['events']; root=verify_chain(events)
    require(events[0]['kind'] == 'start' and events[-1]['kind'] == 'finish', 'invalid receipt endpoints')
    profile = events[0]['payload'].get('recovery_profile')
    if profile is not None:
        require(config['version'] == 2 and profile == RECOVERY_PROFILE, 'unknown recovery profile')
        status = _verify_observation_events(p, events, receipt['status'])
        return {'integrity':'verified','execution_replay':'verified','status':status,'ledger_root':root,'merge_authority':False,'profile':config['profile']}
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
