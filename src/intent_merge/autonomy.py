"""Signed, scope-bound operational governance overlay. No merge side effects.
The trusted control plane supplies a current external root; an old valid prefix is
not proof of freshness. Incident observations are attested, not independently true.
"""
from __future__ import annotations
import json, re
from dataclasses import dataclass, field
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .core import canonical, digest
from .evidence_profile import CURRENT
from .bundle import verify
from .verification import expected

ROLES={'incident':'observer','outcome':'observer','propose_eval':'proposer',
       'approve_eval':'reviewer','eval_result':'verifier','resolve':'governance','promote':'governance'}
ZERO='0'*64

def require(condition, message):
    if not condition: raise ValueError(message)

def hexstr(value,n=64):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(n)+'}',value) is not None

def validate_config(c):
    require(isinstance(c, dict) and set(c)=={'version','scope','keys','initial_level','clean_required','window','adverse_limit','max_level','risk_ceiling'},'invalid config fields')
    require(all(type(c[k]) is int for k in ('version', 'initial_level', 'max_level'))
            and c['version']==1 and c['initial_level'] in (0,1,2) and c['max_level'] in (1,2) and c['initial_level']<=c['max_level'],'invalid levels')
    require(all(type(c[k]) is int and 1<=c[k]<=1000 for k in ('clean_required','window','adverse_limit')) and c['adverse_limit']<=c['window'],'invalid thresholds')
    require(c['risk_ceiling'] in ('low','medium','high'),'invalid risk ceiling')
    scope=c['scope']; require(isinstance(scope, dict) and set(scope)=={'repository','agent','model','harness','policy','spec','bundle_signer','profile'},'invalid scope')
    require(all(isinstance(v,str) and v for v in scope.values()) and all(hexstr(scope[k]) for k in ('harness','policy','spec','bundle_signer')) and scope['profile']=='synthetic-demo','invalid scope values')
    require(isinstance(c['keys'], dict) and set(c['keys'])==set(ROLES.values()) and all(hexstr(v) for v in c['keys'].values()) and len(set(c['keys'].values()))==len(c['keys']),'distinct role keys required')
    return c

def sign_event(config, events, kind, payload, private_key):
    validate_config(config); require(kind in ROLES,'unknown event kind')
    body={'version':1,'config':digest(config),'seq':len(events),'prev':events[-1]['hash'] if events else ZERO,'kind':kind,'payload':payload}
    signed={**body,'signature':private_key.sign(b'ITM-OPERATIONAL-V1\0'+canonical(body)).hex()}
    return {**signed,'hash':digest(signed)}

def validate_case(case):
    # Restricted payment DSL, never executable code from incident reports.
    require(isinstance(case,list) and 1<=len(case)<=64,'invalid operations')
    for op in case:
        require(isinstance(op,list) and len(op) in (2,3),'invalid operation')
        require(isinstance(op[1],str) and 1<=len(op[1])<=128,'invalid operand')
        require((op[0]=='authorize' and len(op)==2) or (op[0]=='register' and len(op)==3 and type(op[2]) is int and abs(op[2])<=10**12),'unsupported operation')
    return {'operations':case}

def ref(p):
    require(hexstr(p['root']) and hexstr(p['head'],40),'invalid candidate reference')
    return p['root'],p['head']

@dataclass
class State:
    level:int
    incidents:dict=field(default_factory=dict)
    evaluations:dict=field(default_factory=dict)
    results:dict=field(default_factory=dict)
    outcomes:dict=field(default_factory=dict)
    recent:list=field(default_factory=list)
    clean:int=0
    history:list=field(default_factory=list)
    root:str=ZERO
    def pending(self): return sorted(k for k,v in self.incidents.items() if not v['resolved'])
    def required(self): return sorted(k for k,v in self.evaluations.items() if v['approved'])
    def evals_pass(self,reference, ids=None):
        ids=self.required() if ids is None else ids
        return all(self.results.get((reference,e),False) for e in ids)
    def summary(self):
        return {'level':self.level,'open_incidents':self.pending(),'required_evals':self.required(),'clean_streak':self.clean,'root':self.root,'history':self.history}

def replay(config, events, expected_root):
    validate_config(config); require(hexstr(expected_root),'external root required')
    s=State(config['initial_level']); previous=ZERO
    for i,event in enumerate(events):
        require(set(event)=={'version','config','seq','prev','kind','payload','signature','hash'},'invalid event fields')
        signed={k:v for k,v in event.items() if k!='hash'}; body={k:v for k,v in signed.items() if k!='signature'}
        kind=body['kind']; require(kind in ROLES and body['version']==1 and body['config']==digest(config) and body['seq']==i and body['prev']==previous and event['hash']==digest(signed),'event chain or scope mismatch')
        try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(config['keys'][ROLES[kind]])).verify(bytes.fromhex(signed['signature']),b'ITM-OPERATIONAL-V1\0'+canonical(body))
        except (InvalidSignature,ValueError,TypeError) as e: raise ValueError('invalid event signature') from e
        p=body['payload']; before=s.level
        fields={'incident':{'id','severity'},'outcome':{'root','head','status'},'propose_eval':{'id','incident','operations'},'approve_eval':{'id','case_digest'},'eval_result':{'id','case_digest','root','head','observations'},'resolve':{'id','root','head'},'promote':{'level'}}
        require(isinstance(p,dict) and set(p)==fields[kind],'invalid payload fields')
        if 'id' in p: require(isinstance(p['id'],str) and 1<=len(p['id'])<=100,'invalid identifier')
        if kind=='incident':
            require(p['id'] not in s.incidents and p['severity'] in ('critical','major'),'invalid or duplicate incident')
            s.incidents[p['id']]={'resolved':False,'severity':p['severity']}; s.level=min(s.level,0 if p['severity']=='critical' else 1); s.clean=0; s.recent=[]
        elif kind=='propose_eval':
            require(p['id'] not in s.evaluations and p['incident'] in s.pending(),'invalid eval proposal')
            case=validate_case(p['operations']); s.evaluations[p['id']]={'incident':p['incident'],'case':case,'digest':digest(case),'approved':False}
        elif kind=='approve_eval':
            e=s.evaluations.get(p['id']); require(e is not None and not e['approved'] and e['digest']==p['case_digest'],'invalid eval approval')
            e['approved']=True; s.clean=0
        elif kind=='eval_result':
            e=s.evaluations.get(p['id']); r=ref(p); require(e is not None and e['approved'] and e['digest']==p['case_digest'],'unapproved or changed evaluation')
            require(isinstance(p['observations'],list),'invalid observations')
            passed=digest(p['observations'])==digest(expected(e['case'])); s.results[r,p['id']]=passed
            if not passed: s.level=min(s.level,1); s.clean=0
        elif kind=='resolve':
            r=ref(p); require(p['id'] in s.pending(),'incident not open')
            ids=[k for k,v in s.evaluations.items() if v['incident']==p['id']]
            require(ids and all(s.evaluations[k]['approved'] for k in ids) and s.evals_pass(r,ids),'approved regression evidence required for resolution')
            s.incidents[p['id']]['resolved']=True; s.clean=0; s.recent=[]
            if not s.pending(): s.level=min(1,config['max_level'])
        elif kind=='outcome':
            r=ref(p); require(r[0] not in s.outcomes and all(o['head']!=r[1] for o in s.outcomes.values()) and p['status'] in ('clean','adverse'),'invalid or duplicate outcome')
            if p['status']=='clean': require(not s.pending() and s.evals_pass(r),'clean outcome requires all incident evals and no open incidents')
            s.outcomes[r[0]]=p; s.recent=(s.recent+[p['status']])[-config['window']:]
            s.clean=s.clean+1 if p['status']=='clean' else 0
            if s.recent.count('adverse')>=config['adverse_limit']: s.level=min(s.level,1)
        elif kind=='promote':
            require(type(p['level']) is int and p['level']==s.level+1 and p['level']<=config['max_level'] and not s.pending() and s.clean>=config['clean_required'] and 'adverse' not in s.recent,'promotion conditions not met')
            s.level=p['level']; s.clean=0
        previous=event['hash']; s.root=previous; s.history.append({'seq':i,'event':kind,'level_before':before,'level_after':s.level,'open_incidents':len(s.pending()),'clean_streak':s.clean})
    require(previous==expected_root,'external root mismatch (stale, truncated or altered stream)')
    return s

def gate(config, events, expected_root, bundle, public_key, *, profile=CURRENT):
    """Evaluate extra gate against a verified *historical synthetic* change.
    Never grants authority, relaxes a base approval, or writes a GitHub check.
    """
    s=replay(config,events,expected_root); b=Path(bundle); v=verify(b,public_key,profile=profile)
    ev=b/'evidence'; report=json.loads((ev/'report.json').read_text()); first=json.loads((ev/'ledger.jsonl').read_text().splitlines()[0])['payload']; scope=config['scope']
    require(v['key_id']==scope['bundle_signer'] and v['profile']==scope['profile'] and all(first[k]==scope[k] for k in ('harness','policy','spec')),'bundle does not match scope pins')
    r=(v['ledger_root'],v['candidate']); reasons=[]
    if not report['decision']['authorized']: reasons.append('base_policy_denied')
    if s.pending(): reasons.append('open_incidents')
    if s.level==0: reasons.append('circuit_open')
    if s.level==1: reasons.append('manual_release_required')
    if ('low','medium','high').index(report['decision']['risk'])>('low','medium','high').index(config['risk_ceiling']): reasons.append('risk_ceiling')
    missing=[e for e in s.required() if not s.results.get((r,e),False)]
    reasons.extend('regression_missing_or_failed:'+e for e in missing)
    return {'profile':'synthetic-demo','status':'ELIGIBLE' if not reasons else 'BLOCKED','merge_authority':False,'base_authorized':report['decision']['authorized'],'level':s.level,'head':r[1],'bundle_root':r[0],'operational_root':s.root,'reasons':reasons}
