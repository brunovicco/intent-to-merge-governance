"""Counterfactual decision-only replay of authenticated historical observations.
No approvals are re-signed, no merges are executed, no future outcome is predicted.
"""
from __future__ import annotations
import json
from pathlib import Path
from .evidence_profile import CURRENT
from .bundle import verify
from .core import digest, load_config, load_user_config, verified_actors, evaluate_decision
from .policy_schema import InvalidConfiguration, validate_local_policy
from .path_policy import LEGACY_V1, SEGMENT_V2
from .approval_registry import gate_decision, verify_recorded_claim

DECISION_FIELDS={'required_checks','protected_paths','risk_rules'}


def validate_proposal(old, new):
    if set(old)!=set(new): raise ValueError('proposed policy must preserve the policy schema')
    changed={k for k in old if old[k]!=new[k]}
    if changed-DECISION_FIELDS: raise ValueError('unsupported counterfactual changes: '+', '.join(sorted(changed-DECISION_FIELDS)))
    for key in ('required_checks','protected_paths'):
        v=new[key]
        if not isinstance(v,list) or not all(isinstance(x,str) and x for x in v) or len(v)!=len(set(v)): raise ValueError('invalid '+key)
    if not isinstance(new['risk_rules'],list): raise ValueError('invalid risk_rules')
    for r in new['risk_rules']:
        if not isinstance(r,dict) or set(r)!={'path','level','required_roles'} or not isinstance(r['path'],str) or not r['path'] or r['level'] not in ('low','medium','high') or not isinstance(r['required_roles'],list) or not all(isinstance(x,str) and x in new['approvers'].values() for x in r['required_roles']): raise ValueError('invalid risk rule')
    return sorted(changed)


def replay(bundles, public_key, proposed_policy, *, profile=CURRENT):
    proposed=load_user_config(proposed_policy); rows=[]; seen=set()
    try:
        validate_local_policy(proposed)
    except ValueError:
        raise InvalidConfiguration('invalid_proposed_policy') from None
    semantics = SEGMENT_V2 if profile == CURRENT else LEGACY_V1
    for bundle in bundles:
        bundle=Path(bundle); verified=verify(bundle,public_key,profile=profile); ev=bundle/'evidence'
        if verified['ledger_root'] in seen: raise ValueError('duplicate historical evidence')
        seen.add(verified['ledger_root'])
        spec=load_config(ev/'spec.toml'); old=load_config(ev/'policy.toml')
        try:
            changed=validate_proposal(old,proposed)
        except ValueError as exc:
            raise InvalidConfiguration(str(exc)) from None
        events=[json.loads(line) for line in (ev/'ledger.jsonl').read_text().splitlines()]
        decision=next(e['payload'] for e in events if e['kind']=='policy_decision'); i=decision['inputs']; actual=decision['decision']
        actors=verified_actors(old,i['binding'],i['approvals'],json.loads((bundle/'approval-trust.json').read_text()),i['author'],approval_context=i.get('approval_context'),_historical_semantics=semantics)
        # Rebind only the policy digest in the *hypothetical* input. Preserve every
        # historical mismatch and never treat original signatures as new approvals.
        binding={**i['binding']}
        if binding.get('policy')==digest(old):
            binding['policy']=digest(proposed)
        eval_binding=i['eval_binding']
        if eval_binding is not None and i['binding'].get('policy')==digest(old) and eval_binding.get('policy')==digest(old):
            eval_binding={**eval_binding,'policy':digest(proposed)}
        candidate=evaluate_decision(spec,proposed,i['paths'],i['checks'],binding,actors,termination=i['termination'],current_head=i['current_head'],current_base=i['current_base'],eval_binding=eval_binding,_historical_semantics=semantics)
        if profile == CURRENT:
            candidate = gate_decision(candidate, verify_recorded_claim(events, i, json.loads((bundle/"approval-trust.json").read_text())))
        state=('unchanged_allow' if actual['authorized'] else 'unchanged_deny') if actual['authorized']==candidate['authorized'] else ('would_allow' if candidate['authorized'] else 'would_deny')
        if not changed and actual!=candidate: raise ValueError('identity replay mismatch')
        rows.append({'scenario':json.loads((ev/'report.json').read_text())['scenario'],'ledger_root':verified['ledger_root'],'candidate':i['current_head'],'original_policy_digest':digest(old),'changed_fields':changed,'historical_decision':actual,'counterfactual_decision':candidate,'transition':state,'historically_verified_actors':sorted(actors),'requires_fresh_authorization':True})
    if not rows: raise ValueError('at least one bundle required')
    return {'mode':'decision_only_counterfactual','proposed_policy_digest':digest(proposed),'bundles':len(rows),'transitions':{k:sum(r['transition']==k for r in rows) for k in ('unchanged_allow','unchanged_deny','would_allow','would_deny')},'historically_authorized':sum(r['historical_decision']['authorized'] for r in rows),'counterfactually_eligible':sum(r['counterfactual_decision']['authorized'] for r in rows),'rows':rows,'limitations':['Historical observations and convergence are held fixed.','Historical verified identities are reused hypothetically, not re-signed or accepted as new approvals.','Unknown checks fail closed; changes to execution, convergence, or identity policy are rejected.','Eligibility is not merge authority, safety proof, or a forecast of production outcomes.']}
