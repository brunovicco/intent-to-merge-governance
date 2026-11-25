"""Synthetic incident-to-eval study over the existing signed AMGB corpus."""
from __future__ import annotations
import json, html
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .autonomy import ROLES, ZERO, sign_event, replay, gate, validate_case
from .core import digest
from .evidence_profile import HISTORICAL_V1
from .bundle import verify
from .verification import Executor, WORKER, expected, plan, evaluate as verify_cases
from .fixtures import FIXED
from .runner import write_json

def require_demo(condition, message):
    if not condition:
        raise ValueError(message)

def study(corpus, public_key, out):
    corpus,public_key,out=map(Path,(corpus,public_key,out)); out.mkdir(parents=True,exist_ok=False)
    names=['happy','safe-first','safe-refactor','safe-delayed','missing-approval']; refs={}
    for n in names:
        b=corpus/n; v=verify(b,public_key,profile=HISTORICAL_V1); ev=b/'evidence'; first=json.loads((ev/'ledger.jsonl').read_text().splitlines()[0])['payload']; report=json.loads((ev/'report.json').read_text())
        refs[n]={'root':v['ledger_root'],'head':v['candidate']};
        if n=='happy': scope={'repository':'demo/payments','agent':'coding-agent','model':'fixture-v1','profile':v['profile'],'bundle_signer':v['key_id'],**{k:first[k] for k in ('harness','policy','spec')}}
    keys={r:Ed25519PrivateKey.generate() for r in set(ROLES.values())}
    config={'version':1,'scope':scope,'keys':{r:k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() for r,k in keys.items()},'initial_level':2,'max_level':2,'risk_ceiling':'high','clean_required':2,'window':2,'adverse_limit':2}
    events=[]; stages=[]
    root=lambda:events[-1]['hash'] if events else ZERO
    def add(kind,**p):
        events.append(sign_event(config,events,kind,p,keys[ROLES[kind]])); replay(config,events,root())
    def stage(label,n='happy'):
        s=replay(config,events,root()); d=gate(config,events,root(),corpus/n,public_key,profile=HISTORICAL_V1); stages.append({'label':label,'scenario':n,'event_count':len(events),'level':s.level,'clean_streak':s.clean,'open_incidents':s.pending(),'gate':d})
    stage('Initial eligibility')
    add('incident',id='INC-424242',severity='critical'); stage('Critical incident: circuit open')
    ops=[['register','edge',424242],['register','edge',424242],['register','edge',424243]]
    case=validate_case(ops); cd=digest(case)
    add('propose_eval',id='E-424242',incident='INC-424242',operations=ops)
    add('approve_eval',id='E-424242',case_digest=cd); stage('Independent regression approval')
    executor=Executor('local')
    # Fault deliberately outside the original generated amount range; separate fixture, not a historical AMGB merge.
    bad=FIXED.replace('if key in store:', 'if key in store and amount != 424242:')
    observations=executor.execute(bad,WORKER,{'cases':[case]}); require_demo(observations['status']=='ok','incident observation failed')
    bad_pass=digest(observations['observations'][0])==digest(expected(case)); require_demo(not bad_pass,'fault fixture unexpectedly passed')
    original_plan=plan(); original_obs=executor.execute(bad,WORKER,original_plan); original_result=verify_cases(original_plan,original_obs); require_demo(all(original_result['checks'].values()),'original checks unexpectedly failed')
    def evaluate(n):
        ev=corpus/n/'evidence'; report=json.loads((ev/'report.json').read_text()); cp=next(json.loads(l)['payload'] for l in reversed((ev/'ledger.jsonl').read_text().splitlines()) if json.loads(l)['kind']=='checkpoint' and json.loads(l)['payload']['binding']['head']==refs[n]['head'])
        source=(ev/f"candidate-{cp['iteration']}.py").read_text(); obs=executor.execute(source,WORKER,{'cases':[case]}); require_demo(obs['status']=='ok','regression observation failed')
        add('eval_result',id='E-424242',case_digest=cd,**refs[n],observations=obs['observations'][0]); require_demo(replay(config,events,root()).evals_pass((refs[n]['root'],refs[n]['head'])),'incident regression failed')
    evaluate('happy'); stage('Regression passes; incident still open')
    add('resolve',id='INC-424242',**refs['happy']); stage('Incident resolved: manual release only')
    for n in ('safe-first','safe-refactor'):
        evaluate(n); add('outcome',**refs[n],status='clean'); stage('Clean outcome: '+n,n)
    add('promote',level=2); stage('Governance-approved recovery','safe-refactor')
    stage('New candidate lacks regression evidence','safe-delayed')
    evaluate('safe-delayed'); stage('Fresh regression evidence restores eligibility','safe-delayed')
    stage('Base policy denial is never overridden','missing-approval')
    # Signed adverse observations, synthetic and independent of historical bundle labels.
    add('outcome',**refs['happy'],status='adverse'); stage('First adverse observation')
    add('outcome',**refs['safe-delayed'],status='adverse'); stage('Adverse threshold: automatic downgrade','safe-delayed')
    write_json(out/'config.json',config); write_json(out/'events.json',events); write_json(out/'anchor.json',{'root':root()})
    result={'profile':'synthetic-demo','scope':scope,'incident_case':case,'regression_fixture_passed':bad_pass,'regression_fixture_original_cases_passed':sum(o['passed'] for o in original_result['outcomes']),'regression_fixture_original_cases_total':len(original_result['outcomes']),'regression_observations':observations['observations'][0],'events':len(events),'stages':stages,'state':replay(config,events,root()).summary(),'limitations':['Operational events are simulated, signed by distinct generated keys; no production telemetry or human identities.','Historical AMGB bundles already record local merges; this overlay evaluates eligibility only, never performs or authorizes a new merge.','Observer and verifier signatures attest claims; they do not independently prove deployment outcomes or trustworthy execution.','Externally pinned config and latest root are required; sample anchor is demonstration-only.']}
    write_json(out/'report.json',result); render_report(result,out/'report.html'); return result

def render_report(result,path):
    esc=lambda x:html.escape(str(x)); stages=result['stages']; rows=''.join('<tr>'+''.join(f'<td>{esc(v)}</td>' for v in (i+1,s['label'],s['scenario'],'L'+str(s['level']),s['clean_streak'],s['gate']['status'],', '.join(s['gate']['reasons']) or '—'))+'</tr>' for i,s in enumerate(stages))
    points=' '.join(f'{40+i*70},{150-s["level"]*55}' for i,s in enumerate(stages)); ticks=''.join(f'<text x="{40+i*70}" y="175" text-anchor="middle">{i+1}</text>' for i in range(len(stages)))
    Path(path).write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ITM | Adaptive autonomy</title><style>body{{background:#101c27;color:#eaf1f5;font:15px system-ui;margin:0}}main{{max-width:1150px;margin:auto;padding:32px 20px}}h1{{font-size:36px;letter-spacing:-1px}}small,p{{color:#afc2d0}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #334858}}svg{{width:100%;background:#192b38;border-radius:10px}}svg text{{fill:#afc2d0;font-size:11px}}.table{{overflow:auto}}.tag{{color:#58d5c3;font-weight:bold;letter-spacing:2px}}</style><main><div class="tag">ITM / OPERATIONAL GOVERNANCE / V0.7</div><h1>Autonomy must be earned again.</h1><p>Signed synthetic incident-to-eval study · {result['events']} events · no production data</p><svg viewBox="0 0 {80+70*(len(stages)-1)} 190" role="img" aria-label="Autonomy level over stages"><text x="8" y="44">L2</text><text x="8" y="99">L1</text><text x="8" y="154">L0</text><polyline points="{points}" stroke="#58d5c3" stroke-width="3" fill="none"/>{ticks}</svg><h2>New incident, new invariant</h2><p>Fault fixture passed {result["regression_fixture_original_cases_passed"]}/{result["regression_fixture_original_cases_total"]} original cases but failed the approved incident regression.</p><h2>Evidence-bound decisions</h2><div class="table"><table><thead><tr><th>Step</th><th>Event</th><th>Candidate</th><th>Level</th><th>Clean streak</th><th>Gate</th><th>Reasons</th></tr></thead><tbody>{rows}</tbody></table></div><h2>Limits</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in result['limitations'])}</ul></main></html>''',encoding='utf-8')
