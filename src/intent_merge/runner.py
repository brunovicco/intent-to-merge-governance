from __future__ import annotations
import json, os, secrets, subprocess, sys, shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from .core import Ledger, Proposal, approval, digest, file_hash, load_config, matches, evaluate_policy, verify_chain
from .fixtures import BASE, PARTIAL, FIXED, BROKEN, HARNESS, DRIFTED, SIGNATURE_DRIFT, IMPORT_DRIFT
from .intent import validate_spec, drift, requirement_coverage, build_graph, graph_mermaid
from .checkpoints import make_checkpoint
from .verification import WORKER, Executor, plan, evaluate, harness_digest, mutation_report, mutation_sources
from .convergence import Governor
from .path_policy import SEGMENT_V2, LEGACY_V1
from .policy_schema import invalid_configuration

SCENARIOS = ('happy', 'missing-approval', 'stale-approval', 'scope-violation', 'protected-path', 'loop', 'failed-eval', 'self-approval', 'stale-base', 'stale-eval', 'intent-drift', 'signature-drift', 'import-drift', 'property-regression', 'budget-exceeded', 'regression-loop')

BENCHMARK_SAFE_SCENARIOS = ("safe-first", "safe-refactor", "safe-delayed")

class FixtureAgent:
    def __init__(self, scenario): self.scenario = scenario
    def propose(self, iteration, feedback):
        code = PARTIAL if iteration == 1 else FIXED
        if self.scenario == 'safe-first': code = FIXED
        if self.scenario == 'safe-refactor': code = FIXED.replace('payment = {', 'record = {').replace('store[key] = payment', 'store[key] = record').replace('return payment', 'return record')
        if self.scenario == 'safe-delayed': code = BASE + '\n# initial proposal\n' if iteration == 1 else PARTIAL if iteration == 2 else FIXED
        if self.scenario == 'loop': code = BROKEN if iteration % 2 else BASE
        if self.scenario == 'failed-eval': code = PARTIAL
        if self.scenario == 'intent-drift': code = DRIFTED
        if self.scenario == 'signature-drift': code = SIGNATURE_DRIFT
        if self.scenario == 'import-drift': code = IMPORT_DRIFT
        if self.scenario == 'property-regression': code = FIXED.replace('if amount <= 0:', 'if amount == 0:')
        if self.scenario == 'regression-loop': code = PARTIAL if iteration == 1 else BASE
        if self.scenario == 'budget-exceeded': code = FIXED + '\n#' + 'x'*15000 + '\n'
        files = {'app/payments.py': code}
        if self.scenario == 'scope-violation': files['app/other.py'] = '# out of scope\n'
        if self.scenario == 'protected-path': files['tests/acceptance.py'] = '# attempted criteria modification\n'
        return Proposal(files, f'Fixture proposal {iteration}; failed criteria: {sorted(k for k,v in feedback.items() if not v)}')

def git(repo, *args):
    return subprocess.run(['git','-C',str(repo),*args], check=True, text=True, capture_output=True, timeout=30).stdout.strip()

def write_json(path, obj): Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n')

def snapshot(repo, base):
    return git(repo, 'diff', '--name-only', base, 'HEAD').splitlines()

def run_checks(repo, harness, spec, policy, paths, trusted_hash, executor, plan_data, mutations_ok, source, baseline_execution):
    scope = not any(not matches(p,spec['allowed_paths']) or matches(p,policy['protected_paths']) for p in paths)
    trusted = harness_digest(harness,harness.parent/'verification-plan.json') == trusted_hash
    execution = executor.execute(source,harness.read_text(),plan_data) if scope and trusted else {'status':'not_run','observations':None}
    verification = evaluate(plan_data,execution,baseline_execution)
    return {**verification['checks'], 'scope':scope, 'trusted_harness':trusted, 'mutation_adequacy':mutations_ok}, execution, verification

def record_candidate(repo,ev,ledger,spec,policy,harness,trusted_hash,paths,binding,i,session,proposal_hash,executor,plan_data,mutations_ok,baseline_execution,*,source='agent_proposal'):
    head,base=binding['head'],binding['base']; tree=git(repo,'rev-parse',head+'^{tree}')
    diff_path=ev/f'iteration-{i}.diff'; diff_path.write_bytes(subprocess.run(['git','-C',str(repo),'diff',base,head],check=True,capture_output=True,timeout=30).stdout)
    candidate_path=ev/f'candidate-{i}.py'; candidate_path.write_bytes(subprocess.run(['git','-C',str(repo),'show',head+':app/payments.py'],check=True,capture_output=True,timeout=30).stdout)
    checkpoint=make_checkpoint(spec['id'],session,binding,tree,paths,file_hash(diff_path),proposal_hash,source=source)
    ledger.add('checkpoint',iteration=i,binding=binding,tree=tree,author='coding-agent',paths=paths,diff_hash=file_hash(diff_path),candidate_hash=file_hash(candidate_path),universal=checkpoint)
    result=drift(spec,{'app/payments.py':(ev/'baseline.py').read_text()},{'app/payments.py':candidate_path.read_text()},paths)
    ledger.add('intent_drift',iteration=i,binding=binding,result=result)
    checks,execution,verification=run_checks(repo,harness,spec,policy,paths,trusted_hash,executor,plan_data,mutations_ok,candidate_path.read_text(),baseline_execution)
    ledger.add('verification',iteration=i,binding=binding,execution=execution,result=verification)
    coverage=requirement_coverage(spec,checks,paths)
    checks.update(intent_drift=result['passed'],requirement_coverage=all(r['verified'] for r in coverage),checkpoint_binding=(head==git(repo,'rev-parse','HEAD') and checkpoint['binding']==binding and digest(candidate_path.read_text())==next(e['payload']['files']['app/payments.py'] for e in ledger.events if e['hash']==proposal_hash)))
    ledger.add('evaluation',iteration=i,binding=binding,checks=checks,score=sum(checks.values()),evaluator='host-oracle-v1')
    return checks,execution


def run(scenario, out, spec_path, policy_path, backend="local", image="python:3.11-slim"):
    if scenario not in SCENARIOS + BENCHMARK_SAFE_SCENARIOS: raise ValueError('unknown scenario')
    spec = load_config(spec_path); policy = load_config(policy_path)
    invalid = invalid_configuration(spec, policy)
    if invalid is not None:
        # A configuration rejection is not a completed candidate run or bundle.
        out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
        ledger = Ledger(); ledger.add('configuration_rejected', decision=invalid)
        ledger.write(out/'configuration-rejection.jsonl')
        return {'decision': invalid, 'merged': False, 'merge_authority': False}
    validate_spec(spec)
    executor=Executor(backend,image)
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    ev = out/'evidence'; ev.mkdir(); repo = out/'repo'; repo.mkdir()
    if not {'intent_drift','requirement_coverage','checkpoint_binding','property_invariants','differential_compatibility','contract_flow','mutation_adequacy'} <= set(policy['required_checks']): raise ValueError('v0.3 policy must include intent, provenance and verification gates')
    shutil.copyfile(spec_path,ev/'spec.toml'); shutil.copyfile(policy_path,ev/'policy.toml')
    harness = ev/'acceptance.py'; harness.write_text(WORKER); plan_data=plan(); write_json(ev/'verification-plan.json',plan_data); trusted_hash=harness_digest(harness,ev/'verification-plan.json')
    baseline_execution=executor.execute(BASE,WORKER,plan_data); write_json(ev/'baseline-observations.json',baseline_execution)
    mutations=mutation_report(plan_data,executor,WORKER,FIXED,baseline_execution); mutations_ok=all(m['killed'] for m in mutations); write_json(ev/'mutation-report.json',mutations)
    pairs = {actor:Ed25519PrivateKey.generate() for actor in set(policy['approvers']) | {'coding-agent'}}
    keys = {actor:'ed25519-private:'+key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex() for actor,key in pairs.items()}
    public_keys = {actor:'ed25519-public:'+key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex() for actor,key in pairs.items()}
    trust = out/'demo-trust.json'; write_json(trust, public_keys)
    git(repo,'init','-b','main'); git(repo,'config','user.name','Governance Demo'); git(repo,'config','user.email','demo@example.invalid')
    (repo/'app').mkdir(); (repo/'app/payments.py').write_text(BASE)
    git(repo,'add','.'); git(repo,'commit','-m','Baseline'); base = git(repo,'rev-parse','HEAD'); git(repo,'checkout','-b','candidate')
    (ev/'baseline.py').write_text(BASE)
    ledger = Ledger(); ledger.add('intent_registered', spec=digest(spec), policy=digest(policy), base=base, harness=trusted_hash, scenario=scenario, baseline_hash=file_hash(ev/'baseline.py'), schema_version='0.4',path_semantics=SEGMENT_V2,executor=executor.metadata(),mutation_report=digest(mutations),baseline_observations=digest(baseline_execution))
    governor=Governor(policy); required=set(spec['criteria'])|set(policy['required_checks']); agent = FixtureAgent(scenario); feedback = {}; termination = 'iteration_budget'; author = 'coding-agent'; paths = []; checks = {}; binding = {}; history = []
    for i in range(1, policy['max_iterations']+1):
        p = agent.propose(i,feedback)
        # Reject scope before touching the checkout, including traversal, symlinks and protected paths.
        rejected = [name for name in p.files if Path(name).is_absolute() or '..' in Path(name).parts or not matches(name,spec['allowed_paths']) or matches(name,policy['protected_paths']) or not (repo/name).resolve().is_relative_to(repo)]
        session = {'schema_version':'1.0','provider':p.provider,'runtime':'fixture','session_id':f'{scenario}-{i}','agent_id':p.agent,'tool_types':['write'],'claimed_requirements':[]}
        proposal_hash = ledger.add('proposal', iteration=i, agent=p.agent, provider=p.provider, summary=p.summary, input_feedback=feedback, files={k:digest(v) for k,v in p.files.items()}, session=session)
        if rejected:
            paths = sorted(p.files); termination = 'scope_rejected'; checks = {'scope':False,'trusted_harness':True}; ledger.add('proposal_rejected', paths=rejected); break
        for name, content in p.files.items():
            target = repo/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_text(content)
        git(repo,'add','--',*p.files); git(repo,'commit','--allow-empty','-m',f'Agent iteration {i}')
        head = git(repo,'rev-parse','HEAD'); tree = git(repo,'rev-parse','HEAD^{tree}'); paths = snapshot(repo,base)
        binding = {'head':head,'base':base,'spec':digest(spec),'policy':digest(policy),'harness':trusted_hash,'path_semantics':SEGMENT_V2}
        checks,execution = record_candidate(repo,ev,ledger,spec,policy,harness,trusted_hash,paths,binding,i,session,proposal_hash,executor,plan_data,mutations_ok,baseline_execution)
        feedback = checks.copy()
        score = sum(v is True for v in checks.values()); history.append({'iteration':i,'passed':score,'total':len(checks),'head':head})
        control=governor.observe(iteration=i,tree=tree,checks=checks,required=required,paths=paths,case_count=len(plan_data['cases']),diff_bytes=(ev/f'iteration-{i}.diff').stat().st_size,execution_ok=execution['status']=='ok')
        ledger.add('convergence',**control)
        if control['action']!='continue': termination=control['action']; break
    if not binding: binding = {'head':git(repo,'rev-parse','HEAD'),'base':base,'spec':digest(spec),'policy':digest(policy),'harness':trusted_hash,'path_semantics':SEGMENT_V2}
    eval_binding = binding.copy() if history else None
    ledger.add('termination', reason=termination, iterations=len(history))
    approvals = []
    if termination == 'passed':
        actors = list(policy['approvers'])
        if scenario == 'missing-approval': actors = [a for a in actors if policy['approvers'][a]!='security']
        if scenario == 'self-approval': actors = ['coding-agent']
        approvals = [approval(a,binding,keys) for a in actors]
        if scenario == 'stale-approval':
            # New commit retains identical code; old approvals/evaluations cannot authorize it.
            git(repo,'commit','--allow-empty','-m','New candidate after approval'); binding = {**binding,'head':git(repo,'rev-parse','HEAD')}
            checks,_ = record_candidate(repo,ev,ledger,spec,policy,harness,trusted_hash,paths,binding,len(history)+1,session,proposal_hash,executor,plan_data,mutations_ok,baseline_execution,source='harness_refresh'); eval_binding = binding.copy()
        if scenario == 'stale-eval': eval_binding = {**binding,'head':base}
        if scenario == 'stale-base':
            git(repo,'checkout','main'); git(repo,'commit','--allow-empty','-m','Concurrent target change'); git(repo,'checkout','candidate')
    ledger.add('approvals', approvals=approvals, simulated=True)
    current_head = git(repo,'rev-parse','candidate'); current_base = git(repo,'rev-parse','main')
    inputs = dict(paths=paths, checks=checks, binding=binding, approvals=approvals, author=author, termination=termination, current_head=current_head, current_base=current_base, eval_binding=eval_binding)
    decision = evaluate_policy(spec,policy,keys=public_keys,**inputs)
    ledger.add('policy_decision', inputs=inputs, decision=decision)
    merged = False
    if decision['authorized']:
        # Local single-process demo: verify refs again immediately before fast-forward.
        if git(repo,'rev-parse','candidate') != binding['head'] or git(repo,'rev-parse','main') != base: raise RuntimeError('refs moved before merge')
        git(repo,'checkout','main'); git(repo,'merge','--ff-only',binding['head']); merged = True
    final_main = git(repo,'rev-parse','main')
    ledger.add('merge_result', merged=merged, main=final_main, candidate=current_head)
    graph = build_graph(spec,ledger.events)
    write_json(ev/'intent-graph.json',graph); (ev/'intent-graph.mmd').write_text(graph_mermaid(graph))
    write_json(ev/'checkpoints.json', [e['payload']['universal'] for e in ledger.events if e['kind']=='checkpoint'])
    write_json(ev/'intent-drift.json', [e['payload'] for e in ledger.events if e['kind']=='intent_drift'])
    coverage = requirement_coverage(spec,checks,paths)
    write_json(ev/'requirement-coverage.json',coverage)
    write_json(ev/'convergence.json',governor.history)
    write_json(ev/'verification.json',[e['payload'] for e in ledger.events if e['kind']=='verification'])
    ledger.write(ev/'ledger.jsonl')
    report = {'scenario':scenario,'executor':executor.metadata(),'mutation_score':{'killed':sum(m['killed'] for m in mutations),'total':len(mutations)},'verification_cases_per_candidate':len(plan_data['cases']),'termination':termination,'decision':decision,'merged':merged,'base':base,'candidate':current_head,'main':final_main,'history':history,'requirement_coverage':coverage,'graph':{'nodes':len(graph['nodes']),'edges':len(graph['edges'])},'ledger_root':ledger.events[-1]['hash']}
    write_json(ev/'report.json',report)
    manifest = {p.name:file_hash(p) for p in sorted(ev.iterdir()) if p.is_file()}; write_json(out/'manifest.json',manifest)
    # Store separately in a real immutable/trusted system; colocated here solely for reproducibility.
    write_json(out/'anchor.json', {'manifest':file_hash(out/'manifest.json'),'ledger_root':report['ledger_root']})
    return report

def audit(out, anchor_path, trust_path):
    out = Path(out).resolve(); ev = out/'evidence'; anchor = json.loads(Path(anchor_path).read_text()); keys = json.loads(Path(trust_path).read_text())
    if file_hash(out/'manifest.json') != anchor['manifest']: raise ValueError('manifest anchor mismatch')
    manifest = json.loads((out/'manifest.json').read_text()); actual = {p.name:file_hash(p) for p in ev.iterdir() if p.is_file()}
    if manifest != actual: raise ValueError('artifact integrity mismatch')
    events = [json.loads(line) for line in (ev/'ledger.jsonl').read_text().splitlines()]; root = verify_chain(events)
    if root != anchor['ledger_root']: raise ValueError('ledger anchor mismatch')
    spec = load_config(ev/'spec.toml'); policy = load_config(ev/'policy.toml'); init = events[0]['payload']
    if init['spec'] != digest(spec) or init['policy'] != digest(policy) or init['harness'] != harness_digest(ev/'acceptance.py',ev/'verification-plan.json'): raise ValueError('configuration provenance mismatch')
    semantics = init.get('path_semantics', LEGACY_V1)
    if semantics not in (LEGACY_V1, SEGMENT_V2):
        raise ValueError('unknown historical path semantics')
    validate_spec(spec, semantics=semantics)
    verify_intent_evidence(ev,spec,events,semantics=semantics)
    verify_verification_evidence(ev,spec,policy,events)
    d = next(e['payload'] for e in events if e['kind']=='policy_decision'); inputs = d['inputs']
    replay = evaluate_policy(spec,policy,keys=keys,_historical_semantics=semantics,**inputs)
    if replay != d['decision']: raise ValueError('policy replay mismatch')
    result = events[-1]['payload']; report = json.loads((ev/'report.json').read_text())
    if report['ledger_root'] != root or report['decision'] != replay or report['merged'] != result['merged'] or report['main'] != result['main']: raise ValueError('report mismatch')
    if result['merged'] != replay['authorized'] or (result['merged'] and result['main'] != inputs['binding']['head']): raise ValueError('merge authorization mismatch')
    return {'integrity':'verified','policy_replay':'verified','intent_graph':'verified','checkpoint_contract':'verified','structural_drift_replay':'verified','verification_replay':'verified','convergence_replay':'verified','merged':result['merged'],'ledger_root':root,'limitations':'Does not re-execute tests or attest an external Git server.'}


def verify_intent_evidence(ev,spec,events,*,semantics=SEGMENT_V2):
    init=events[0]['payload']
    if init['baseline_hash'] != file_hash(ev/'baseline.py'): raise ValueError('baseline provenance mismatch')
    proposals={e['hash']:e['payload'] for e in events if e['kind']=='proposal'}
    cp_events=[e['payload'] for e in events if e['kind']=='checkpoint']
    drift_events=[e['payload'] for e in events if e['kind']=='intent_drift']
    eval_events=[e['payload'] for e in events if e['kind']=='evaluation']
    if not len(cp_events)==len(drift_events)==len(eval_events): raise ValueError('incomplete candidate evidence')
    for cp,dr,evl in zip(cp_events,drift_events,eval_events):
        i=cp['iteration']; binding=cp['binding']; uni=cp['universal']; proposal=proposals.get(uni['proposal_event_hash'])
        if proposal is None or cp['diff_hash'] != file_hash(ev/f'iteration-{i}.diff') or cp['candidate_hash'] != file_hash(ev/f'candidate-{i}.py'): raise ValueError('checkpoint provenance mismatch')
        if digest((ev/f'candidate-{i}.py').read_text()) != proposal['files'].get('app/payments.py'): raise ValueError('proposal content mismatch')
        expected=make_checkpoint(spec['id'],proposal['session'],binding,cp['tree'],cp['paths'],cp['diff_hash'],uni['proposal_event_hash'],source=uni['source'])
        if uni!=expected or binding!=dr['binding'] or binding!=evl['binding'] or i!=dr['iteration'] or i!=evl['iteration']: raise ValueError('checkpoint binding mismatch')
        observed=drift(spec,{'app/payments.py':(ev/'baseline.py').read_text()},{'app/payments.py':(ev/f'candidate-{i}.py').read_text()},cp['paths'],semantics=semantics)
        coverage=requirement_coverage(spec,evl['checks'],cp['paths'],semantics=semantics)
        if observed!=dr['result'] or evl['checks']['intent_drift']!=observed['passed'] or evl['checks']['requirement_coverage']!=all(r['verified'] for r in coverage) or evl['checks']['checkpoint_binding'] is not True: raise ValueError('intent evaluation mismatch')
    read=lambda name:json.loads((ev/name).read_text())
    graph=build_graph(spec,events)
    if read('intent-graph.json')!=graph or (ev/'intent-graph.mmd').read_text()!=graph_mermaid(graph): raise ValueError('intent graph mismatch')
    if read('checkpoints.json')!=[cp['universal'] for cp in cp_events] or read('intent-drift.json')!=drift_events: raise ValueError('derived checkpoint or drift mismatch')
    d=next(e['payload'] for e in events if e['kind']=='policy_decision')['inputs']
    coverage=requirement_coverage(spec,d['checks'],d['paths'],semantics=semantics)
    if read('requirement-coverage.json')!=coverage: raise ValueError('requirement coverage mismatch')
    if d['termination']=='passed' and not any(e['binding']==d['binding'] and e['checks']==d['checks'] for e in eval_events): raise ValueError('missing decision-bound evaluation')
    report=read('report.json')
    if report['requirement_coverage']!=coverage or report['graph']!={'nodes':len(graph['nodes']),'edges':len(graph['edges'])}: raise ValueError('intent report mismatch')


def verify_verification_evidence(ev,spec,policy,events):
    read=lambda name:json.loads((ev/name).read_text())
    plan_data=read('verification-plan.json'); mutations=read('mutation-report.json'); baseline_execution=read('baseline-observations.json'); init=events[0]['payload']
    if init['baseline_observations']!=digest(baseline_execution): raise ValueError('baseline observation mismatch')
    if plan_data!=plan() or init['mutation_report']!=digest(mutations): raise ValueError('verification plan or mutation evidence mismatch')
    sources=mutation_sources(FIXED)
    if [m['mutant'] for m in mutations]!=list(sources): raise ValueError('mutation inventory mismatch')
    for m in mutations:
        killed=m['execution']['status']=='ok' and not all(evaluate(plan_data,m['execution'],baseline_execution)['checks'].values())
        if m['source_digest']!=digest(sources[m['mutant']]) or killed!=m['killed']: raise ValueError('mutation replay mismatch')
    verification=[e['payload'] for e in events if e['kind']=='verification']; evals=[e['payload'] for e in events if e['kind']=='evaluation']; checkpoints=[e['payload'] for e in events if e['kind']=='checkpoint']; controls=[e['payload'] for e in events if e['kind']=='convergence']
    if read('verification.json')!=verification or len(verification)!=len(evals) or len(evals)!=len(checkpoints): raise ValueError('verification inventory mismatch')
    governor=Governor(policy); required=set(spec['criteria'])|set(policy['required_checks'])
    for v,e,cp in zip(verification,evals,checkpoints):
        expected=evaluate(plan_data,v['execution'],baseline_execution)
        if v['binding']!=e['binding'] or v['iteration']!=e['iteration'] or expected!=v['result'] or any(e['checks'].get(k)!=val for k,val in expected['checks'].items()) or e['checks'].get('mutation_adequacy')!=all(m['killed'] for m in mutations): raise ValueError('verification replay mismatch')
        if cp['universal']['source']=='harness_refresh': continue
        i=e['iteration']; governor.observe(iteration=i,tree=cp['tree'],checks=e['checks'],required=required,paths=cp['paths'],case_count=len(plan_data['cases']),diff_bytes=(ev/f'iteration-{i}.diff').stat().st_size,execution_ok=v['execution']['status']=='ok')
    if governor.history!=controls or read('convergence.json')!=controls: raise ValueError('convergence replay mismatch')
    termination=next(e['payload']['reason'] for e in events if e['kind']=='termination')
    if controls and controls[-1]['action']!=termination: raise ValueError('convergence termination mismatch')
    report=read('report.json')
    if report['executor']!=init['executor'] or report['mutation_score']!={'killed':sum(m['killed'] for m in mutations),'total':len(mutations)} or report['verification_cases_per_candidate']!=len(plan_data['cases']) or report['termination']!=termination: raise ValueError('verification report mismatch')
