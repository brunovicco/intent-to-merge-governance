"""Host-side oracle and fixture-only execution adapters.

A candidate reports observations, never gate decisions. Docker limits host exposure,
not the ability of malicious Python to fabricate observations inside its process.
"""
from __future__ import annotations
import json, os, random, shutil, subprocess, sys, tempfile, uuid
from pathlib import Path
from .core import digest, file_hash

WORKER = '''import importlib.util, json, sys, copy
spec = importlib.util.spec_from_file_location("candidate", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
results = []
for case in json.load(sys.stdin):
    store = {}; observations = []
    for op in case["operations"]:
        try:
            value = m.authorize(op[1]) if op[0] == "authorize" else m.register(store, op[1], op[2])
            observations.append({"value":copy.deepcopy(value),"store":copy.deepcopy(store)})
        except Exception as e:
            observations.append({"error":type(e).__name__,"store":copy.deepcopy(store)})
    results.append(observations)
print(json.dumps(results, sort_keys=True, allow_nan=False))
'''
GROUPS = ('positive_amount','same_key_same_payment','distinct_keys','conflicting_payload','property_invariants','differential_compatibility','contract_flow')

def plan(seed=104):
    cases=[]
    def add(group, ops):
        cases.append({'id':f'{group}:{len(cases)}','group':group,'operations':ops})
    reg=lambda k,a:['register',k,a]
    add('positive_amount',[reg('a',0)])
    add('same_key_same_payment',[reg('a',10),reg('a',10)])
    add('distinct_keys',[reg('a',10),reg('b',10)])
    add('conflicting_payload',[reg('a',10),reg('a',20)])
    rng=random.Random(seed)
    for i in range(24):
        a=rng.randint(1,10000); b=a+rng.randint(1,100); k=f'key-{i}'
        add('property_invariants',[reg(k,a)]*rng.randint(2,7)+[reg(k,b),reg(k,a),reg(k+'-other',b),reg('invalid',-a)])
    for i in range(8):
        add('differential_compatibility',[reg(f'k{j}',rng.randint(1,1000)) for j in range(i+1)])
    add('contract_flow',[['authorize','payment-operator'],['authorize','viewer'],reg('a',5),reg('a',5),reg('b',7),reg('a',8)])
    return {'schema_version':'1.0','seed':seed,'cases':cases}

def expected(case):
    # Compatibility cases restrict input to distinct positive keys, where the
    # registered baseline and intended implementation have identical behavior.
    store={}; observations=[]
    for op in case['operations']:
        if op[0]=='authorize': result={'value':op[1]=='payment-operator'}
        else:
            _,key,amount=op
            if amount<=0 or (key in store and store[key]['amount']!=amount): result={'error':'ValueError'}
            else:
                if key not in store: store[key]={'id':len(store)+1,'amount':amount}
                result={'value':dict(store[key])}
        observations.append({**result,'store':{k:dict(v) for k,v in store.items()}})
    return observations

def evaluate(plan_data, execution, baseline=None):
    cases=plan_data['cases']; observations=execution.get('observations'); valid=execution.get('status')=='ok' and isinstance(observations,list) and len(observations)==len(cases)
    outcomes=[]
    for i,c in enumerate(cases):
        passed=valid and digest(observations[i])==digest(expected(c))
        if c['group']=='differential_compatibility' and baseline is not None:
            base=baseline.get('observations'); passed=passed and baseline.get('status')=='ok' and isinstance(base,list) and len(base)==len(cases) and digest(base[i])==digest(observations[i])
        outcomes.append({'id':c['id'],'group':c['group'],'passed':bool(passed)})
    return {'checks':{g:all(o['passed'] for o in outcomes if o['group']==g) and any(o['group']==g for o in outcomes) for g in GROUPS},'outcomes':outcomes}

class Executor:
    def __init__(self, backend='local', image='python:3.11-slim', timeout=15):
        if backend not in ('local','docker'): raise ValueError('unknown executor')
        self.backend=backend; self.timeout=timeout; self.image=image; self.image_id=None
        if backend=='docker':
            if not shutil.which('docker'): raise ValueError('Docker unavailable; no local fallback')
            try:
                self.image_id=subprocess.run(['docker','image','inspect','--format','{{.Id}}',image],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
            except (OSError,subprocess.SubprocessError) as e: raise ValueError('Docker daemon or preloaded image unavailable; no local fallback') from e
            if not self.image_id.startswith('sha256:'): raise ValueError('invalid Docker image ID')
    def metadata(self):
        return {'backend':self.backend,'image_id':self.image_id,'timeout_seconds':self.timeout,'isolation':'restricted_container' if self.backend=='docker' else 'none_fixture_only'}
    def command(self, directory, name):
        if self.backend=='local': return [sys.executable,'-I','-B',str(directory/'worker.py'),str(directory/'candidate.py')]
        return ['docker','run','--rm','--name',name,'--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--memory','128m','--cpus','0.5','--pids-limit','32','--ulimit','nofile=64:64','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m','--mount',f'type=bind,src={directory},dst=/input,readonly','--workdir','/input','-i',self.image_id,'python','-I','-B','/input/worker.py','/input/candidate.py']
    def execute(self, source, worker, plan_data):
        with tempfile.TemporaryDirectory(prefix='itm-worker-') as tmp:
            d=Path(tmp); d.chmod(0o755)
            for n,content in [('candidate.py',source),('worker.py',worker)]:
                f=d/n; f.write_text(content); f.chmod(0o444)
            name='itm-'+uuid.uuid4().hex
            try:
                result=subprocess.run(self.command(d,name),input=json.dumps(plan_data['cases']),text=True,capture_output=True,timeout=self.timeout,cwd=d,env={'PATH':os.environ.get('PATH','')} if self.backend=='local' else None)
                if result.returncode or len(result.stdout)>2_000_000: return {'status':'execution_failed','observations':None}
                try:
                    obs=json.loads(result.stdout,parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
                    return {'status':'ok','observations':obs}
                except (ValueError,RecursionError): return {'status':'invalid_output','observations':None}
            except subprocess.TimeoutExpired:
                return {'status':'timeout','observations':None}
            except OSError:
                return {'status':'execution_failed','observations':None}
            finally:
                if self.backend=='docker':
                    try: subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=5)
                    except (OSError,subprocess.SubprocessError): pass

def harness_digest(worker_path, plan_path):
    return digest({'worker':file_hash(worker_path),'plan':file_hash(plan_path),'oracle':file_hash(__file__),'governor':file_hash(Path(__file__).with_name('convergence.py'))})

def mutation_sources(fixed):
    return {
        'accept_invalid':fixed.replace('if amount <= 0:', 'if False:'),
        'ignore_conflict':fixed.replace('if store[key]["amount"] != amount:', 'if False:'),
        'wrong_identity':fixed.replace('"id": len(store) + 1','"id": 1'),
    }

def mutation_report(plan_data, executor, worker, fixed, baseline=None):
    records=[]
    for name,source in mutation_sources(fixed).items():
        execution=executor.execute(source,worker,plan_data); checks=evaluate(plan_data,execution,baseline)['checks']
        records.append({'mutant':name,'source_digest':digest(source),'execution':execution,'killed':execution['status']=='ok' and not all(checks.values())})
    return records
