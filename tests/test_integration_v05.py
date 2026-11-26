import copy, json, tempfile, unittest
from pathlib import Path
from intent_merge.evidence_profile import HISTORICAL_V1
from intent_merge.github import preflight, policy_from, CHECK_NAME
from intent_merge.agent_import import import_agent
from intent_merge.explorer import render
ROOT=Path(__file__).resolve().parents[1]
HEAD='a'*40; BASE='b'*40
class FixtureAPI:
    installation_id = 1
    installation_repository = 'OWNER/REPO'
    def __init__(self):
        self.pr={'head':{'sha':HEAD,'repo':{'full_name':'OWNER/REPO'}},'base':{'sha':BASE,'ref':'main','repo':{'full_name':'OWNER/REPO'}},'state':'open','draft':False,'changed_files':1,'user':{'id':99}}
        self.files=[{'filename':'app/payments.py','status':'modified'}]
        self.reviews=[{'id':i,'user':{'id':uid,'type':'User'},'state':'APPROVED','commit_id':HEAD} for i,uid in [(1,10001),(2,10002)]]
        self.checks=[{'id':3,'name':'trusted-ci','app':{'id':12345},'head_sha':HEAD,'status':'completed','conclusion':'success','external_id':None}]
        self.posts=[]; self.reads=0; self.move=False; self.installation_app_id=789
    def request(self,path,payload=None):
        if payload is not None: self.posts.append((path,payload)); return {**payload, 'id':44, 'app':{'id':self.installation_app_id}}
        if '/check-suites?' in path:
            return {'total_count': 1, 'check_suites': [{'id': 1}]}
        if '/check-runs?' in path:
            return {'total_count': len(self.checks), 'check_runs': copy.deepcopy(self.checks)}
        self.reads+=1; obj=copy.deepcopy(self.pr)
        if self.move and self.reads>1: obj['head']['sha']='c'*40
        return obj
    def pages(self,path,key=None):
        return iter(self.files if path.endswith('/files') else self.reviews)
class GitHubTests(unittest.TestCase):
    def setUp(self): self.api=FixtureAPI(); self.policy=policy_from(ROOT/'examples/github-policy.toml')
    def run_gate(self,publish=False): return preflight(self.api,'OWNER/REPO',1,self.policy,publish=publish)
    def test_pass_read_only(self):
        r=self.run_gate(); self.assertEqual(r['decision'],'PASS'); self.assertFalse(r['full_itm_authorization']); self.assertEqual(self.api.posts,[])
    def test_publish_sha(self):
        self.assertEqual(self.run_gate(True)['published_check_id'],44); p=self.api.posts[0][1]; self.assertEqual((p['name'],p['head_sha'],p['conclusion']),(CHECK_NAME,HEAD,'success'))
    def test_stale_review(self):
        self.api.reviews[1]['commit_id']=BASE; self.assertIn('approval:security',self.run_gate()['reasons'])
    def test_self_approval(self):
        self.api.pr['user']['id']=10001; self.assertIn('approval:engineering',self.run_gate()['reasons'])
    def test_dismissed(self):
        r=copy.deepcopy(self.api.reviews[1]); r.update(id=5,state='DISMISSED'); self.api.reviews.append(r); self.assertEqual(self.run_gate()['decision'],'BLOCK')
    def test_protected_rename(self):
        self.api.files[0].update(status='renamed',previous_filename='tests/acceptance.py'); self.assertIn('scope:tests/acceptance.py',self.run_gate(True)['reasons']); self.assertEqual(self.api.posts[0][1]['conclusion'],'failure')
    def test_wrong_app(self):
        self.api.checks[0]['app']['id']=77; self.assertIn('check:trusted-ci',self.run_gate()['reasons'])
    def test_latest_rerun_fails(self):
        c=copy.deepcopy(self.api.checks[0]); c.update(id=4,status='in_progress',conclusion=None); self.api.checks.append(c); self.assertEqual(self.run_gate()['decision'],'BLOCK')
    def test_moved_head(self):
        self.api.move=True
        with self.assertRaisesRegex(ValueError,'changed'): self.run_gate(True)
        self.assertEqual(self.api.posts,[])
    def test_missing_files(self):
        self.api.pr['changed_files']=2
        with self.assertRaisesRegex(ValueError,'incomplete'): self.run_gate(True)
    def test_fork(self):
        self.api.pr['head']['repo']['full_name']='fork/repo'
        with self.assertRaisesRegex(ValueError,'fork'): self.run_gate(True)
    def test_policy_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'policy.toml'; p.write_text((ROOT/'examples/github-policy.toml').read_text().replace('10002','10001'))
            with self.assertRaisesRegex(ValueError,'overlapping'): policy_from(p)
class AgentExplorerTests(unittest.TestCase):
    def test_native_import(self):
        for provider in ('claude','codex'):
            r=import_agent(provider,ROOT/f'examples/native-sessions/{provider}.jsonl',head=HEAD)
            self.assertEqual(r['session']['tool_types'],['write']); self.assertFalse(r['merge_authority']); self.assertEqual(r['commit_binding'],'self_reported'); self.assertNotIn('not retained',json.dumps(r)); self.assertNotIn('example.py',json.dumps(r))
    def test_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log'; p.write_text('{"type":"thread.started","thread_id":"x"}\n')
            with self.assertRaisesRegex(ValueError,'completed'): import_agent('codex',p)
    def test_mixed_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log'; p.write_text('{"type":"thread.started","thread_id":"x"}\n'+(ROOT/'examples/native-sessions/codex.jsonl').read_text())
            with self.assertRaisesRegex(ValueError,'one successfully'): import_agent('codex',p)
    def test_explorer_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'explorer.html'; s=ROOT/'examples/sample-evidence'; r=render([s/'signed-demo-bundle'],s/'demo-signer.pub',p,profile=HISTORICAL_V1)
            self.assertEqual(r['verified_bundles'],1); self.assertIn('synthetic-demo',p.read_text()); self.assertIn('not production authorization',p.read_text())
