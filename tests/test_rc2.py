import copy,importlib.util,tempfile,unittest
from pathlib import Path
from intent_merge.capture import command
from intent_merge.live_benchmark import SCENARIOS,evaluate,structural,execute_one,summarize
from intent_merge.verification import Executor
from intent_merge.github import policy_from
from test_integration_v05 import FixtureAPI,ROOT,HEAD
spec=importlib.util.spec_from_file_location('github_lab',ROOT/'scripts/github_lab.py');lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
APP=5897543
class LabAPI(FixtureAPI):
    installation_repository = lab.LAB
    def __init__(self):
        super().__init__();self.installation_app_id=APP;self.pr['head']['repo']['full_name']=lab.LAB;self.pr['base']['repo']['full_name']=lab.LAB;self.reviews=[];self.remote={};self.required=False;self.lost=False
    def pages(self,path,key=None):
        if path.endswith('/rulesets'):return iter([{'id':1}])
        return super().pages(path,key)
    def request(self,path,payload=None,*,method=None):
        if path.endswith('/rulesets/1'):return {'rules':[{'type':'required_status_checks','parameters':{'required_status_checks':[{'context':lab.TRANSPORT}] if self.required else []}}]}
        if payload is not None:
            self.posts.append((path,payload));self.remote.update(payload);self.remote.update(id=44,app={'id':APP})
            if self.lost:raise ValueError('response lost')
            return copy.deepcopy(self.remote)
        if path.endswith('/check-runs/44'):return copy.deepcopy(self.remote)
        return super().request(path)
class RC2Tests(unittest.TestCase):
    def test_claude_permissions(self):
        c=command('claude','prompt');self.assertIn('acceptEdits',c);self.assertNotIn('--dangerously-skip-permissions',c);self.assertNotIn('Bash',c[c.index('--tools')+1])
    def test_reference_and_baseline_oracles(self):
        e=Executor()
        for sid,s in SCENARIOS.items():
            if sid=='PAY-104':continue
            with self.subTest(sid=sid):
                self.assertTrue(evaluate(s['fixed'],s,e)['passed']);bad=evaluate(s['base'],s,e);self.assertFalse(bad['passed']);self.assertTrue(bad['weak_ci_passed'])
    def test_structural_guard(self):
        s=SCENARIOS['REF-504'];self.assertFalse(structural(s['fixed'].replace('role == "operator"','True'),s));self.assertFalse(structural(s['fixed'].replace('def total(values):','def total(values, extra=1):'),s));self.assertFalse(structural(s['fixed']+'\nimport os\n',s))
    def test_fixture_trial(self):
        r=execute_one('claude','PAY-104',Executor(),5,ROOT,True);self.assertTrue(r['passed']);self.assertEqual(r['verification']['cases'],37);self.assertEqual(r['mode'],'synthetic_fixture');self.assertFalse(r['merge_authority']);self.assertEqual(summarize([r])['claude']['passed'],1)
    def test_negative_real_path_mock_api(self):
        p=policy_from(ROOT/'examples/github-policy.toml');p['repository']=lab.LAB
        with tempfile.TemporaryDirectory() as tmp:
            api=LabAPI();r=lab.lab_negative(api,p,1,APP,Path(tmp),True);self.assertEqual(r['report']['decision'],'BLOCK');self.assertEqual(r['remote']['conclusion'],'failure');self.assertEqual(r['journal_state'],'DONE');self.assertFalse(r['merge_authority']);self.assertFalse(list((Path(tmp)/'receipts').iterdir()))
    def test_transport_mock_api(self):
        p=policy_from(ROOT/'examples/github-policy.toml');p['repository']=lab.LAB
        with tempfile.TemporaryDirectory() as tmp:
            api=LabAPI();r=lab.transport(api,p,1,APP,Path(tmp));self.assertEqual(r['created']['conclusion'],'success');self.assertEqual(r['revoked']['conclusion'],'failure');self.assertFalse(r['authorization_revocation_validated']);self.assertEqual(r['created']['id'],r['revoked']['id'])
    def test_transport_must_not_be_required(self):
        p=policy_from(ROOT/'examples/github-policy.toml');p['repository']=lab.LAB
        with tempfile.TemporaryDirectory() as tmp:
            api=LabAPI();api.required=True
            with self.assertRaisesRegex(ValueError,'never be required'):lab.transport(api,p,1,APP,Path(tmp))
            self.assertFalse(api.posts)
    def test_transport_lost_response_journal(self):
        p=policy_from(ROOT/'examples/github-policy.toml');p['repository']=lab.LAB
        with tempfile.TemporaryDirectory() as tmp:
            api=LabAPI();api.lost=True;out=Path(tmp)
            with self.assertRaises(ValueError):lab.transport(api,p,1,APP,out)
            self.assertTrue((out/'publication-intent.json').is_file());self.assertFalse((out/'created.json').exists());self.assertEqual(len(api.posts),1)
