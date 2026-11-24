import unittest
from unittest.mock import patch
from pathlib import Path
from intent_merge.verification import Executor, WORKER, plan, evaluate, mutation_report
from intent_merge.fixtures import FIXED
from intent_merge.convergence import Governor
from intent_merge.core import load_config
ROOT=Path(__file__).resolve().parents[1]
class VerificationTests(unittest.TestCase):
    def test_oracle_and_properties(self):
        p=plan(); e=Executor(); self.assertEqual(len(p['cases']),37)
        self.assertTrue(all(evaluate(p,e.execute(FIXED,WORKER,p))['checks'].values()))
        result=evaluate(p,e.execute(FIXED.replace('if amount <= 0:', 'if amount == 0:'),WORKER,p))['checks']
        self.assertTrue(all(result[k] for k in ('positive_amount','same_key_same_payment','distinct_keys','conflicting_payload')))
        self.assertFalse(result['property_invariants'])
    def test_malformed_output_fails_closed(self):
        for data in (None, [], {'passed':True}):
            self.assertFalse(any(evaluate(plan(),{'status':'ok','observations':data})['checks'].values()))
    def test_mutations(self):
        self.assertTrue(all(m['killed'] for m in mutation_report(plan(),Executor(),WORKER,FIXED)))
    def test_missing_docker_never_falls_back(self):
        with patch('intent_merge.verification.shutil.which',return_value=None):
            with self.assertRaisesRegex(ValueError,'no local fallback'): Executor('docker')
    def test_docker_command_restrictions(self):
        with patch('intent_merge.verification.shutil.which',return_value='/bin/docker'),patch('intent_merge.verification.subprocess.run') as run:
            run.return_value.stdout='sha256:'+'a'*64; e=Executor('docker'); cmd=e.command(Path('/tmp/example'),'test')
        for flag in ('--read-only','--network','none','--cap-drop','ALL','--user','65534:65534','--memory','--pids-limit','--pull','never'):
            self.assertIn(flag,cmd)
        self.assertIn('type=bind,src=/tmp/example,dst=/input,readonly',cmd)
        self.assertNotIn('/var/run/docker.sock',' '.join(cmd))
    def test_governor_budget_and_regression(self):
        p=load_config(ROOT/'examples/policy.toml'); g=Governor(p); req={'a','b','intent_drift'}
        common=dict(required=req,paths=['app/payments.py'],case_count=37,diff_bytes=100)
        row=g.observe(iteration=1,tree='x',checks={'a':True,'b':False,'intent_drift':True},**common)
        self.assertEqual(row['action'],'continue')
        row=g.observe(iteration=2,tree='y',checks={'a':False,'b':False,'intent_drift':True},**common)
        self.assertEqual(row['reopened'],['a'])
        g=Governor(p); row=g.observe(iteration=1,tree='x',checks={'a':True,'b':True,'intent_drift':True},**{**common,'diff_bytes':999999})
        self.assertEqual(row['action'],'budget_exceeded')
