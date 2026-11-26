import copy, json, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from intent_merge.evidence_profile import HISTORICAL_V1
from intent_merge.autonomy import ROLES, ZERO, replay, sign_event, gate, validate_case
from intent_merge.core import digest
from intent_merge.verification import expected
from intent_merge.operations_demo import study
ROOT=Path(__file__).resolve().parents[1]; CORPUS=ROOT/'examples/amgb-v1'

class AutonomyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.tmp.cleanup)
        cls.path=Path(cls.tmp.name)/'study'; cls.report=study(CORPUS/'bundles',CORPUS/'signer.pub',cls.path)
        cls.sample=json.loads((cls.path/'config.json').read_text()); cls.events=json.loads((cls.path/'events.json').read_text()); cls.anchor=json.loads((cls.path/'anchor.json').read_text())['root']
    def setUp(self):
        self.cfg=copy.deepcopy(self.sample); self.keys={r:Ed25519PrivateKey.generate() for r in self.cfg['keys']}; self.cfg['keys']={r:k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() for r,k in self.keys.items()}; self.log=[]
    def add(self,k,**p): self.log.append(sign_event(self.cfg,self.log,k,p,self.keys[ROLES[k]]))
    def state(self): return replay(self.cfg,self.log,self.log[-1]['hash'] if self.log else ZERO)
    def incident(self): self.add('incident',id='I',severity='critical')
    def proposal(self):
        self.case=validate_case([['register','k',1],['register','k',1]])
        self.add('propose_eval',id='E',incident='I',operations=self.case['operations'])
    def approve(self): self.add('approve_eval',id='E',case_digest=digest(self.case))
    def reference(self,n=1): return {'root':format(n,'064x'),'head':format(n,'040x')}
    def result(self,n=1,passed=True): self.add('eval_result',id='E',case_digest=digest(self.case),**self.reference(n),observations=expected(self.case) if passed else [])
    def test_demo_stages(self):
        s=self.report['stages']; self.assertEqual([x['level'] for x in s],[2,0,0,0,1,1,1,2,2,2,2,2,1]); self.assertEqual([x['gate']['status'] for x in s],['ELIGIBLE','BLOCKED','BLOCKED','BLOCKED','BLOCKED','BLOCKED','BLOCKED','ELIGIBLE','BLOCKED','ELIGIBLE','BLOCKED','ELIGIBLE','BLOCKED']); self.assertFalse(any(x['gate']['merge_authority'] for x in s))
    def test_incident_regression(self):
        self.assertEqual(self.report['regression_fixture_original_cases_passed'],37); self.assertFalse(self.report['regression_fixture_passed'])
    def test_replay_exact(self): self.assertEqual(replay(self.sample,self.events,self.anchor).summary(),self.report['state'])
    def test_truncation(self):
        with self.assertRaisesRegex(ValueError,'external root mismatch'): replay(self.sample,self.events[:-1],self.anchor)
    def test_tamper_even_rehashed(self):
        e=copy.deepcopy(self.events[:1]); e[0]['payload']['severity']='major'; e[0]['hash']=digest({k:v for k,v in e[0].items() if k!='hash'})
        with self.assertRaisesRegex(ValueError,'signature'): replay(self.sample,e,e[0]['hash'])
    def test_wrong_role(self):
        e=sign_event(self.cfg,[],'incident',{'id':'I','severity':'critical'},self.keys['proposer'])
        with self.assertRaisesRegex(ValueError,'signature'): replay(self.cfg,[e],e['hash'])
    def test_scope_change(self):
        c=copy.deepcopy(self.sample); c['scope']['model']='other'
        with self.assertRaisesRegex(ValueError,'scope mismatch'): replay(c,self.events,self.anchor)
    def test_shared_key(self):
        self.cfg['keys']['reviewer']=self.cfg['keys']['proposer']
        with self.assertRaisesRegex(ValueError,'distinct role keys'): self.state()
    def test_critical(self): self.incident(); self.assertEqual(self.state().level,0)
    def test_major(self): self.add('incident',id='I',severity='major'); self.assertEqual(self.state().level,1)
    def test_no_premature_resolution(self):
        self.incident(); self.proposal(); self.add('resolve',id='I',**self.reference())
        with self.assertRaisesRegex(ValueError,'regression evidence'): self.state()
    def test_unapproved_eval(self):
        self.incident(); self.proposal(); self.result()
        with self.assertRaisesRegex(ValueError,'unapproved'): self.state()
    def test_failed_eval_cannot_resolve(self):
        self.incident(); self.proposal(); self.approve(); self.result(passed=False); self.add('resolve',id='I',**self.reference())
        with self.assertRaisesRegex(ValueError,'regression evidence'): self.state()
    def test_result_bound_to_candidate(self):
        self.incident(); self.proposal(); self.approve(); self.result(); self.add('resolve',id='I',**self.reference(2))
        with self.assertRaisesRegex(ValueError,'regression evidence'): self.state()
    def test_early_promotion(self):
        self.incident(); self.proposal(); self.approve(); self.result(); self.add('resolve',id='I',**self.reference()); self.add('promote',level=2)
        with self.assertRaisesRegex(ValueError,'promotion conditions'): self.state()
    def test_repeated_outcome(self):
        self.add('outcome',status='clean',**self.reference()); self.add('outcome',status='clean',**self.reference())
        with self.assertRaisesRegex(ValueError,'duplicate outcome'): self.state()
    def test_adverse_threshold(self):
        for n in (1,2): self.add('outcome',status='adverse',**self.reference(n))
        self.assertEqual(self.state().level,1)
    def test_no_arbitrary_executable_eval(self):
        with self.assertRaises(ValueError): validate_case([['exec','arbitrary']])
    def test_gate_never_bypasses_base(self):
        r=gate(self.cfg,[],ZERO,CORPUS/'bundles/missing-approval',CORPUS/'signer.pub', profile=HISTORICAL_V1); self.assertIn('base_policy_denied',r['reasons']); self.assertFalse(r['merge_authority'])
    def test_bundle_scope_pin(self):
        self.cfg['scope']['harness']='0'*64
        with self.assertRaisesRegex(ValueError,'scope pins'): gate(self.cfg,[],ZERO,CORPUS/'bundles/happy',CORPUS/'signer.pub', profile=HISTORICAL_V1)
