import copy, hashlib,hmac,json,tempfile,time,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intent_merge.control_plane import *
from intent_merge.budget import BudgetController,Limits,normalized
from intent_merge.merge_group import parse_merge_group
from intent_merge.hardening import verify_control_receipts

class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.keys={c:Ed25519PrivateKey.generate() for c in (*CONTROL_NAMES,'aggregate')};self.trust={c:public(k) for c,k in self.keys.items()};self.nonce='a'*32;self.now=1800000000
    def receipts(self,case):return {c:receipt(c,case,self.nonce,self.keys[c],self.now) for c in CONTROL_NAMES}
    def test_happy(self):self.assertEqual(set(evaluate_receipts(binding('happy',self.nonce),self.receipts('happy'),self.trust,self.now).values()),{'PASS'})
    def test_denials(self):
        for case,c in [('scope','intent'),('behavior','verification'),('provenance','provenance'),('loop','convergence'),('missing_approval','authorization'),('circuit_open','operational_autonomy')]:
            with self.subTest(case=case):self.assertEqual(evaluate_receipts(binding(case,self.nonce),self.receipts(case),self.trust,self.now)[c],'DENIED')
    def test_wrong_binding_and_expiry(self):
        for case in ('wrong_candidate','wrong_nonce','expired'):
            with self.subTest(case=case):self.assertEqual(evaluate_receipts(binding(case,self.nonce),self.receipts(case),self.trust,self.now)['verification'],'INVALID')
    def test_tampered(self):
        r=self.receipts('happy');r['verification']['artifact']['cases']=0;self.assertEqual(evaluate_receipts(binding('happy',self.nonce),r,self.trust,self.now)['verification'],'INVALID')
    def test_wrong_signer(self):
        r=self.receipts('happy');s=r['verification']['statement'];r['verification']['signature']=sign(self.keys['intent'],RECEIPT,s);self.assertEqual(evaluate_receipts(binding('happy',self.nonce),r,self.trust,self.now)['verification'],'INVALID')
    def test_missing(self):
        r=self.receipts('happy');r.pop('verification');self.assertEqual(evaluate_receipts(binding('happy',self.nonce),r,self.trust,self.now)['verification'],'MISSING')
    def test_shared_key(self):
        self.trust['aggregate']=self.trust['intent'];with_error=lambda:evaluate_receipts(binding('happy',self.nonce),{},self.trust,self.now);self.assertRaises(ValueError,with_error)
    def test_live_gate_rejects_lab_profile(self):
        r=self.receipts('happy');self.assertRaises(ValueError,verify_control_receipts,list(r.values()),{k:v for k,v in self.trust.items() if k!='aggregate'}, {},self.now)
    def test_key_files_separate(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'keys';trust=init(root);self.assertEqual(len(set(trust.values())),7);self.assertEqual(public(read_key(root/'intent/key.pem')),trust['intent']);self.assertEqual((root/'intent/key.pem').stat().st_mode&0o777,0o600)

class BudgetTests(unittest.TestCase):
    def setUp(self):self.t={'input_tokens':100,'output_tokens':10,'cached_input_tokens':80}
    def test_normalization(self):
        self.assertEqual(normalized('codex',self.t)['input_total'],100);self.assertEqual(normalized('codex',self.t)['uncached'],20);self.assertEqual(normalized('claude',{'input_tokens':1,'output_tokens':5,'cache_creation_input_tokens':30,'cache_read_input_tokens':69})['input_total'],100);self.assertIsNone(normalized('claude',self.t))
    def test_repeat_and_budget(self):
        for cap,expected in [(500,'STOP_REPEAT'),(200,'STOP_BUDGET')]:
            g=BudgetController(Limits(3,cap,5000));self.assertTrue(g.admit());g.record(provider='codex',telemetry=self.t,elapsed_ms=20,tree='a',passed=False,scope_valid=True);self.assertTrue(g.admit());r=g.record(provider='codex',telemetry=self.t,elapsed_ms=20,tree='a',passed=False,scope_valid=True);self.assertEqual(r['state'],expected);self.assertFalse(g.admit())
    def test_fail_closed(self):
        g=BudgetController(Limits());self.assertTrue(g.admit());self.assertFalse(g.admit());self.assertEqual(g.record(provider='codex',telemetry=None,elapsed_ms=10,tree='a',passed=True,scope_valid=True)['state'],'STOP_UNKNOWN_USAGE');self.assertFalse(g.admit())
    def test_success(self):
        g=BudgetController(Limits());self.assertTrue(g.admit());self.assertEqual(g.record(provider='codex',telemetry=self.t,elapsed_ms=10,tree='a',passed=True,scope_valid=True)['state'],'PASSED');self.assertFalse(g.admit())

class MergeGroupTests(unittest.TestCase):
    def payload(self):return {'action':'checks_requested','repository':{'full_name':'fixture/lab'},'installation':{'id':1},'merge_group':{'head_sha':'a'*40,'base_sha':'b'*40,'head_ref':'refs/heads/gh-readonly-queue/main/pr-1','base_ref':'refs/heads/main'}}
    def parse(self,p,valid=True):
        raw=json.dumps(p).encode();secret=b'x'*32;sig='sha256='+hmac.new(secret,raw,hashlib.sha256).hexdigest() if valid else 'invalid';return parse_merge_group(raw,sig,'merge_group','delivery-1',secret,'fixture/lab',1)
    def test_valid(self):self.assertEqual(self.parse(self.payload())['decision'],'BLOCK_PENDING_FRESH_GROUP_VERIFICATION')
    def test_bad_hmac_and_repo(self):
        self.assertRaises(ValueError,self.parse,self.payload(),False);p=self.payload();p['repository']['full_name']='wrong/repo';self.assertRaises(ValueError,self.parse,p)
    def test_wrong_ref(self):
        p=self.payload();p['merge_group']['head_ref']='refs/heads/other';self.assertRaises(ValueError,self.parse,p)
