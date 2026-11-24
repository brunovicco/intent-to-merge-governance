import hashlib,hmac,json,tempfile,unittest,copy
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intent_merge.integrated import run,attest,check_receipt,decision,Lifecycle,PROFILE
from intent_merge.budget import Limits
from intent_merge.control_plane import public
from intent_merge.core import canonical
from intent_merge.verification import Executor
from intent_merge.hardening import verify_control_receipts
from intent_merge.operational import CONTROLS

class IntegratedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def fixture(self,case='first',limits=Limits()):
        p=self.root/case;r=run(p,'claude',limits,fixture=case);return p,r
    def signed(self):
        p,r=self.fixture();k=Ed25519PrivateKey.generate();return p,r,attest(p/'repo',r,Executor('local'),k,100),public(k)
    def test_first(self):
        p,r=self.fixture();self.assertEqual(r['status'],'PASSED');self.assertEqual(len(r['attempts']),1);self.assertFalse(r['merge_authority'])
    def test_repair(self):
        p,r=self.fixture('repair');self.assertEqual(r['status'],'PASSED');self.assertEqual(len(r['attempts']),2);self.assertFalse(r['attempts'][0]['verification']['verification']['passed']);self.assertTrue(r['attempts'][1]['verification']['verification']['passed'])
    def test_repeat(self):
        _,r=self.fixture('repeat');self.assertEqual(r['status'],'STOP_REPEAT');self.assertEqual(len(r['attempts']),2)
    def test_budget(self):
        _,r=self.fixture('budget',Limits(3,100,120000));self.assertEqual(r['status'],'STOP_BUDGET');self.assertIsNone(r['head'])
    def test_scope(self):
        _,r=self.fixture('scope');self.assertEqual(r['status'],'STOP_SCOPE');self.assertIsNone(r['attempts'][0]['verification'])
    def test_valid_receipt_not_authorization(self):
        _,r,rec,pub=self.signed();self.assertTrue(check_receipt(rec,pub,r,100));d=decision(rec,pub,r,100);self.assertTrue(d['candidate_verified']);self.assertEqual(d['decision'],'BLOCK')
    def test_wrong_candidate(self):
        _,r,rec,pub=self.signed();r['head']='f'*40;self.assertFalse(decision(rec,pub,r,100)['candidate_verified'])
    def test_tamper(self):
        _,r,rec,pub=self.signed();rec['artifact']['verification']['cases']=0;self.assertFalse(decision(rec,pub,r,100)['candidate_verified'])
    def test_expired_and_wrong_key(self):
        _,r,rec,pub=self.signed();self.assertFalse(decision(rec,pub,r,160)['candidate_verified']);self.assertFalse(decision(rec,public(Ed25519PrivateKey.generate()),r,100)['candidate_verified'])
    def test_external_validator_rejects(self):
        _,r,rec,pub=self.signed();pins={c:public(Ed25519PrivateKey.generate()) for c in CONTROLS};pins['verification']=pub
        with self.assertRaises(ValueError):verify_control_receipts([rec]+[{} for _ in range(5)],pins,{},100)
    def test_lifecycle_dedup_conflict_restart(self):
        p,r,rec,pub=self.signed();j=Lifecycle(p/'j.db');i=j.register(rec,pub,r,100);key=b'k'*32;e={'id':'a','kind':'review_withdrawn','head':r['head'],'base':r['base'],'at':100};raw=canonical(e);sig=lambda raw:hmac.new(key,raw,hashlib.sha256).hexdigest()
        with self.assertRaises(ValueError):j.event(raw,'bad',key)
        self.assertEqual(j.event(raw,sig(raw),key),'APPLIED');self.assertEqual(j.event(raw,sig(raw),key),'DUPLICATE');e['kind']='circuit_open';raw=canonical(e)
        with self.assertRaises(ValueError):j.event(raw,sig(raw),key)
        self.assertEqual(j.register(rec,pub,r,100),i);self.assertEqual(j.state(i)['state'],'REVOKED');j.close();j=Lifecycle(p/'j.db');self.assertEqual(j.state(i)['state'],'REVOKED');j.close()
    def test_reconciliation_binding(self):
        p,r,rec,pub=self.signed();j=Lifecycle(p/'j.db');i=j.register(rec,pub,r,100);j.reconcile('f'*40,r['base'],101);self.assertEqual(j.state(i)['reason'],'binding_changed');j.close()
    def test_reconciliation_expiry(self):
        p,r,rec,pub=self.signed();j=Lifecycle(p/'j.db');i=j.register(rec,pub,r,100);j.reconcile(r['head'],r['base'],160);self.assertEqual(j.state(i)['reason'],'expired');j.close()
if __name__=='__main__':unittest.main()
