import base64, json, shutil, tempfile, unittest
from pathlib import Path
from intent_merge.runner import run
from intent_merge.bundle import keygen, pack, verify, pae
from intent_merge.replay import replay

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'examples/spec.toml'; POLICY=ROOT/'examples/policy.toml'; PROPOSED=ROOT/'examples/policy-proposed.toml'

class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.root=Path(cls.tmp.name)
        cls.priv=cls.root/'signer.pem'; cls.pub=cls.root/'signer.pub'; keygen(cls.priv,cls.pub)
        cls.other=cls.root/'other.pub'; keygen(cls.root/'other.pem',cls.other)
        cls.bundles=[]
        for scenario in ('happy','missing-approval','intent-drift','stale-approval','property-regression','stale-eval','stale-base','scope-violation'):
            out=cls.root/scenario; run(scenario,out,SPEC,POLICY)
            bundle=cls.root/(scenario+'-bundle'); pack(out,bundle,cls.priv); cls.bundles.append(bundle)
            shutil.rmtree(out) # prove no original repo or HMAC secret required
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def copy(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        return Path(shutil.copytree(self.bundles[0],Path(tmp.name)/'bundle'))
    def test_offline_all(self):
        for i,b in enumerate(self.bundles):
            r=verify(b,self.pub); self.assertEqual(r['signature'],'verified'); self.assertEqual(r['merged'],i==0)
            self.assertFalse((b/'repo').exists()); self.assertTrue(all(v.startswith('ed25519-public:') for v in json.loads((b/'approval-trust.json').read_text()).values()))
    def test_wrong_key(self):
        with self.assertRaisesRegex(ValueError,'untrusted signer'): verify(self.bundles[0],self.other)
    def test_artifact_tamper(self):
        b=self.copy(); p=b/'evidence/report.json'; p.write_text('{}')
        with self.assertRaisesRegex(ValueError,'signed subject'): verify(b,self.pub)
    def test_envelope_tamper(self):
        b=self.copy(); p=b/'attestation.json'; d=json.loads(p.read_text()); d['signatures'][0]['sig']=base64.b64encode(b'0'*64).decode(); p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'signature'): verify(b,self.pub)
    def test_trust_tamper(self):
        b=self.copy(); p=b/'approval-trust.json'; d=json.loads(p.read_text()); d['reviewer']=d['security']; p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'signed subject'): verify(b,self.pub)
    def test_extra_file(self):
        b=self.copy(); (b/'evidence/extra').write_text('extra')
        with self.assertRaisesRegex(ValueError,'signed subject'): verify(b,self.pub)
    def test_removed_file(self):
        b=self.copy(); (b/'evidence/ledger.jsonl').unlink()
        with self.assertRaisesRegex(ValueError,'signed subject'): verify(b,self.pub)
    def test_symlink(self):
        b=self.copy(); (b/'evidence/alias').symlink_to(b/'evidence/report.json')
        with self.assertRaisesRegex(ValueError,'non-regular'): verify(b,self.pub)
    def test_identity_replay(self):
        r=replay(self.bundles,self.pub,POLICY); self.assertEqual(r['transitions'],{'unchanged_allow':1,'unchanged_deny':7,'would_allow':0,'would_deny':0})
    def test_counterfactual(self):
        r=replay(self.bundles,self.pub,PROPOSED); self.assertEqual(r['transitions'],{'unchanged_allow':1,'unchanged_deny':6,'would_allow':1,'would_deny':0}); self.assertEqual([x['scenario'] for x in r['rows'] if x['transition']=='would_allow'],['missing-approval']); self.assertTrue(all(x['requires_fresh_authorization'] for x in r['rows']))
    def test_unknown_check(self):
        p=self.root/'unknown.toml'; p.write_text(POLICY.read_text().replace('required_checks = [','required_checks = ["new_unobserved_check", ')); r=replay(self.bundles,self.pub,p); self.assertEqual(r['counterfactually_eligible'],0); self.assertEqual(r['transitions']['would_deny'],1)
    def test_unsupported_policy_change(self):
        p=self.root/'execution.toml'; p.write_text(POLICY.read_text().replace('max_iterations = 4','max_iterations = 5'))
        with self.assertRaisesRegex(ValueError,'unsupported counterfactual'): replay(self.bundles,self.pub,p)
    def test_duplicate_history(self):
        with self.assertRaisesRegex(ValueError,'duplicate'): replay([self.bundles[0]]*2,self.pub,POLICY)
    def test_pae(self): self.assertEqual(pae('text/plain',b'hello'),b'DSSEv1 10 text/plain 5 hello')
