import json, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from intent_merge.runner import run, audit, git, SCENARIOS
from intent_merge.core import evaluate_policy, digest, load_config
from intent_merge.approvals import decision_context, sign_approval

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT/'examples/spec.toml'; POLICY = ROOT/'examples/policy.toml'

class IntegrationTests(unittest.TestCase):
    def test_scenarios(self):
        expected = {'happy':None, 'missing-approval':'missing_approval:security', 'stale-approval':'missing_approval:engineering', 'scope-violation':'outside_spec', 'protected-path':'protected_path', 'loop':'not_converged', 'failed-eval':'check_failed:conflicting_payload', 'self-approval':'missing_approval:engineering', 'stale-base':'stale_base', 'stale-eval':'stale_evaluation','intent-drift':'check_failed:intent_drift','signature-drift':'check_failed:intent_drift','import-drift':'check_failed:intent_drift','property-regression':'check_failed:property_invariants','budget-exceeded':'not_converged','regression-loop':'not_converged'}
        with tempfile.TemporaryDirectory() as tmp:
            for scenario in SCENARIOS:
                with self.subTest(scenario=scenario):
                    out = Path(tmp)/scenario; r = run(scenario,out,SPEC,POLICY)
                    self.assertEqual(r['merged'],scenario=='happy')
                    self.assertEqual(r['decision']['authorized'],scenario=='happy')
                    if expected[scenario]: self.assertIn(expected[scenario],r['decision']['reasons'])
                    self.assertEqual(git(out/'repo','rev-parse','main'),r['main'])
                    self.assertEqual(audit(out,out/'anchor.json',out/'demo-trust.json')['merged'],r['merged'])
                    if scenario=='happy': self.assertEqual([h['passed'] for h in r['history']],[9,13])
                    if scenario=='loop': self.assertEqual(r['termination'],'repeated_tree')
                    if scenario=='protected-path': self.assertFalse((out/'repo/tests/acceptance.py').exists())
    def test_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'run'; run('happy',out,SPEC,POLICY)
            p=out/'evidence/ledger.jsonl'; p.write_text(p.read_text()+'\n')
            with self.assertRaisesRegex(ValueError,'artifact integrity'): audit(out,out/'anchor.json',out/'demo-trust.json')
    def test_tampered_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'run'; run('happy',out,SPEC,POLICY)
            p=out/'manifest.json'; p.write_text('{}')
            with self.assertRaisesRegex(ValueError,'manifest anchor'): audit(out,out/'anchor.json',out/'demo-trust.json')

class PolicyTests(unittest.TestCase):
    def test_invalid_signature_and_duplicate(self):
        s,p=load_config(SPEC),load_config(POLICY)
        pairs={actor:Ed25519PrivateKey.generate() for actor in ('reviewer','security')}
        keys={actor:'ed25519-public:'+key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex() for actor,key in pairs.items()}
        b={'head':'a'*40,'base':'b'*40,'spec':digest(s),'policy':digest(p),'harness':'c'*64,'path_semantics':'segment-v2'}
        ctx=decision_context('d'*32,100)
        valid=sign_approval('reviewer','engineering','coding-agent',b,ctx,pairs['reviewer'],issued_at=99,expires_at=200)
        bad=sign_approval('security','security','coding-agent',b,ctx,pairs['security'],issued_at=99,expires_at=200); bad['signature']='0'*128
        d=evaluate_policy(s,p,['app/payments.py'],{k:True for k in p['required_checks']},b,[valid,valid,bad],keys,author='coding-agent',termination='passed',current_head=b['head'],current_base=b['base'],eval_binding=b,approval_context=ctx)
        self.assertFalse(d['authorized']); self.assertEqual(d['verified_roles'],['engineering']); self.assertIn('missing_approval:security',d['reasons'])
    def test_unknown_check_fails_closed(self):
        s,p=load_config(SPEC),load_config(POLICY); keys={}; b={'head':'h','base':'b','spec':digest(s),'policy':digest(p),'harness':'t','path_semantics':'segment-v2'}
        d=evaluate_policy(s,p,['app/payments.py'],{},b,[],keys,author='coding-agent',termination='passed',current_head='h',current_base='b',eval_binding=b)
        self.assertFalse(d['authorized']); self.assertIn('check_failed:positive_amount',d['reasons'])
if __name__=='__main__': unittest.main()
