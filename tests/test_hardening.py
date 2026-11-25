import base64, copy, json, tempfile, unittest
from pathlib import Path
from functools import partial
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intent_merge.core import canonical,digest,load_config
from intent_merge.hardening import verify_control_receipts,strict_gate,sweep,DurableChangeSet,verify_payment_candidate,RECEIPT_DOMAIN,BINDINGS
from intent_merge.operational import CONTROLS,DOMAIN,NAME,Journal,work_once
from intent_merge.github import policy_from
from intent_merge.changeset_demo import config_keys,fixture,public,command
from intent_merge.changeset import plan,approve,ref,git
from intent_merge.fixtures import BASE as BASE_CODE,FIXED,DRIFTED
from test_operational import API,APP,NOW
from test_integration_v05 import ROOT,HEAD,BASE

class Remote(API):
    def request(self,path,payload=None,*,method=None):
        if '/check-runs/' in path:
            row=next(c for c in self.checks if str(c['id'])==path.rsplit('/',1)[-1])
            if method=='PATCH': row.update(payload)
            return copy.deepcopy(row)
        return super().request(path,payload)

class HardeningTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.api=Remote();self.policy=policy_from(ROOT/'examples/github-policy.toml');self.key=Ed25519PrivateKey.generate()
        self.keys={c:Ed25519PrivateKey.generate() for c in CONTROLS};self.trust={c:public(k) for c,k in self.keys.items()}
        self.job={'id':'d1','repo':'OWNER/REPO','pr':1,'body_sha256':'a'*64};self.j=Journal(self.root/'jobs.sqlite');self.addCleanup(self.j.close);self.j.enqueue(self.job)
        self.bind={'repository':'OWNER/REPO','pr':1,'head':HEAD,'base':BASE,'policy_digest':digest(self.policy)}
        self.a=self.root/'assertions';self.a.mkdir();self.r=self.root/'receipts';self.r.mkdir();self.filename=f'1-{HEAD}.json'
    def receipts(self):
        result=[]
        for c in sorted(CONTROLS):
            artifact={'observations':['synthetic test observation'],'control':c};s={**self.bind,'control':c,'profile':'external-control-v1','issued_at':NOW-1,'expires_at':NOW+60,'passed':True,'artifact_digest':digest(artifact)}
            result.append({'statement':s,'artifact':artifact,'signature':base64.b64encode(self.keys[c].sign(RECEIPT_DOMAIN+canonical(s))).decode()})
        return result
    def setup_evidence(self,receipts=None,**kwargs):
        receipts=self.receipts() if receipts is None else receipts
        root=digest({r['statement']['control']:digest(r) for r in receipts})
        s={**self.bind,'schema_version':1,'profile':'live-external-verifier','issued_at':NOW-1,'expires_at':NOW+60,'controls':dict.fromkeys(CONTROLS,True),'evidence_digest':root,**kwargs}
        (self.a/self.filename).write_text(json.dumps({'statement':s,'signature':base64.b64encode(self.key.sign(DOMAIN+canonical(s))).decode()}));(self.r/self.filename).write_text(json.dumps(receipts))
    def gate(self,now=NOW):return strict_gate(self.api,self.job,self.policy,self.a,self.key.public_key(),now,receipt_dir=self.r,control_trust=self.trust)
    def publish(self):return work_once(self.j,self.api,self.policy,self.a,self.key.public_key(),app_id=APP,now=NOW,publish=True,gate_fn=partial(strict_gate,receipt_dir=self.r,control_trust=self.trust))
    def sweep(self,now=NOW,apply=False):return sweep(self.j,self.api,self.policy,self.a,self.key.public_key(),self.r,self.trust,APP,now=now,apply=apply)
    def test_complete_signed_receipts(self):self.setup_evidence();self.assertEqual(self.publish()['decision'],'PASS');self.assertEqual(self.sweep()[0]['status'],'CURRENT')
    def publish_with_clock(self, clock, *, after_refresh=None, after_journal=None):
        from unittest.mock import patch
        calls = 0
        original_transition = self.j.transition
        def refresh(*args):
            nonlocal calls
            result = strict_gate(*args, receipt_dir=self.r, control_trust=self.trust)
            calls += 1
            if calls == 2 and after_refresh is not None:
                clock[0] = after_refresh
            return result
        def transition(*args, **kwargs):
            original_transition(*args, **kwargs)
            if args[2] == 'PUBLISHING' and after_journal is not None:
                clock[0] = after_journal
        with patch('intent_merge.operational.time.time', side_effect=lambda: clock[0]), patch.object(self.j, 'transition', side_effect=transition):
            return work_once(self.j,self.api,self.policy,self.a,self.key.public_key(),app_id=APP,publish=True,gate_fn=refresh)

    def test_expiry_between_refresh_and_publication(self):
        self.setup_evidence()
        result = self.publish_with_clock([NOW], after_refresh=NOW+60)
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertIn('evidence_expired_before_publication', result['reasons'])
        self.assertFalse(self.api.posts)
        self.assertEqual(self.j.get('d1')['state'], 'BLOCKED_BEFORE_PUBLICATION')

    def test_expiry_after_journal_commit(self):
        self.setup_evidence()
        result = self.publish_with_clock([NOW], after_journal=NOW+60)
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertFalse(self.api.posts)
        row = self.j.get('d1')
        self.assertEqual(row['state'], 'BLOCKED_BEFORE_PUBLICATION')
        self.assertIsNone(row['external_id'])
        self.j.recover()
        self.assertEqual(self.j.get('d1')['state'], 'BLOCKED_BEFORE_PUBLICATION')

    def test_publication_before_expiry(self):
        self.setup_evidence(expires_at=NOW+30)
        result = self.publish_with_clock([NOW], after_journal=NOW+29)
        self.assertEqual(result['decision'], 'PASS')
        self.assertEqual(self.api.posts[0][1]['conclusion'], 'success')

    def test_clock_regression_before_publication(self):
        self.setup_evidence()
        result = self.publish_with_clock([NOW], after_journal=NOW-1)
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertIn('evidence_clock_invalid_before_publication', result['reasons'])
        self.assertFalse(self.api.posts)

    def test_missing_receipt(self):self.setup_evidence(self.receipts()[:-1]);self.assertEqual(self.gate()['decision'],'BLOCK')
    def test_tampered_artifact(self):r=self.receipts();r[0]['artifact']['observations']=['tamper'];self.setup_evidence(r);self.assertEqual(self.gate()['decision'],'BLOCK')
    def test_duplicate_receipt(self):r=self.receipts();r[-1]=r[0];self.setup_evidence(r);self.assertEqual(self.gate()['decision'],'BLOCK')
    def test_shared_key(self):self.setup_evidence();self.trust['intent']=self.trust['verification'];self.assertEqual(self.gate()['decision'],'BLOCK')
    def test_bad_aggregate(self):self.setup_evidence(evidence_digest='f'*64);self.assertEqual(self.gate()['decision'],'BLOCK')
    def test_expiry_sweep(self):self.setup_evidence();self.publish();self.assertEqual(self.sweep(NOW+60)[0]['status'],'WOULD_REVOKE');self.assertEqual(self.sweep(NOW+60,True)[0]['status'],'REVOKED');self.assertEqual(self.sweep(NOW+60,True)[0]['status'],'ALREADY_BLOCKED')
    def test_review_revocation(self):self.setup_evidence();self.publish();self.api.reviews.pop();self.assertEqual(self.sweep(apply=True)[0]['status'],'REVOKED')
    def test_base_revocation(self):self.setup_evidence();self.publish();self.api.pr['base']['sha']='d'*40;self.assertEqual(self.sweep(apply=True)[0]['status'],'REVOKED')
    def test_remote_mismatch(self):self.setup_evidence();self.publish();self.api.checks[-1]['app']['id']=42;self.assertEqual(self.sweep(NOW+60,True)[0]['status'],'REMOTE_STATE_UNKNOWN')
    def test_legacy_boolean_not_accepted(self):self.setup_evidence();(self.r/self.filename).unlink();self.assertEqual(self.gate()['decision'],'BLOCK')

class DurableTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.c,self.k=config_keys();self.repos=fixture(self.root/'repos','compatible');self.p=plan(self.c,self.repos);self.approvals=[approve(self.c,self.p,n,self.k[n]) for n in self.p['order']];self.db=self.root/'journal.sqlite'
    def run_durable(self,**kw):
        d=DurableChangeSet(self.db)
        try:return d.run(self.c,self.p,self.approvals,self.repos,self.k['executor'],**kw)
        finally:d.close()
    def crash(self,stage):
        def fault(s,n,repos):
            if s==stage and n=='payments':raise RuntimeError('simulated interruption')
        with self.assertRaises(RuntimeError):self.run_durable(fault=fault)
    def test_after_cas_recovery(self):self.crash('after_cas');r=self.run_durable();self.assertEqual(r['status'],'COMPLETED');self.assertEqual(r['completed'],self.p['order']);self.assertIn('reconciled_applied',[e['event'] for e in r['events']])
    def test_before_cas_recovery(self):self.crash('before_cas');r=self.run_durable();self.assertEqual(r['status'],'COMPLETED');self.assertIn('reconciled_not_applied',[e['event'] for e in r['events']])
    def test_compensation_recovery(self):self.crash('after_cas');r=self.run_durable(compensate=True);self.assertEqual(r['status'],'COMPENSATED');self.assertEqual(r['completed'],[])
    def test_tampered_journal(self):
        self.crash('after_cas');d=DurableChangeSet(self.db)
        try:
            state=d.load();state['completed']=['portal']
            with d.db:d.save(state)
        finally:d.close()
        with self.assertRaisesRegex(ValueError,'signature'):self.run_durable()
    def test_conflict_recovery(self):
        self.crash('after_cas');c=self.p['components']['portal'];git(self.repos['portal'],'update-ref','refs/heads/main',c['head'],c['base']);self.assertEqual(self.run_durable()['status'],'MANUAL_INTERVENTION');self.assertEqual(ref(self.repos['portal'],'refs/heads/main'),c['head'])

class CandidateTests(unittest.TestCase):
    def test_exact_commit_verification(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);work=root/'work';work.mkdir();command('init','-b','main',cwd=work);command('config','user.name','Fixture',cwd=work);command('config','user.email','fixture@example.invalid',cwd=work);(work/'app').mkdir();p=work/'app/payments.py';p.write_text(BASE_CODE);command('add','.','--',cwd=work);command('commit','-m','base',cwd=work);base=command('rev-parse','HEAD',cwd=work)
            p.write_text(FIXED);command('commit','-am','fixed',cwd=work);good=command('rev-parse','HEAD',cwd=work);p.write_text(DRIFTED);command('commit','-am','drift',cwd=work);bad=command('rev-parse','HEAD',cwd=work);repo=root/'repo.git';command('clone','--bare',str(work),str(repo));spec=load_config(ROOT/'examples/spec.toml')
            with self.assertRaisesRegex(ValueError,'trusted fixtures'):verify_payment_candidate(repo,base,good,spec,backend='local')
            a=verify_payment_candidate(repo,base,good,spec,backend='local',trusted_fixture=True);b=verify_payment_candidate(repo,base,bad,spec,backend='local',trusted_fixture=True)
            self.assertTrue(a['passed']);self.assertEqual(len(a['verification']['outcomes']),37);self.assertFalse(b['passed']);self.assertFalse(b['intent']['passed']);self.assertFalse(a['merge_authority'])
