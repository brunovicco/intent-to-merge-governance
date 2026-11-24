import copy, json, tempfile, unittest
from pathlib import Path
from intent_merge.changeset import (order, plan, approve, execute, verify_receipt, verify_plan, derive, sign, git, ref)
from intent_merge.changeset_demo import config_keys, fixture, study
from intent_merge.core import digest

class ChangeSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.root=Path(cls.tmp.name)
        cls.report=study(cls.root/'study'); cls.rows={r['scenario']:r for r in cls.report['scenarios']}
        cls.config=json.loads((cls.root/'study/config.json').read_text())
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def receipt(self,scenario='compatible'):
        return json.loads((self.root/'study'/scenario/'receipt.json').read_text())
    def test_all_scenario_labels(self):
        self.assertEqual({n:r['status'] for n,r in self.rows.items()}, {'compatible':'COMPLETED','incompatible-final':'BLOCKED','incompatible-prefix':'BLOCKED','partial-failure':'COMPENSATED','compensation-conflict':'MANUAL_INTERVENTION','stale-plan':'BLOCKED','missing-approval':'BLOCKED','scope-violation':'BLOCKED'})
    def test_valid_plan_order(self):
        self.assertEqual(self.receipt()['plan']['order'],['payments','checkout','portal'])
    def test_final_incompatible(self): self.assertFalse(self.rows['incompatible-final']['final_compatible'])
    def test_prefix_incompatible_despite_final(self):
        r=self.rows['incompatible-prefix']; self.assertTrue(r['final_compatible']); self.assertFalse(r['prefix_compatible']); self.assertEqual(r['writes_by_coordinator'],0)
    def test_compensation_restores_refs(self):
        r=self.receipt('partial-failure'); self.assertEqual(r['events'][-1]['payload']['refs'],{n:c['base'] for n,c in r['plan']['components'].items()})
        for n,c in r['plan']['components'].items(): self.assertEqual(ref(self.root/'study/partial-failure/repositories'/f'{n}.git','refs/heads/main'),c['base'])
    def test_conflict_does_not_overwrite(self):
        r=self.receipt('compensation-conflict'); refs=r['events'][-1]['payload']['refs']; self.assertEqual(refs['payments'],r['plan']['components']['payments']['head']); self.assertEqual(refs['portal'],r['plan']['components']['portal']['head'])
        self.assertEqual(self.rows['compensation-conflict']['writes_by_coordinator'],1)
    def test_blocked_zero_coordinator_writes(self):
        self.assertTrue(all(r['writes_by_coordinator']==0 for r in self.rows.values() if r['status']=='BLOCKED'))
    def test_offline_replay(self):
        for n in ('compatible','partial-failure','compensation-conflict'):
            r=self.receipt(n); self.assertEqual(verify_receipt(self.config,r,digest(self.config))['status'],r['status'])
    def test_tampered_receipt(self):
        r=self.receipt(); r['status']='COMPENSATED'
        with self.assertRaises(ValueError): verify_receipt(self.config,r,digest(self.config))
    def test_untrusted_config(self):
        with self.assertRaises(ValueError): verify_receipt(self.config,self.receipt(),'0'*64)
    def test_cycle_rejected(self):
        c=copy.deepcopy(self.config); c['components']['payments']['depends_on']=['portal']
        with self.assertRaisesRegex(ValueError,'cycle'): order(c)
    def test_shared_keys_rejected(self):
        c=copy.deepcopy(self.config); c['components']['payments']['reviewer_key']=c['executor_key']
        with self.assertRaisesRegex(ValueError,'independent'): order(c)
    def test_duplicate_approval(self):
        r=self.receipt(); a=r['approvals']+[r['approvals'][0]]
        with self.assertRaises(ValueError): verify_plan(self.config,r['plan'],a)
    def test_stale_approval(self):
        r=self.receipt(); p=copy.deepcopy(r['plan']); p['components']['payments']['head']='f'*40; p=derive(self.config,p['components'])
        with self.assertRaisesRegex(ValueError,'binding'): verify_plan(self.config,p,r['approvals'])
    def test_wrong_reviewer(self):
        c,k=config_keys(); repos=fixture(self.root/'wrong-reviewer','compatible'); p=plan(c,repos)
        a=[approve(c,p,n,k['executor'] if n=='portal' else k[n]) for n in p['order']]
        with self.assertRaisesRegex(ValueError,'signature'): execute(c,p,a,repos,k['executor'])
        self.assertEqual(ref(repos['payments'],'refs/heads/main'),p['components']['payments']['base'])
    def test_wrong_executor(self):
        c,k=config_keys(); repos=fixture(self.root/'wrong-executor','compatible'); p=plan(c,repos); a=[approve(c,p,n,k[n]) for n in p['order']]
        with self.assertRaisesRegex(ValueError,'signature'): execute(c,p,a,repos,k['portal'])
        self.assertEqual(ref(repos['payments'],'refs/heads/main'),p['components']['payments']['base'])
    def test_repo_alias_rejected(self):
        c,k=config_keys(); repos=fixture(self.root/'alias','compatible'); repos['portal']=repos['payments']
        with self.assertRaisesRegex(ValueError,'aliases'): plan(c,repos)
    def test_wrong_candidate_before_merge(self):
        c,k=config_keys(); repos=fixture(self.root/'candidate-drift','compatible'); p=plan(c,repos); a=[approve(c,p,n,k[n]) for n in p['order']]
        def fault(stage,n,rs):
            if stage=='before_merge' and n=='checkout':
                x=p['components'][n]; git(rs[n],'update-ref','refs/heads/candidate',x['base'],x['head'])
        r=execute(c,p,a,repos,k['executor'],fault=fault)
        self.assertEqual(verify_receipt(c,r,digest(c))['status'],'COMPENSATED')
    def test_resigned_invalid_event_order(self):
        c,k=config_keys(); repos=fixture(self.root/'bad-sequence','compatible'); p=plan(c,repos); a=[approve(c,p,n,k[n]) for n in p['order']]; r=execute(c,p,a,repos,k['executor'])
        from intent_merge.core import Ledger
        l=Ledger()
        for e in r['events']:
            d=copy.deepcopy(e['payload'])
            if e['kind']=='merged' and d['component']=='payments': d['component']='portal'
            l.add(e['kind'],**d)
        r['events']=l.events; r.pop('signature'); r['signature']=sign('receipt',r,k['executor'])
        with self.assertRaisesRegex(ValueError,'sequence'): verify_receipt(c,r,digest(c))
