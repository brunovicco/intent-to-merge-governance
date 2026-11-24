import json, shutil, tempfile, unittest
from pathlib import Path
from intent_merge.benchmark import CATALOG, STRATEGIES, classify, summarize, evaluate_corpus, generate, write_reports

ROOT=Path(__file__).resolve().parents[1]
CORPUS=ROOT/'examples/amgb-v1'

class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=evaluate_corpus(CORPUS/'bundles',CORPUS/'signer.pub')
    def test_catalog(self):
        self.assertEqual(len(CATALOG),19)
        self.assertEqual(sum(v[0] for v in CATALOG.values()),4)
    def test_exact_replay(self):
        self.assertEqual(self.report,json.loads((CORPUS/'report.json').read_text()))
    def test_metrics(self):
        self.assertEqual([s['unsafe_allow'] for s in self.report['strategies']],[10,8,6,5,0])
        self.assertEqual([s['false_block'] for s in self.report['strategies']],[0]*5)
        self.assertEqual([s['true_allow'] for s in self.report['strategies']],[4]*5)
        self.assertEqual([s['missing_evidence_scenarios'] for s in self.report['strategies']],[2]*5)
    def test_full_decision_matches_labels(self):
        for row in self.report['rows']:
            self.assertEqual(row['expected_allow'],row['recorded_merge'],row['scenario'])
            self.assertEqual(row['strategies']['S4']['allow'],row['expected_allow'],row['scenario'])
    def test_nested_strategies(self):
        for r in self.report['rows']:
            a=[int(r['strategies'][s]['allow']) for s in STRATEGIES]
            self.assertEqual(a,sorted(a,reverse=True),r['scenario'])
    def test_scope_is_missing_evidence_not_detected(self):
        for r in self.report['rows']:
            if r['category']=='scope':
                self.assertTrue(r['strategies']['S0']['missing_checks'])
                self.assertEqual(r['observed']['executed_candidate_cases'],0)
    def test_missing_corpus(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'catalog exactly'): evaluate_corpus(d,CORPUS/'signer.pub')
    def test_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bundles'; shutil.copytree(CORPUS/'bundles',p)
            f=p/'happy/evidence/report.json'; f.write_text(f.read_text()+' ')
            with self.assertRaisesRegex(ValueError,'inventory mismatch'): evaluate_corpus(p,CORPUS/'signer.pub')
    def test_wrong_policy_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'catalog-bound'):
                generate(Path(d)/'out',ROOT/'examples/spec.toml',ROOT/'examples/policy-proposed.toml')
            self.assertFalse((Path(d)/'out').exists())
    def test_reports(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); write_reports(self.report,p)
            self.assertEqual(json.loads((p/'report.json').read_text()),self.report)
            self.assertIn('Synthetic', (p/'report.html').read_text().title())
            self.assertEqual(len((p/'scenario-matrix.csv').read_text().splitlines()),20)
    def test_unknown_checks_fail_closed(self):
        r=classify({'checks':{},'termination':'passed'},{'criteria':['test']},{},'S0')
        self.assertFalse(r['allow']); self.assertEqual(r['missing_checks'],['test'])
    def test_empty_denominators(self):
        r=summarize([])[0]
        self.assertIsNone(r['unsafe_allow_rate']); self.assertIsNone(r['false_block_rate']); self.assertIsNone(r['accuracy'])
