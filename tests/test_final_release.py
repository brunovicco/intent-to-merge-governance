import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class FinalReleaseTests(unittest.TestCase):
    def setUp(self):
        self.mod = load('review_bandit')
        self.baseline = json.loads((ROOT / 'docs/bandit-review.json').read_text())
        self.expected = [f for f in self.baseline['findings'] if f['disposition'] != 'remediated_pending_rescan']
        self.report = {'errors': [], 'results': [dict(filename=f['file'], line_number=f['line'], test_id=f['rule'], issue_severity=f['severity'], issue_confidence=f['confidence']) for f in self.expected]}

    def test_exact_baseline(self):
        r = self.mod.classify(ROOT, self.report, self.baseline)
        self.assertEqual(r['status'], 'REVIEWED_LAB_BASELINE')
        self.assertEqual(len(r['reviewed']), 57)
        self.assertFalse(r['publication_ready'])

    def test_new_duplicate_and_missing_findings(self):
        for results in (self.report['results'][:-1], self.report['results'] + self.report['results'][:1], self.report['results'] + [dict(self.report['results'][0], test_id='B999')]):
            with self.subTest(count=len(results)):
                self.assertEqual(self.mod.classify(ROOT, {'errors': [], 'results': results}, self.baseline)['status'], 'REVIEW_REQUIRED')

    def test_changed_source_pin(self):
        baseline = copy.deepcopy(self.baseline)
        baseline['findings'][0]['source_sha256'] = '0' * 64
        self.assertEqual(self.mod.classify(ROOT, self.report, baseline)['status'], 'REVIEW_REQUIRED')

    def test_scanner_error(self):
        with self.assertRaises(ValueError):
            self.mod.classify(ROOT, dict(self.report, errors=[{'reason': 'failed'}]), self.baseline)

    def test_locked_wheels(self):
        mod = load('locked_docker_requirements')
        text = mod.requirements(ROOT / 'uv.lock')
        self.assertEqual(len(text.splitlines()), 7)
        self.assertIn('cryptography==50.0.2 --hash=sha256:', text)
        self.assertEqual(text.count('=='), 7)

    def test_reject_lock_with_unknown_source(self):
        mod = load('locked_docker_requirements')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'uv.lock'
            p.write_text((ROOT / 'uv.lock').read_text().replace('https://pypi.org/simple', 'https://invalid.example/simple'))
            with self.assertRaises(ValueError):
                mod.requirements(p)

    def test_demo_condition_is_explicit(self):
        from intent_merge.operations_demo import require_demo
        with self.assertRaises(ValueError):
            require_demo(False, 'fail')
