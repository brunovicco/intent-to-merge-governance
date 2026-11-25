"""Versioned scope policy and read-only historical changeset replay."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge.changeset import approve, derive, execute, order, plan, verify_plan, verify_receipt
from intent_merge.changeset_demo import config_keys


ROOT = Path(__file__).resolve().parents[1] / 'examples/changeset-v1'


class ChangeSetPathPolicyTests(unittest.TestCase):
    def setUp(self):
        self.legacy = json.loads((ROOT / 'config.json').read_text())
        self.receipt = json.loads((ROOT / 'compatible/receipt.json').read_text())
        self.pin = json.loads((ROOT / 'anchor.json').read_text())['config_digest']
        self.config, self.keys = config_keys()
        self.components = copy.deepcopy(self.receipt['plan']['components'])

    def with_scope(self, pattern, path):
        self.config['components']['portal']['allowed_paths'] = [pattern]
        self.components['portal']['paths'] = [path]
        return derive(self.config, self.components)

    def test_single_star_does_not_cross_directory(self):
        p = self.with_scope('app/*.py', 'app/sub/main.py')
        self.assertFalse(p['eligible'])
        self.assertIn('portal:out_of_scope:app/sub/main.py', p['issues'])

    def test_single_star_same_directory(self):
        self.assertTrue(self.with_scope('app/*.py', 'app/main.py')['eligible'])

    def test_recursive_glob_zero_or_more_segments(self):
        for path in ('app/main.py', 'app/sub/main.py'):
            with self.subTest(path=path):
                self.assertTrue(self.with_scope('app/**/*.py', path)['eligible'])

    def test_invalid_paths_never_allow(self):
        for path in ('../x', '/x', 'app//main.py', 'app/./main.py', 'C:/x', 'app\\main.py'):
            with self.subTest(path=path):
                self.assertFalse(self.with_scope('**', path)['eligible'])

    def test_invalid_patterns_rejected(self):
        for pattern in ('../*', 'app/**x', '!app/*', 'app/[ab]', '/app/*'):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                self.with_scope(pattern, 'app/main.py')

    def test_unknown_semantics_rejected(self):
        self.config['path_semantics'] = 'fnmatch-v1'
        with self.assertRaisesRegex(ValueError, 'semantics'):
            order(self.config)

    def test_legacy_cannot_plan_or_execute(self):
        with patch('intent_merge.changeset.git') as git:
            with self.assertRaisesRegex(ValueError, 'historical replay only'):
                plan(self.legacy, {})
            with self.assertRaisesRegex(ValueError, 'historical replay only'):
                execute(self.legacy, self.receipt['plan'], self.receipt['approvals'], {}, None)
            git.assert_not_called()

    def test_legacy_cannot_sign_or_validate_new_plan(self):
        with self.assertRaisesRegex(ValueError, 'historical replay only'):
            approve(self.legacy, self.receipt['plan'], 'portal', self.keys['portal'])
        with self.assertRaisesRegex(ValueError, 'historical replay only'):
            verify_plan(self.legacy, self.receipt['plan'], self.receipt['approvals'])

    def test_historical_receipts_preserved(self):
        for scenario in ('compatible', 'partial-failure', 'compensation-conflict'):
            with self.subTest(scenario=scenario):
                r = json.loads((ROOT / scenario / 'receipt.json').read_text())
                result = verify_receipt(self.legacy, r, self.pin)
                self.assertEqual(result['status'], r['status'])
                self.assertFalse(result['merge_authority'])

    def test_old_plan_not_valid_under_new_config(self):
        with self.assertRaisesRegex(ValueError, 'plan derivation mismatch'):
            verify_plan(self.config, self.receipt['plan'], self.receipt['approvals'])

    def test_config_version_and_semantics_bound_to_plan(self):
        p = derive(self.config, self.components)
        self.assertEqual(p['version'], 2)
        self.assertTrue(p['eligible'])
        self.assertNotEqual(p['config_digest'], self.receipt['plan']['config_digest'])

    def test_nested_change_rejected_before_any_ref_update(self):
        import tempfile
        from intent_merge.changeset import git, ref
        from intent_merge.changeset_demo import command, fixture

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repos'
            repos = fixture(root, 'compatible')
            work = root / 'portal-work'
            nested = work / 'app' / 'sub' / 'main.py'
            nested.parent.mkdir(parents=True)
            nested.write_text('pass\n')
            command('add', '.', cwd=work)
            command('commit', '-m', 'Nested change', cwd=work)
            command('push', str(repos['portal']), 'candidate', cwd=work)
            self.config['components']['portal']['allowed_paths'].append('app/*.py')
            p = plan(self.config, repos)
            self.assertIn('portal:out_of_scope:app/sub/main.py', p['issues'])
            before = {n: ref(repo, 'refs/heads/main') for n, repo in repos.items()}
            approvals = [approve(self.config, p, n, self.keys[n]) for n in p['order']]
            with self.assertRaisesRegex(ValueError, 'blocked by plan'):
                execute(self.config, p, approvals, repos, self.keys['executor'])
            self.assertEqual(before, {n: ref(repo, 'refs/heads/main') for n, repo in repos.items()})
