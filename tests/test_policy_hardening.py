"""Negative tests for the new decision profile; no external calls."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge.core import approval, digest, evaluate_decision, evaluate_policy, load_config
from intent_merge.github import policy_from, preflight
from intent_merge.path_policy import LEGACY_V1, SEGMENT_V2, matches, validate_patterns
from intent_merge.runner import run
from test_integration_v05 import FixtureAPI, ROOT


class PathTests(unittest.TestCase):
    def test_segment_and_recursive_matching(self):
        cases = [
            ('app/a.py', 'app/*.py', True),
            ('app/sub/a.py', 'app/*.py', False),
            ('app/sub/a.py', 'app/**/*.py', True),
            ('app/a.py', 'app/**/*.py', True),
            ('policy.toml', '**/policy.toml', True),
            ('app/policy.toml', '**/policy.toml', True),
            ('docs', 'docs/**', True),
            ('docs2/a', 'docs/**', False),
            ('app/a.py', 'app/?.py', True),
            ('app/ab.py', 'app/?.py', False),
            ('App/a.py', 'app/**', False),
        ]
        for path, pattern, expected in cases:
            with self.subTest(path=path, pattern=pattern):
                self.assertEqual(matches(path, [pattern]), expected)

    def test_legacy_only_explicit(self):
        self.assertTrue(matches('app/sub/a.py', ['app/*.py'], semantics=LEGACY_V1))
        self.assertFalse(matches('app/sub/a.py', ['app/*.py']))

    def test_invalid_paths_never_allowed(self):
        for path in ('/app/a.py', 'app/../a.py', './app/a.py', 'app//a.py', 'app\\a.py', 'C:/a.py', 'app/a\x00.py', 'app/a\n.py', ''):
            with self.subTest(path=path):
                self.assertFalse(matches(path, ['**']))

    def test_invalid_patterns_rejected(self):
        for pattern in ('!app/**', 'app/[ab].py', 'app/a**.py', 'app/../*', 'app/', '/app/**', 'app\\*', ''):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                validate_patterns([pattern])


class LocalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_config(ROOT/'examples/spec.toml')
        self.policy = load_config(ROOT/'examples/policy.toml')

    def args(self, path='app/payments.py'):
        binding = {'head': 'h', 'base': 'b', 'spec': digest(self.spec), 'policy': digest(self.policy),
                   'harness': 't', 'path_semantics': SEGMENT_V2}
        return dict(paths=[path], checks={k: True for k in self.policy['required_checks']}, binding=binding,
                    termination='passed', current_head='h', current_base='b', eval_binding=binding)

    def test_nested_allowlist_rejected_even_with_passed_checks(self):
        self.spec['allowed_paths'] = ['app/*.py']
        result = evaluate_decision(self.spec, self.policy, actors={'reviewer','security'}, **self.args('app/sub/evil.py'))
        self.assertFalse(result['authorized'])
        self.assertIn('outside_spec', result['reasons'])

    def test_invalid_policy_structured(self):
        for mutator in (lambda p: p['risk_rules'][0].update(level='critical'),
                        lambda p: p.update(max_iterations=True),
                        lambda p: p.update(protected_paths=['../*']),
                        lambda p: p['risk_rules'][0].update(required_roles=['nonexistent']),
                        lambda p: p.pop('approvers')):
            with self.subTest(mutator=mutator):
                policy = copy.deepcopy(self.policy); mutator(policy)
                result = evaluate_policy(self.spec, policy, approvals=[], keys={}, author='agent', **self.args())
                self.assertFalse(result['authorized'])
                self.assertEqual(result['status'], 'INVALID_CONFIGURATION')
                self.assertTrue(result['reasons'][0].startswith('invalid_configuration:'))

    def test_legacy_binding_rejected(self):
        args = self.args(); args['binding'].pop('path_semantics')
        result = evaluate_decision(self.spec, self.policy, actors={'reviewer','security'}, **args)
        self.assertIn('path_semantics_mismatch', result['reasons'])
        self.assertFalse(result['authorized'])

    def test_symmetric_keys_cannot_approve_new_decisions(self):
        args = self.args(); keys = {'reviewer': 'ab'*32, 'security': 'cd'*32}
        approvals = [approval(actor, args['binding'], keys) for actor in keys]
        result = evaluate_policy(self.spec, self.policy, approvals=approvals, keys=keys, author='agent', **args)
        self.assertFalse(result['authorized'])
        self.assertEqual(result['verified_roles'], [])

    def test_invalid_policy_rejected_before_executor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); policy = root/'policy.toml'; out = root/'run'
            policy.write_text((ROOT/'examples/policy.toml').read_text().replace('level = "low"', 'level = "critical"'))
            with patch('intent_merge.runner.Executor') as executor:
                result = run('happy', out, ROOT/'examples/spec.toml', policy)
                executor.assert_not_called()
            self.assertFalse(result['merged'])
            self.assertFalse(result['merge_authority'])
            event = json.loads((out/'configuration-rejection.jsonl').read_text())
            self.assertEqual(event['kind'], 'configuration_rejected')
            self.assertFalse((out/'repo').exists())


class GithubPolicyTests(unittest.TestCase):
    def test_shared_matcher_blocks_nested_path(self):
        api = FixtureAPI(); policy = policy_from(ROOT/'examples/github-policy.toml')
        policy['allowed_paths'] = ['app/*.py']; api.files[0]['filename'] = 'app/sub/evil.py'
        result = preflight(api, 'OWNER/REPO', 1, policy, publish=True)
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertIn('scope:app/sub/evil.py', result['reasons'])
        self.assertEqual(api.posts[0][1]['conclusion'], 'failure')

    def test_protected_root_file(self):
        api = FixtureAPI(); policy = policy_from(ROOT/'examples/github-policy.toml')
        policy['allowed_paths'] = ['**']; api.files[0]['filename'] = 'policy.toml'
        result = preflight(api, 'OWNER/REPO', 1, policy)
        self.assertIn('scope:policy.toml', result['reasons'])

    def test_invalid_policy_never_calls_github(self):
        api = FixtureAPI(); policy = policy_from(ROOT/'examples/github-policy.toml')
        policy['allowed_paths'] = ['app/../**']
        with self.assertRaises(ValueError):
            preflight(api, 'OWNER/REPO', 1, policy, publish=True)
        self.assertEqual(api.reads, 0)
        self.assertEqual(api.posts, [])

    def test_normalized_policy_digest_changes(self):
        policy = policy_from(ROOT/'examples/github-policy.toml')
        self.assertEqual(policy['path_semantics'], SEGMENT_V2)
        self.assertNotEqual(digest(policy), digest(load_config(ROOT/'examples/github-policy.toml')))

    def test_missing_filename_never_publishes_success(self):
        api = FixtureAPI(); policy = policy_from(ROOT/'examples/github-policy.toml')
        api.files[0]['filename'] = ''
        with self.assertRaises(ValueError):
            preflight(api, 'OWNER/REPO', 1, policy, publish=True)
        self.assertEqual(api.posts, [])
