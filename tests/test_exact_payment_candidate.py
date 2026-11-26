"""Exact-object verification against disposable, trusted synthetic repositories."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge.changeset_demo import command
from intent_merge.core import digest, load_config
from intent_merge.fixtures import BASE, DRIFTED, FIXED
from intent_merge.hardening import verify_payment_candidate
from test_integration_v05 import ROOT


class ExactPaymentCandidateTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.target = self.work / 'app/payments.py'
        self.target.parent.mkdir()
        self.local('init', '-b', 'main')
        self.local('config', 'user.name', 'Synthetic fixture')
        self.local('config', 'user.email', 'fixture@example.invalid')
        self.base = self.commit(BASE, 'base')
        self.good = self.commit(FIXED, 'fixed')
        self.bad = self.commit(DRIFTED, 'drifted')
        self.repo = self.root / 'trusted.git'
        self.local('clone', '--bare', str(self.work), str(self.repo))
        self.spec = load_config(ROOT / 'examples/spec.toml')

    def local(self, *args):
        return command(*args, cwd=self.work)

    def bare(self, *args):
        return command(*args, cwd=self.repo)

    def commit(self, source, message):
        self.target.write_text(source)
        self.local('add', 'app/payments.py')
        self.local('commit', '-m', message)
        return self.local('rev-parse', 'HEAD')

    def verify(self, base=None, head=None):
        return verify_payment_candidate(self.repo, self.base if base is None else base,
                                        self.good if head is None else head, self.spec,
                                        backend='local', trusted_fixture=True)

    def test_ordinary_bare_repository_and_exact_observations(self):
        report = self.verify()
        self.assertEqual((report['base'], report['head']), (self.base, self.good))
        self.assertEqual(report['paths'], ['app/payments.py'])
        self.assertEqual(report['source_digest'], digest(FIXED))
        self.assertTrue(report['intent']['passed'])
        self.assertTrue(report['passed'])
        self.assertEqual(len(report['verification']['outcomes']), 37)

    def test_head_replacement_uses_named_object(self):
        expected = self.verify(head=self.bad)
        self.bare('replace', self.bad, self.good)
        actual = self.verify(head=self.bad)
        for key in ('base', 'head', 'source_digest', 'paths', 'intent', 'verification', 'passed'):
            self.assertEqual(actual[key], expected[key], key)
        self.assertEqual(actual['source_digest'], digest(DRIFTED))
        self.assertFalse(actual['passed'])

    def test_base_replacement_uses_named_object(self):
        self.bare('replace', self.base, self.good)
        report = self.verify()
        self.assertEqual(report['base'], self.base)
        self.assertEqual(report['source_digest'], digest(FIXED))
        self.assertTrue(report['passed'])

    def test_inherited_repository_and_object_selectors_are_ignored(self):
        other = self.root / 'other.git'
        self.local('init', '--bare', str(other))
        selectors = {
            'GIT_DIR': str(other), 'GIT_COMMON_DIR': str(other),
            'GIT_INDEX_FILE': str(other / 'index'), 'GIT_OBJECT_DIRECTORY': str(other / 'objects'),
            'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(other / 'objects'),
            'GIT_WORK_TREE': str(self.work), 'GIT_NAMESPACE': 'unrelated',
            'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.bare',
            'GIT_CONFIG_VALUE_0': 'false',
        }
        for group in (selectors, {'GIT_OBJECT_DIRECTORY': selectors['GIT_OBJECT_DIRECTORY']}):
            with self.subTest(selectors=tuple(group)), patch.dict(os.environ, group):
                self.assertTrue(self.verify()['passed'])

    def test_commit_identifiers_reject_aliases_and_noncommits(self):
        self.bare('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                  'tag', '-a', '-m', 'synthetic tag', 'annotated', self.good)
        for head in ('annotated', self.good[:12], 'f' * 40,
                     self.bare('rev-parse', 'annotated'),
                     self.bare('rev-parse', self.good + '^{tree}'),
                     self.bare('rev-parse', self.good + ':app/payments.py')):
            with self.subTest(head=head), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.verify(head=head)

    def test_nonregular_candidate_entries_rejected_before_evaluation(self):
        blob = self.local('rev-parse', self.good + ':app/payments.py')
        self.local('checkout', '--detach', self.base)
        for mode, oid in (('120000', blob), ('160000', self.good)):
            self.local('update-index', '--cacheinfo', f'{mode},{oid},app/payments.py')
            self.local('commit', '-m', 'synthetic nonregular entry')
            self.bare('fetch', str(self.work), f'HEAD:refs/heads/mode-{mode}')
            head = self.local('rev-parse', 'HEAD')
            with self.subTest(mode=mode), patch('intent_merge.verification.Executor') as executor:
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    self.verify(head=head)
                executor.assert_not_called()

    def test_grafts_cannot_supply_ancestry(self):
        self.local('checkout', '--detach', self.base)
        self.local('commit', '--amend', '-m', 'unrelated root')
        unrelated = self.local('rev-parse', 'HEAD')
        self.bare('fetch', str(self.work), 'HEAD:refs/heads/unrelated')
        (self.repo / 'info/grafts').write_text(f'{self.good} {unrelated}\n')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.verify(base=unrelated)

    def test_alternate_only_objects_are_rejected(self):
        other = self.root / 'alternates.git'
        self.local('init', '--bare', str(other))
        (other / 'objects/info/alternates').write_text(str(self.repo / 'objects') + '\n')
        self.repo = other
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.verify()
