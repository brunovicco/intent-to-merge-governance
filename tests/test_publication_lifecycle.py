"""Adversarial transport observations and SQLite recovery boundaries."""
import copy
import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from functools import partial
from pathlib import Path

from intent_merge.github import CheckPublicationUnconfirmed, preflight
from intent_merge.hardening import strict_gate, sweep
from intent_merge.operational import Journal, delivery, reconcile, work_once
import test_hardening
from test_operational import NOW, SECRET


class Interrupted(BaseException):
    pass


class PublicationLifecycleTests(unittest.TestCase):
    def setUp(self):
        # Reuse signed strict fixture construction, with different App and installation IDs.
        fixture = test_hardening.HardeningTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.api = fixture.api
        self.api.installation_app_id = 77
        self.api.installation_id = 42
        self.job = fixture.job
        self.db = fixture.j.path
        self.journal = fixture.j
        self.policy = fixture.policy
        self.posts = []
        self.patches = []
        self.api.request = self.request
        self.remote = None
        self.creation_fault = None
        self.revocation_fault = None
        fixture.setup_evidence()

    def request(self, path, payload=None, *, method=None):
        if path.endswith('/pulls/1'):
            return copy.deepcopy(self.api.pr)
        if path.endswith('/check-runs'):
            self.posts.append(copy.deepcopy(payload))
            self.remote = {**payload, 'id': 41, 'app': {'id': 77}}
            self.api.checks.append(self.remote)
            if self.creation_fault:
                raise self.creation_fault
        elif path.endswith('/check-runs/41'):
            if method == 'PATCH':
                self.patches.append(copy.deepcopy(payload))
                self.remote.update(payload)
                if self.revocation_fault == 'lost':
                    raise OSError('mock response lost after PATCH')
                if self.revocation_fault == 'malformed':
                    return {**self.remote, 'id': 41.0}
        else:
            raise AssertionError('unexpected request')
        return copy.deepcopy(self.remote)

    def publish(self):
        f = self.fixture
        return work_once(self.journal, self.api, self.policy, f.a, f.key.public_key(),
                         app_id=77, installation_id=42, publish=True, now=NOW,
                         publication_clock=lambda: NOW,
                         gate_fn=partial(strict_gate, receipt_dir=f.r, control_trust=f.trust))

    def reconcile(self, app=77, installation=42):
        return reconcile(self.journal, self.api, self.job['id'], app, installation_id=installation)

    def sweep(self, apply=True):
        f = self.fixture
        return sweep(self.journal, self.api, self.policy, f.a, f.key.public_key(), f.r, f.trust,
                     77, installation_id=42, now=NOW+60, apply=apply)[0]

    def reopen(self):
        self.journal.close()
        self.journal = Journal(self.db)
        self.addCleanup(self.journal.close)

    def lost_post(self):
        self.creation_fault = OSError('mock response lost after POST')
        with self.assertRaises(CheckPublicationUnconfirmed):
            self.publish()
        return self.journal.get(self.job['id'])

    def test_reconciliation_identity_is_fixed_across_restart(self):
        original = self.lost_post()
        self.reopen()
        intent = json.loads(original['publication_intent'])
        self.assertEqual((intent['app_id'], intent['installation_id']), (77, 42))
        self.assertEqual(intent['external_id'], self.remote['external_id'])
        self.assertEqual(intent['repository'], self.job['repo'])
        self.api.installation_app_id = 78
        self.remote['app']['id'] = 78
        self.assertEqual(self.reconcile(app=78)['status'], 'RECONCILIATION_REQUIRED')
        self.remote['app']['id'] = 77
        self.assertEqual(self.reconcile()['status'], 'RECONCILIATION_REQUIRED')
        self.api.installation_app_id = 77
        self.api.installation_id = 43
        self.assertEqual(self.reconcile(installation=43)['status'], 'RECONCILIATION_REQUIRED')
        self.assertEqual(self.sweep()['status'], 'RECONCILIATION_REQUIRED')
        self.assertFalse(self.patches)
        self.api.installation_id = 42
        self.assertEqual(self.journal.get(self.job['id'])['publication_intent'], original['publication_intent'])
        self.assertEqual(self.reconcile()['state'], 'DONE')
        self.assertEqual(len(self.posts), 1)

    def test_ingress_installation_must_match_the_worker(self):
        other = {**self.job, 'id': 'ingress', 'installation_id': 43}
        self.journal.claim()
        self.journal.transition(self.job['id'], 'RUNNING', 'DRY_RUN')
        self.journal.enqueue(other)
        with self.assertRaisesRegex(ValueError, 'delivery installation mismatch'):
            self.publish()
        self.assertEqual(self.journal.get('ingress')['state'], 'QUEUED')
        self.assertFalse(self.posts)

    def test_legacy_sqlite_schema_keeps_uncertainty_without_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp)/'legacy.sqlite'
            db = sqlite3.connect(database)
            with db:
                db.execute('''CREATE TABLE jobs(id TEXT PRIMARY KEY,repo TEXT,pr INTEGER,body_sha256 TEXT,
                           state TEXT,report TEXT,external_id TEXT,check_id INTEGER)''')
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',
                           ('legacy', 'OWNER/REPO', 1, 'body', 'PUBLISHING', '{}', 'legacy-correlation', None))
            db.close()
            journal = Journal(database)
            try:
                result = reconcile(journal, self.api, 'legacy', 77, installation_id=42)
                self.assertEqual(result['status'], 'RECONCILIATION_REQUIRED')
                self.assertEqual(result['external_id'], 'legacy-correlation')
                self.assertEqual(journal.get('legacy')['state'], 'UNCERTAIN')
                f = self.fixture
                result = sweep(journal, self.api, self.policy, f.a, f.key.public_key(), f.r, f.trust,
                               77, installation_id=42, now=NOW+60, apply=True)
                self.assertEqual(result[0]['status'], 'RECONCILIATION_REQUIRED')
            finally:
                journal.close()
        self.assertFalse(self.posts or self.patches)

    def test_expired_ambiguous_creation_is_reconciled_then_revoked(self):
        original = self.lost_post()
        self.assertEqual(self.sweep(apply=False)['status'], 'WOULD_REVOKE')
        self.assertEqual(self.journal.get(self.job['id'])['state'], 'UNCERTAIN')
        self.assertEqual(self.sweep()['status'], 'REVOKED')
        self.assertEqual(self.remote['external_id'], original['external_id'])
        self.assertEqual(self.remote['conclusion'], 'failure')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def test_expired_interrupted_post_survives_restart(self):
        self.creation_fault = Interrupted()
        with self.assertRaises(Interrupted):
            self.publish()
        self.assertEqual(self.journal.get(self.job['id'])['state'], 'PUBLISHING')
        self.reopen()
        self.assertEqual(self.sweep()['status'], 'REVOKED')
        self.assertIsNone(self.publish())
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def test_uncertain_sweep_reports_missing_duplicate_and_malformed_observations(self):
        original = self.lost_post()
        unrelated = self.api.checks[:-1]
        for observations in ([], [self.remote, {**self.remote, 'id': 52}],
                             [{**self.remote, 'conclusion': {}}]):
            with self.subTest(observations=len(observations)):
                self.api.checks = unrelated + observations
                result = self.sweep()
                self.assertEqual(result['status'], 'RECONCILIATION_REQUIRED')
                self.assertEqual(result['external_id'], original['external_id'])
                self.assertEqual(self.journal.get(self.job['id'])['state'], 'UNCERTAIN')
        self.assertEqual(len(self.posts), 1)
        self.assertFalse(self.patches)

    def test_confirmed_malformed_get_does_not_patch(self):
        self.publish()
        for conclusion in ({}, False, None, 'unknown'):
            with self.subTest(conclusion=conclusion):
                self.remote['conclusion'] = conclusion
                self.assertEqual(self.sweep()['status'], 'REMOTE_STATE_UNKNOWN')
        self.assertFalse(self.patches)

    def test_lost_and_malformed_revocation_acknowledgements_require_observation(self):
        self.publish()
        for fault in ('lost', 'malformed'):
            with self.subTest(fault=fault):
                self.remote['conclusion'] = 'success'
                self.revocation_fault = fault
                result = self.sweep()
                self.assertEqual(result['status'], 'REVOCATION_UNCERTAIN')
                self.assertEqual(result['external_id'], self.remote['external_id'])
                self.assertEqual(self.journal.get(self.job['id'])['state'], 'REVOCATION_UNCERTAIN')
                self.reopen()
                self.assertEqual(self.sweep()['status'], 'ALREADY_BLOCKED')
                self.assertEqual(self.journal.get(self.job['id'])['state'], 'DONE')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 2))

    def test_invalid_prerequisite_identifiers_cannot_satisfy_gate(self):
        original = copy.deepcopy(self.api.checks[0])
        for field, bad in (('id', -1), ('id', True), ('id', 0), ('id', '2'),
                           ('app', {'id': float(original['app']['id'])})):
            with self.subTest(field=field, bad=bad):
                self.api.checks[0] = {**original, field: bad}
                report = preflight(self.api, self.job['repo'], self.job['pr'], self.policy)
                self.assertEqual(report['decision'], 'BLOCK')
        self.assertFalse(self.posts)

    def test_webhook_installation_id_is_exact(self):
        for value in (True, 1.0, 0, -1, '1', 1):
            with self.subTest(value=value):
                raw = json.dumps({'action': 'opened', 'repository': {'full_name': self.job['repo']},
                                  'installation': {'id': value}, 'pull_request': {'number': 1}}).encode()
                signature = 'sha256=' + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
                if type(value) is int and value == 1:
                    self.assertEqual(delivery(raw, signature, 'pull_request', 'hook', SECRET,
                                              self.job['repo'], 1)['installation_id'], 1)
                else:
                    with self.assertRaises(ValueError):
                        delivery(raw, signature, 'pull_request', 'hook', SECRET, self.job['repo'], 1)
