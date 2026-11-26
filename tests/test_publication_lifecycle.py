"""Adversarial transport observations and SQLite recovery boundaries."""
import base64
import copy
import io
import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from functools import partial
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from intent_merge import ops_cli
from intent_merge.core import canonical
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
            self.remote = {**payload, 'id': 40 + len(self.posts), 'app': {'id': 77}}
            self.api.checks.append(self.remote)
            if self.creation_fault:
                raise self.creation_fault
        elif '/check-runs/' in path:
            check_id = int(path.rsplit('/', 1)[-1])
            remote = next(row for row in self.api.checks if row['id'] == check_id)
            if method != 'PATCH':
                return copy.deepcopy(remote)
            self.patches.append(copy.deepcopy(payload))
            remote.update(payload)
            if self.revocation_fault == 'lost':
                raise OSError('mock response lost after PATCH')
            if self.revocation_fault == 'malformed':
                return {**remote, 'id': float(check_id)}
            return copy.deepcopy(remote)
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

    def sweep(self, apply=True, *, now=NOW+60):
        f = self.fixture
        return sweep(self.journal, self.api, self.policy, f.a, f.key.public_key(), f.r, f.trust,
                     77, installation_id=42, now=now, apply=apply)[0]

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

    def test_sweep_expires_during_check_get(self):
        self.publish()
        request = self.api.request

        def advance(path, *args, **kwargs):
            result = request(path, *args, **kwargs)
            if path.endswith('/check-runs/41') and not kwargs.get('method'):
                clock[0] = NOW+60
            return result

        clock = [NOW]
        with patch('intent_merge.hardening.time.time', side_effect=lambda: clock[0]), patch.object(
                self.api, 'request', side_effect=advance):
            self.assertEqual(self.sweep(now=None)['status'], 'REVOKED')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def test_sweep_expires_during_publishing_recovery(self):
        self.creation_fault = Interrupted()
        with self.assertRaises(Interrupted):
            self.publish()
        self.assertEqual(self.journal.get(self.job['id'])['state'], 'PUBLISHING')
        recover = self.journal.recover
        clock = [NOW]

        def recovery():
            recover()
            clock[0] = NOW+60

        with patch('intent_merge.hardening.time.time', side_effect=lambda: clock[0]), patch.object(
                self.journal, 'recover', side_effect=recovery):
            self.assertEqual(self.sweep(now=None)['status'], 'REVOKED')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def test_sweep_expires_during_uncertain_reconciliation(self):
        self.lost_post()
        with patch('intent_merge.hardening.time.time', self.advancing_clock_after_pages(NOW+60)):
            self.assertEqual(self.sweep(now=None)['status'], 'REVOKED')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def advancing_clock_after_pages(self, final):
        clock = [NOW]
        pages = self.api.pages

        def advance(*args, **kwargs):
            yield from pages(*args, **kwargs)
            clock[0] = final

        self.addCleanup(setattr, self.api, 'pages', pages)
        self.api.pages = advance
        return lambda: clock[0]

    def test_sweep_rejects_clock_regression_during_reconciliation(self):
        self.lost_post()
        with patch('intent_merge.hardening.time.time', self.advancing_clock_after_pages(NOW-1)):
            self.assertEqual(self.sweep(apply=False, now=None)['status'], 'WOULD_REVOKE')
        self.assertEqual(self.journal.get(self.job['id'])['state'], 'UNCERTAIN')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 0))

    def check_sweep_expiry(self, assertion, expiry):
        self.fixture.setup_evidence(expires_at=NOW+assertion)
        self.publish()
        self.assertEqual(self.sweep(apply=False, now=NOW+expiry-1)['status'], 'CURRENT')
        self.assertEqual(self.sweep(apply=True, now=NOW+expiry)['status'], 'REVOKED')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 1))

    def test_sweep_receipt_expires_before_assertion(self):
        self.check_sweep_expiry(assertion=90, expiry=60)

    def test_sweep_assertion_expires_before_receipts(self):
        self.check_sweep_expiry(assertion=45, expiry=45)

    def test_sweep_refresh_boundary_and_revocation_acknowledgements(self):
        self.publish()
        request = self.api.request
        for fault in ('lost', 'malformed', None):
            with self.subTest(fault=fault):
                self.remote['conclusion'] = 'success'
                self.revocation_fault = fault
                clock = [NOW]

                def refresh(path, *args, **kwargs):
                    result = request(path, *args, **kwargs)
                    if path.endswith('/pulls/1'):
                        clock[0] = NOW+60
                    return result

                with patch('intent_merge.hardening.time.time', side_effect=lambda: clock[0]), patch.object(
                        self.api, 'request', side_effect=refresh):
                    expected = 'REVOCATION_UNCERTAIN' if fault else 'REVOKED'
                    self.assertEqual(self.sweep(now=None)['status'], expected)
                self.assertEqual(self.sweep()['status'], 'ALREADY_BLOCKED')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 3))

    def test_sweep_rejects_missing_or_malformed_authenticated_expiry(self):
        self.publish()
        f = self.fixture
        for mutation in ('missing-assertion', 'bad-assertion', 'missing-receipt', 'bad-receipt'):
            with self.subTest(mutation=mutation):
                f.setup_evidence()
                if mutation.endswith('assertion'):
                    path = f.a / f.filename
                    envelope = json.loads(path.read_text())
                    artifact = envelope
                    signer, domain = f.key, test_hardening.DOMAIN
                else:
                    path = f.r / f.filename
                    artifact = json.loads(path.read_text())
                    envelope = artifact[0]
                    signer = f.keys[envelope['statement']['control']]
                    domain = test_hardening.RECEIPT_DOMAIN
                statement = envelope['statement']
                if mutation.startswith('missing'):
                    del statement['expires_at']
                else:
                    statement['expires_at'] = str(NOW+60)
                envelope['signature'] = base64.b64encode(signer.sign(domain+canonical(statement))).decode()
                path.write_text(json.dumps(artifact))
                self.assertEqual(self.sweep(apply=False, now=NOW)['status'], 'WOULD_REVOKE')
        self.assertFalse(self.patches)

    def test_sweep_samples_each_row(self):
        first = self.publish()
        self.assertEqual(first['decision'], 'PASS')
        self.journal.enqueue({**self.job, 'id': 'second'})
        self.publish()
        clock = [NOW]

        def get_check(path, payload=None, *, method=None):
            result = self.request(path, payload, method=method)
            if path.endswith('/check-runs/42'):
                clock[0] = NOW+60
            return result

        f = self.fixture
        with patch('intent_merge.hardening.time.time', side_effect=lambda: clock[0]), patch.object(
                self.api, 'request', side_effect=get_check):
            results = sweep(self.journal, self.api, self.policy, f.a, f.key.public_key(),
                            f.r, f.trust, 77, installation_id=42)
        self.assertEqual([row['status'] for row in results], ['CURRENT', 'WOULD_REVOKE'])
        self.assertEqual((len(self.posts), len(self.patches)), (2, 0))

    def test_sweep_keeps_uncertain_when_exact_get_is_unconfirmed(self):
        self.lost_post()
        request = self.api.request

        def unknown(path, *args, **kwargs):
            if path.endswith('/check-runs/41'):
                raise OSError('mock GET unavailable')
            return request(path, *args, **kwargs)

        with patch.object(self.api, 'request', side_effect=unknown):
            self.assertEqual(self.sweep()['status'], 'REMOTE_STATE_UNKNOWN')
        self.assertEqual(self.journal.get(self.job['id'])['state'], 'UNCERTAIN')
        self.assertEqual((len(self.posts), len(self.patches)), (1, 0))

    def exercise_batch(self, expiries, malformed, *, wrong_id=None, lost_id=None, apply=True, cli=False):
        """Supply observations keyed by the exact check GET that starts each row."""
        f = self.fixture
        for i, expiry in enumerate(expiries):
            f.setup_evidence(expires_at=NOW+expiry)
            if i:
                self.journal.enqueue({**self.job, 'id': f'row-{i + 1}'})
            self.assertEqual(self.publish()['decision'], 'PASS')
        original = self.journal.list()

        # Use the last publication's evidence for the well-formed row.
        active = None
        clock = NOW
        pages = self.api.pages
        patched = []

        def request(path, payload=None, *, method=None):
            nonlocal active, clock
            self.assertFalse(path.endswith('/check-runs'), 'sweep must never create a check')
            if '/check-runs/' in path:
                check_id = int(path.rsplit('/', 1)[1])
                if method == 'PATCH':
                    patched.append(check_id)
                    if check_id == lost_id:
                        self.revocation_fault = 'lost'
                    try:
                        return self.request(path, payload, method=method)
                    finally:
                        self.revocation_fault = None
                active = check_id
                clock = NOW+20 if check_id > 41 else NOW+5
                response = self.request(path)
                if check_id == wrong_id:
                    response['external_id'] = 'unrelated'
                return response
            return self.request(path, payload, method=method)

        def observe_pages(path, key=None):
            if active in malformed and path.endswith('/reviews'):
                return iter([{'id': 11, 'user': None, 'state': 'APPROVED'}])
            return pages(path, key)

        with patch.object(self.api, 'request', side_effect=request), \
                patch.object(self.api, 'pages', side_effect=observe_pages), \
                patch('intent_merge.hardening.time.time', side_effect=lambda: clock):
            if cli:
                results = self.cli_sweep()
            else:
                results = sweep(self.journal, self.api, self.policy, f.a, f.key.public_key(),
                                f.r, f.trust, 77, installation_id=42, apply=apply)
        fields = ('report', 'publication_intent', 'external_id', 'check_id')
        self.assertEqual([{k: row[k] for k in fields} for row in original],
                         [{k: row[k] for k in fields} for row in self.journal.list()])
        self.assertEqual(len(self.posts), len(expiries))
        return results, patched

    def cli_sweep(self):
        f = self.fixture
        trust, key = f.root / 'trust.json', f.root / 'verifier.pub'
        trust.write_text(json.dumps(f.trust))
        key.write_bytes(f.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        args = ['itm-ops', 'sweep', '--db', str(self.db), '--policy',
                str(test_hardening.ROOT / 'examples/github-policy.toml'),
                '--app-id', '77', '--installation', '42', '--app-key', str(key),
                '--control-trust', str(trust), '--verifier-key', str(key),
                '--assertions', str(f.a), '--receipts', str(f.r), '--publish']
        out = io.StringIO()
        with patch('sys.argv', args), patch.object(ops_cli, 'installation_client', return_value=self.api), \
                redirect_stdout(out), self.assertRaises(SystemExit) as caught:
            ops_cli.main()
        self.assertEqual(caught.exception.code, 2)
        return json.loads(out.getvalue())

    def test_null_review_does_not_prevent_later_expired_revocation(self):
        results, patched = self.exercise_batch([45, 20], {41})
        self.assertEqual([r['status'] for r in results], ['REVOKED', 'REVOKED'])
        self.assertEqual(results[0]['reason'], 'preflight_observation_unavailable')
        self.assertEqual(patched, [41, 42])
        self.assertEqual(self.remote['conclusion'], 'failure')

    def test_mixed_batch_preserves_unresolved_outcomes_and_later_current(self):
        results, patched = self.exercise_batch([45, 20, 50], {41}, lost_id=42, cli=True)
        self.assertEqual([r['status'] for r in results], ['REVOKED', 'REVOCATION_UNCERTAIN', 'CURRENT'])
        self.assertEqual(results[1]['external_id'], self.journal.get('row-2')['external_id'])
        self.assertEqual(self.journal.get('row-2')['state'], 'REVOCATION_UNCERTAIN')
        self.assertEqual(patched, [41, 42])

    def test_malformed_final_row_preserves_prior_result(self):
        results, patched = self.exercise_batch([50, 50], {42}, apply=False)
        self.assertEqual([r['status'] for r in results], ['CURRENT', 'WOULD_REVOKE'])
        self.assertEqual(results[1]['reason'], 'preflight_observation_unavailable')
        self.assertTrue(results[1]['action'])
        self.assertFalse(patched)

    def test_unconfirmed_first_identity_preserves_correlation_and_continues(self):
        results, patched = self.exercise_batch([45, 20], {41}, wrong_id=41)
        self.assertEqual([r['status'] for r in results], ['REMOTE_STATE_UNKNOWN', 'REVOKED'])
        self.assertEqual(results[0]['external_id'], self.journal.get(self.job['id'])['external_id'])
        self.assertTrue(results[0]['action'])
        self.assertEqual(patched, [42])
        self.assertEqual(self.api.checks[-2]['conclusion'], 'success')

    def test_systemic_journal_and_unexpected_evaluation_failures_propagate(self):
        self.publish()
        with patch.object(self.journal, 'transition', side_effect=sqlite3.OperationalError('fixture failure')):
            with self.assertRaises(sqlite3.OperationalError):
                self.sweep()
        with patch('intent_merge.hardening.strict_gate', side_effect=TypeError('unexpected implementation fault')):
            with self.assertRaises(TypeError):
                self.sweep(now=NOW)
        self.assertEqual(len(self.posts), 1)
        self.assertFalse(self.patches)
