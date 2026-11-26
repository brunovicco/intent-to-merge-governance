import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from intent_merge import cli, operational
from intent_merge.cli_errors import failure
from intent_merge.github import GitHub, CheckPublicationUnconfirmed, preflight, policy_from
from test_integration_v05 import FixtureAPI, ROOT


class InstallationContractTests(unittest.TestCase):
    def client(self, body):
        # No private key or network: mock only the authentication exchange.
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(body).encode()
        with patch.object(Path, 'read_bytes', return_value=b'fixture'), \
                patch.object(operational.serialization, 'load_pem_private_key'), \
                patch.object(operational, 'app_jwt', return_value='fixture-jwt'), \
                patch.object(operational, 'build_opener') as opener:
            opener.return_value.open.return_value = response
            return operational.installation_client(789, 2, Path('fixture'), 'OWNER/REPO')

    def test_invalid_installation_token_no_fallback(self):
        with patch.dict(os.environ, {'ITM_GITHUB_TOKEN': 'read-token'}):
            for body in ({}, {'token': None}, {'token': ''}, {'token': 12}, {'token': ' '}, {'token': 'x\ny'}, {'token': ['x']}, [], {'token': 'x'*16385}):
                with self.subTest(body=type(body)), self.assertRaises(ValueError):
                    self.client(body)

    def test_installation_token_identity(self):
        with patch.dict(os.environ, {'ITM_GITHUB_TOKEN': 'read-token'}):
            client = self.client({'token': 'installation-fixture'})
        self.assertEqual(client.token, 'installation-fixture')
        self.assertEqual(client.installation_app_id, 789)
        self.assertEqual(client.installation_id, 2)
        self.assertEqual(client.installation_repository, 'OWNER/REPO')

    def test_declared_token_response_identity_must_be_exact(self):
        for field, value in (('app_id', 789.0), ('app_id', 788), ('installation_id', True),
                             ('installation_id', 3), ('installation_id', '2')):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.client({'token': 'fixture', field: value})
        client = self.client({'token': 'fixture', 'app_id': 789, 'installation_id': 2})
        self.assertEqual(client.installation_id, 2)

    def test_explicit_invalid_token_cannot_fallback(self):
        with patch.dict(os.environ, {'ITM_GITHUB_TOKEN': 'read-token'}):
            for token in ('', None, ' '):
                with self.subTest(token=token), self.assertRaises(ValueError):
                    GitHub(token, installation_app_id=789)
            with self.assertRaises(ValueError):
                GitHub('')
            self.assertEqual(GitHub().token, 'read-token')


class PublicationContractTests(unittest.TestCase):
    def setUp(self):
        self.api = FixtureAPI()
        self.policy = policy_from(ROOT/'examples/github-policy.toml')

    def gate(self):
        return preflight(self.api, 'OWNER/REPO', 1, self.policy, publish=True)

    def test_no_app_identity_no_post(self):
        self.api.installation_app_id = None
        with self.assertRaises(ValueError): self.gate()
        self.assertEqual(self.api.posts, [])
        self.assertEqual(self.api.reads, 0)

    def test_matched_response(self):
        result = self.gate()
        self.assertEqual(result['publication_confirmation'], 'RESPONSE_MATCHED')
        self.assertEqual(result['published_external_id'], self.api.posts[0][1]['external_id'])
        self.assertEqual(result['published_check_id'], 44)
        self.assertFalse(result['full_itm_authorization'])

    def test_malformed_response_never_confirmed(self):
        original = self.api.request
        for field, value in [('id', 0), ('id', True), ('app', None), ('app', {'id': 788}), ('app', {'id': 789.0}), ('name', 'other'), ('head_sha', 'f'*40), ('status', 'queued'), ('conclusion', 'failure'), ('external_id', 'wrong')]:
            def request(path, payload=None):
                result = original(path, payload)
                if payload is not None: result[field] = value
                return result
            self.api.request = request
            self.api.posts.clear()
            with self.subTest(field=field, value=value), self.assertRaises(CheckPublicationUnconfirmed) as error:
                self.gate()
            self.assertEqual(len(self.api.posts), 1)
            report = failure('github-preflight', error.exception)
            self.assertEqual(report['remote_state'], 'NOT_CONFIRMED')
            self.assertEqual(report['publication']['external_id'], self.api.posts[0][1]['external_id'])
            self.assertFalse(report['authorized'])

    def test_lost_response_is_correlated_not_retried(self):
        original = self.api.request
        def request(path, payload=None):
            result = original(path, payload)
            if payload is not None: raise OSError('private path or token')
            return result
        self.api.request = request
        with self.assertRaises(CheckPublicationUnconfirmed) as error:
            self.gate()
        self.assertEqual(len(self.api.posts), 1)
        report = failure('github-preflight', error.exception)
        self.assertNotIn('private', json.dumps(report))
        self.assertEqual(report['publication']['head_sha'], self.api.posts[0][1]['head_sha'])

    def test_invalid_configuration_nonzero_and_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); policy = root/'policy.toml'; policy.write_text('version = 999\n')
            out = root/'run'; stdout = io.StringIO(); stderr = io.StringIO()
            args = ['intent-merge', 'demo', '--out', str(out), '--spec', str(ROOT/'examples/spec.toml'), '--policy', str(policy)]
            with patch('sys.argv', args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                cli.main()
            self.assertEqual(error.exception.code, 2)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['decision']['status'], 'INVALID_CONFIGURATION')
            self.assertFalse(result['merged'])
            self.assertFalse(result['decision']['authorized'])
            self.assertEqual(json.loads((out/'configuration-rejection.jsonl').read_text())['kind'], 'configuration_rejected')
            self.assertFalse((out/'repo').exists())

    def assert_bad_observations(self, messages):
        for route, payload, message in messages:
            with self.subTest(route=route, payload_type=type(payload)):
                client = GitHub('fixture-token', installation_app_id=789)

                def request(path, body=None):
                    self.assertIsNone(body, 'invalid observations must stop before POST')
                    if path.split('?')[0].endswith(route):
                        return payload
                    if '/check-runs?' in path:
                        return {'check_runs': self.api.checks}
                    if '/files?' in path:
                        return self.api.files
                    if '/reviews?' in path:
                        return self.api.reviews
                    return self.api.pr

                with patch.object(client, 'request', side_effect=request):
                    with self.assertRaisesRegex(ValueError, '^' + message + '$') as caught:
                        preflight(client, 'OWNER/REPO', 1, self.policy, publish=True)
                self.assertEqual(type(caught.exception).__name__, 'GitHubObservationError')

    def test_review_containers_and_nested_fields_are_validated(self):
        review = self.api.reviews[0]
        self.assert_bad_observations([
            ('/reviews', payload, 'invalid GitHub collection') for payload in ({}, None, 'private fixture')
        ] + [
            ('/reviews', [payload, *self.api.reviews], 'invalid review observation')
            for payload in (None, 'private fixture', 7, {'id': 10}, {**review, 'id': 10, 'user': None},
                            {**review, 'id': 10, 'user': 'private fixture'},
                            {**review, 'id': 10, 'user': {'id': True, 'type': 'User'}},
                            {**review, 'id': 10, 'user': {'id': 1}},
                            {**review, 'id': 10, 'user': {'id': 1, 'type': 1}},
                            {**review, 'id': 10, 'state': []},
                            {'id': 10, 'user': review['user'], 'state': 'APPROVED'},
                            {**review, 'id': 10, 'commit_id': {'unexpected': 1}})
        ])

    def test_pr_file_and_prerequisite_containers_are_validated(self):
        pr = self.api.pr
        self.assert_bad_observations([
            ('/pulls/1', payload, 'invalid PR observation')
            for payload in (None, [], {**pr, 'user': None}, {**pr, 'head': []},
                            {**pr, 'head': {**pr['head'], 'repo': None}},
                            {**pr, 'base': {**pr['base'], 'sha': 1}},
                            {**pr, 'base': {**pr['base'], 'ref': 1}},
                            {**pr, 'base': {**pr['base'], 'repo': {'full_name': []}}})
        ] + [
            ('/files', [payload], 'invalid PR file observation')
            for payload in (None, {}, {'filename': 'app/payments.py', 'status': {}},
                            {'filename': 'app/payments.py', 'status': 'unknown'},
                            {'filename': 'app/payments.py', 'status': 'renamed', 'previous_filename': []})
        ] + [
            ('/check-runs', payload, 'invalid GitHub collection')
            for payload in ([], None, {}, {'check_runs': {}})
        ])

    def test_malformed_prerequisite_record_cannot_leave_a_passing_gate(self):
        for payload in (None, {}, {'name': []}, {'name': 'trusted-ci', 'app': None}):
            with self.subTest(payload=payload):
                with patch.object(self.api, 'checks', [*self.api.checks, payload]):
                    report = preflight(self.api, 'OWNER/REPO', 1, self.policy)
                self.assertEqual(report['decision'], 'BLOCK')
                self.assertIn('check:trusted-ci', report['reasons'])
        self.assertEqual(preflight(self.api, 'OWNER/REPO', 1, self.policy)['decision'], 'PASS')

    def test_malformed_wire_json_has_a_redacted_domain_error(self):
        client = GitHub('fixture-token')
        for raw in (b'{"private fixture":}', b'{"private fixture":0,"private fixture":1}', b'\xff'):
            with self.subTest(raw=raw):
                with patch.object(client.opener, 'open') as opener:
                    opener.return_value.__enter__.return_value.read.return_value = raw
                    with self.assertRaisesRegex(ValueError, '^invalid GitHub response JSON$') as caught:
                        client.request('/repos/OWNER/REPO/pulls/1')
                self.assertEqual(type(caught.exception).__name__, 'GitHubObservationError')
