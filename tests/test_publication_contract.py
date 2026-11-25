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
