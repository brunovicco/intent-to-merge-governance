import contextlib
import io
import json
import sqlite3
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge import cli, ops_cli
from intent_merge.cli_errors import failure, TelemetryUnavailable, telemetry_provider

ROOT = Path(__file__).resolve().parents[1]


class FailureContractTests(unittest.TestCase):
    def test_failure_never_authorizes(self):
        for exc in (ValueError('private'), sqlite3.Error('private'), RuntimeError('private')):
            with self.subTest(exc=type(exc)):
                result = failure('demo', exc)
                self.assertFalse(result['authorized'])
                self.assertFalse(result['merge_authority'])
                self.assertEqual(result['decision'], 'BLOCK')
                self.assertNotIn('private', json.dumps(result))

    def test_operational_error_types(self):
        for exc in (OSError(), sqlite3.Error(), subprocess.TimeoutExpired('git', 1)):
            self.assertEqual(failure('demo', exc)['reason'], 'OPERATIONAL_ERROR')

    def test_unknown_remote_state(self):
        self.assertEqual(failure('worker', ValueError(), remote_write_possible=True)['remote_state'], 'NOT_CONFIRMED')

    def test_missing_telemetry(self):
        with patch.dict('sys.modules', {'opentelemetry.sdk.trace': None}):
            with self.assertRaises(TelemetryUnavailable):
                telemetry_provider(io.StringIO())
        self.assertEqual(failure('worker', TelemetryUnavailable())['reason'], 'OPTIONAL_TELEMETRY_UNAVAILABLE')

    def invoke(self, main, args):
        err, out = io.StringIO(), io.StringIO()
        with patch('sys.argv', args), contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 1)
        self.assertEqual(out.getvalue(), '')
        result = json.loads(err.getvalue())
        self.assertFalse(result['authorized'])
        return result

    def preflight_args(self):
        return ['intent-merge', 'github-preflight', '--repo', 'OWNER/REPO', '--pr', '1', '--policy', str(ROOT/'examples/github-policy.toml')]

    def test_preflight_publish_requires_installation(self):
        with patch.object(cli, 'GitHub') as generic, patch.object(cli, 'installation_client') as app:
            result = self.invoke(cli.main, self.preflight_args() + ['--publish'])
        generic.assert_not_called()
        app.assert_not_called()
        self.assertEqual(result['decision'], 'BLOCK')

    def test_preflight_dry_run_uses_read_client(self):
        with patch('sys.argv', self.preflight_args()), patch.object(cli, 'GitHub') as generic, patch.object(cli, 'installation_client') as app, patch.object(cli, 'preflight', return_value={'decision':'BLOCK'}) as preflight, contextlib.redirect_stdout(io.StringIO()):
            cli.main()
        generic.assert_called_once_with()
        app.assert_not_called()
        self.assertFalse(preflight.call_args.kwargs['publish'])

    def test_preflight_app_credentials_route(self):
        args = self.preflight_args() + ['--publish', '--app-id','1','--installation','2','--app-key','key.pem']
        with patch('sys.argv', args), patch.object(cli, 'GitHub') as generic, patch.object(cli, 'installation_client') as app, patch.object(cli, 'preflight', return_value={'decision':'BLOCK'}) as preflight, contextlib.redirect_stdout(io.StringIO()):
            cli.main()
        generic.assert_not_called()
        app.assert_called_once_with(1, 2, Path('key.pem'), 'OWNER/REPO')
        self.assertTrue(preflight.call_args.kwargs['publish'])

    def test_cli_redacts_unexpected_failure(self):
        with patch.object(cli, 'run', side_effect=RuntimeError('private token')):
            result = self.invoke(cli.main, ['intent-merge','demo','--out','results/not-run'])
        self.assertEqual(result['reason'], 'UNEXPECTED_ERROR')
        self.assertNotIn('private', json.dumps(result))

    def test_ops_cli_reports_database_error(self):
        with patch.object(ops_cli, 'Journal', side_effect=sqlite3.OperationalError('private path')):
            result = self.invoke(ops_cli.main, ['itm-ops','journal','--db','results/not-run.sqlite'])
        self.assertEqual(result['reason'], 'OPERATIONAL_ERROR')
        self.assertNotIn('private', json.dumps(result))

    def test_demo_configuration_rejection_is_structured(self):
        from tempfile import TemporaryDirectory
        spec = (ROOT/'examples/spec.toml').read_text()
        policy = (ROOT/'examples/policy.toml').read_text()
        for name, spec_text, policy_text in (
                ('malformed', spec, 'secret = "sentinel'),
                ('duplicate', spec.replace('id = "R02"', 'id = "R01"'), policy),
                ('invalid-schema', spec, 'version = 42'),
                ('invalid-shape', spec.replace('[[requirements]]', '[[unused]]'), policy)):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'spec').write_text(spec_text)
                (root/'policy').write_text(policy_text)
                args = ['intent-merge', 'demo', '--out', str(root/'run'),
                        '--spec', str(root/'spec'), '--policy', str(root/'policy')]
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch('sys.argv', args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                    cli.main()
                self.assertEqual(exc.exception.code, 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result['decision']['status'], 'INVALID_CONFIGURATION')
                self.assertFalse(result['decision']['authorized'])
                self.assertFalse(result['merged'])
                self.assertNotIn('sentinel', stdout.getvalue()+stderr.getvalue())

    def test_missing_approval_block_is_a_successful_evaluation(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            args = ['intent-merge', 'demo', '--scenario', 'missing-approval', '--out', str(Path(tmp)/'run')]
            stdout = io.StringIO()
            with patch('sys.argv', args), contextlib.redirect_stdout(stdout):
                self.assertIsNone(cli.main())
            result = json.loads(stdout.getvalue())
            self.assertFalse(result['decision']['authorized'])
            self.assertFalse(result['merged'])

    def test_unavailable_config_file_is_operational(self):
        result = self.invoke(cli.main, ['intent-merge', 'demo', '--spec', 'missing-file.toml',
                                       '--out', 'results/not-run'])
        self.assertEqual(result['reason'], 'OPERATIONAL_ERROR')
        self.assertFalse(result['merged'])

    def test_benchmark_validates_typed_fields_before_hashing(self):
        from tempfile import TemporaryDirectory

        spec = (ROOT/'examples/spec.toml').read_text()
        values = ('2026-11-25', '2026-11-25T12:00:00Z', '12:00:00', '1.5', 'true',
                  '["configuration-secret"]', '{secret = "configuration-secret"}')
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec_path = root/'spec.toml'
            for value in values:
                with self.subTest(value=value):
                    spec_path.write_text(spec.replace('id = "PAY-104"', f'id = {value}', 1))
                    stdout, stderr = io.StringIO(), io.StringIO()
                    argv = ['intent-merge', 'benchmark', '--out', str(root/'out'),
                            '--spec', str(spec_path), '--policy', str(ROOT/'examples/policy.toml')]
                    with patch('sys.argv', argv), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                        cli.main()
                    self.assertEqual(exc.exception.code, 2)
                    result = json.loads(stderr.getvalue())
                    self.assertEqual(result['status'], 'INVALID_CONFIGURATION')
                    self.assertFalse(result['authorized'])
                    self.assertFalse(result['merged'])
                    self.assertFalse((root/'out').exists())
                    self.assertNotIn('configuration-secret', stdout.getvalue()+stderr.getvalue())

    def test_nested_json_configuration_errors_are_redacted(self):
        from tempfile import TemporaryDirectory

        cases = (
            ('autonomy-replay', 'examples/autonomy-v1/config.json', 'scope',
             ['configuration-secret'], ['--events', 'unused', '--expected-root', 'unused']),
            ('changeset-verify', 'examples/changeset-v1/config.json', 'components',
             {'payments': {'depends_on': [{'secret': 'configuration-secret'}]}},
             ['--receipt', 'unused', '--expected-config-digest', 'unused']),
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp)/'config.json'
            for command, original, field, value, extra in cases:
                with self.subTest(command=command):
                    source = json.loads((ROOT/original).read_text())
                    source[field] = value
                    path.write_text(json.dumps(source))
                    stderr = io.StringIO()
                    with patch('sys.argv', ['intent-merge', command, '--config', str(path), *extra]), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                        cli.main()
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(json.loads(stderr.getvalue())['status'], 'INVALID_CONFIGURATION')
                    self.assertNotIn('configuration-secret', stderr.getvalue())
