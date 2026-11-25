import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge.evidence_patch import PAYMENT_PATH, verify_patch
from intent_merge.runner import audit, run

ROOT = Path(__file__).resolve().parents[1]


class EvidencePatchTests(unittest.TestCase):
    def test_producer_ignores_ambient_diff_settings(self):
        settings = {
            'diff.suppressBlankEmpty': 'true', 'diff.mnemonicPrefix': 'true',
            'diff.noprefix': 'true', 'diff.context': '0', 'diff.interHunkContext': '20',
            'diff.algorithm': 'histogram', 'diff.renames': 'copies', 'color.diff': 'always',
            'diff.external': '/nonexistent-diff-driver', 'diff.orderFile': '/nonexistent-order',
        }
        environment = {'GIT_CONFIG_COUNT': str(len(settings)),
                       'GIT_DIFF_OPTS': '--unified=0', 'GIT_EXTERNAL_DIFF': '/nonexistent-diff'}
        for index, (key, value) in enumerate(settings.items()):
            environment.update({f'GIT_CONFIG_KEY_{index}': key, f'GIT_CONFIG_VALUE_{index}': value})
        with tempfile.TemporaryDirectory() as tmp:
            reference, ambient = Path(tmp)/'reference', Path(tmp)/'ambient'
            spec, policy = ROOT/'examples/spec.toml', ROOT/'examples/policy.toml'
            run('happy', reference, spec, policy)
            with patch.dict(os.environ, environment):
                run('happy', ambient, spec, policy)
            expected = [p.read_bytes() for p in sorted((reference/'evidence').glob('*.diff'))]
            self.assertTrue(any(b'\n \n' in p for p in expected))
            self.assertEqual(expected, [p.read_bytes() for p in sorted((ambient/'evidence').glob('*.diff'))])
            self.assertTrue(audit(ambient, ambient/'anchor.json', ambient/'demo-trust.json')['merged'])

    def test_reader_agrees_with_git_on_supported_patch_boundaries(self):
        cases = [
            (b'a\n\nb\n', b'A\n\nb\n', '-U3'),
            (b'a\r\nb\r\n', b'a\r\nB\r\n', '-U3'),
            (b'a\nb', b'a\nB\n', '-U3'),
            (b'a\nb\n', b'a\nb', '-U3'),
            (b'a\n', b'b\na\n', '-U0'),
            (b'a\n', b'a\nb\n', '-U0'),
            (b'a\n', b'', '-U0'),
            (b'', b'a\n', '-U0'),
            (b'a\n'+b'x\n'*20+b'b\n', b'A\n'+b'x\n'*20+b'B\n', '-U3'),
            (b'unchanged\n', b'unchanged\n', '-U3'),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/PAYMENT_PATH
            path.parent.mkdir()
            def git(*args, data=None):
                return subprocess.run(['git', '-C', tmp, '-c', 'diff.suppressBlankEmpty=false', *args],
                                      input=data, capture_output=True, check=True).stdout
            git('init', '--object-format=sha1')
            for baseline, candidate, context in cases:
                with self.subTest(baseline=baseline, candidate=candidate, context=context):
                    path.write_bytes(baseline)
                    git('add', '--', PAYMENT_PATH)
                    path.write_bytes(candidate)
                    diff = git('diff', '--full-index', '--no-color', '--no-ext-diff',
                               '--src-prefix=a/', '--dst-prefix=b/', context)
                    verify_patch(diff, baseline, candidate)
                    path.write_bytes(baseline)
                    if diff:
                        git('apply', '--unidiff-zero', '-', data=diff)
                    self.assertEqual(path.read_bytes(), candidate)
