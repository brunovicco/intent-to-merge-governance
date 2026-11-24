import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from intent_merge.control_plane import lab_http, MAX

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_gitleaks', ROOT / 'scripts/review_gitleaks.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

class SecurityRemediationTests(unittest.TestCase):
    def test_non_lab_urls(self):
        with patch('intent_merge.control_plane.HTTPConnection') as conn:
            for endpoint in ('file:///etc/passwd','https://127.0.0.1:1234','http://example.org:80','http://provenance:8080','http://intent:80','http://127.0.0.1:80/foo','http://user@127.0.0.1:80'):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    lab_http('intent',endpoint,'/health')
            conn.assert_not_called()

    def test_no_redirect(self):
        with patch('intent_merge.control_plane.HTTPConnection') as conn:
            response=conn.return_value.getresponse.return_value.__enter__.return_value
            response.status=302
            with self.assertRaises(ValueError):lab_http('intent','http://intent:8080','/health')
            conn.assert_called_once_with('intent',8080,timeout=3)
            conn.return_value.close.assert_called_once()

    def test_valid_health_and_response_cap(self):
        with patch('intent_merge.control_plane.HTTPConnection') as conn:
            response=conn.return_value.getresponse.return_value.__enter__.return_value
            response.status=200;response.read.return_value=b'{"ok":true}'
            self.assertEqual(lab_http('intent','http://127.0.0.1:8123','/health'),{'ok':True})
            response.read.assert_called_with(MAX+1)
            response.read.return_value=b'x'*(MAX+1)
            with self.assertRaises(ValueError):lab_http('intent','http://127.0.0.1:8123','/health')

    def test_scoped_public_key_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);fixture=root/review.FIXTURE;fixture.parent.mkdir(parents=True);shutil.copyfile(ROOT/review.FIXTURE,fixture)
            findings=[{'RuleID':'generic-api-key','File':str(fixture),'StartLine':n,'EndLine':n} for n in sorted(review.LINES)]
            self.assertEqual(review.classify(root,findings)['status'],'REVIEWED_PUBLIC_KEYS_ONLY')
            for additional in ({**findings[0],'RuleID':'other-rule'},{**findings[0],'File':str(root/'other.json')},{**findings[0],'StartLine':13,'EndLine':13},findings[0]):
                self.assertEqual(review.classify(root,findings+[additional])['status'],'REVIEW_REQUIRED')
            fixture.write_bytes(fixture.read_bytes()+b' ')
            self.assertEqual(review.classify(root,findings)['status'],'REVIEW_REQUIRED')

    def test_empty_report_not_a_review(self):
        self.assertEqual(review.classify(ROOT,[])['status'],'REVIEW_REQUIRED')
