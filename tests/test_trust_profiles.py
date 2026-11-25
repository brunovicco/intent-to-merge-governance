import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge.evidence_profile import HISTORICAL_V1
from intent_merge.runner import run
from intent_merge.trust import ANCHORED, SYNTHETIC, audit_anchored, audit_synthetic

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TrustProfilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.original = Path(cls.workspace.name) / 'original'
        run('happy', cls.original, ROOT/'examples/spec.toml', ROOT/'examples/policy.toml')

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)/'run'
        shutil.copytree(self.original, self.out)
        self.anchor = self.out/'anchor.json'
        self.trust = self.out/'demo-trust.json'
        self.pins = dict(expected_anchor_sha256=sha(self.anchor), expected_trust_sha256=sha(self.trust))

    def anchored(self, **overrides):
        return audit_anchored(self.out, self.anchor, self.trust, **(self.pins | overrides))

    def test_synthetic_has_no_authority(self):
        result = audit_synthetic(self.out, self.anchor, self.trust)
        self.assertEqual(result['trust_profile'], SYNTHETIC)
        self.assertTrue(result['merged'])
        self.assertFalse(result['merge_authority'])
        self.assertFalse(result['current_authorization'])
        self.assertFalse(result['organizational_authority_verified'])

    def test_anchored_success_is_historical_only(self):
        result = self.anchored()
        self.assertEqual(result['trust_profile'], ANCHORED)
        self.assertTrue(result['pins_verified'])
        self.assertFalse(result['current_authorization'])
        self.assertFalse(result['organizational_authority_verified'])
        self.assertFalse(result['merge_authority'])
        self.assertFalse(result['production_ready'])

    def test_wrong_anchor_pin(self):
        with self.assertRaisesRegex(ValueError, 'external pin mismatch'):
            self.anchored(expected_anchor_sha256='0'*64)

    def test_wrong_trust_pin(self):
        with self.assertRaisesRegex(ValueError, 'external pin mismatch'):
            self.anchored(expected_trust_sha256='0'*64)

    def test_malformed_pin(self):
        with self.assertRaisesRegex(ValueError, 'pin required'):
            self.anchored(expected_anchor_sha256='')

    def test_changed_trust_even_same_directory(self):
        self.trust.write_text(self.trust.read_text()+'\n')
        with self.assertRaisesRegex(ValueError, 'external pin mismatch'):
            self.anchored()

    def test_changed_manifest(self):
        (self.out/'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'manifest anchor mismatch'):
            self.anchored()

    def test_changed_evidence(self):
        p = self.out/'evidence/report.json'
        p.write_text(p.read_text()+'\n')
        with self.assertRaisesRegex(ValueError, 'artifact integrity mismatch'):
            self.anchored()

    def test_extra_artifact(self):
        (self.out/'evidence/extra').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            self.anchored()

    def test_missing_artifact(self):
        (self.out/'evidence/report.json').unlink()
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            self.anchored()

    def test_symlink_artifact(self):
        path = self.out/'evidence/report.json'
        path.unlink()
        path.symlink_to(self.original/'evidence/report.json')
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.anchored()

    def test_pinned_duplicate_keys_rejected(self):
        keys = json.loads(self.trust.read_text())
        keys['security'] = keys['reviewer']
        self.trust.write_text(json.dumps(keys))
        with self.assertRaisesRegex(ValueError, 'duplicate approval key'):
            self.anchored(expected_trust_sha256=sha(self.trust))

    def test_pinned_hmac_rejected(self):
        self.trust.write_text(json.dumps({'reviewer': '0'*64}))
        with self.assertRaisesRegex(ValueError, 'public Ed25519'):
            self.anchored(expected_trust_sha256=sha(self.trust))

    def test_pinned_duplicate_json_member_rejected(self):
        self.trust.write_text('{"a":"x","a":"y"}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON member'):
            self.anchored(expected_trust_sha256=sha(self.trust))

    def test_legacy_bundle_cannot_enter_anchored_mode(self):
        legacy = ROOT/'examples/amgb-v1/bundles/happy'
        anchor, trust = legacy/'anchor.json', legacy/'approval-trust.json'
        with self.assertRaisesRegex(ValueError, 'current lab profiles'):
            audit_anchored(legacy, anchor, trust, expected_anchor_sha256=sha(anchor),
                           expected_trust_sha256=sha(trust))
        self.assertTrue(audit_synthetic(legacy, anchor, trust, profile=HISTORICAL_V1)['merged'])

    def test_snapshot_not_original_passed_to_audit(self):
        from intent_merge.runner import audit
        def check(stage, anchor, trust):
            self.assertNotEqual(stage, self.out)
            self.assertEqual(sha(anchor), self.pins['expected_anchor_sha256'])
            self.assertEqual(sha(trust), self.pins['expected_trust_sha256'])
            return audit(stage, anchor, trust)
        with patch('intent_merge.trust.audit', side_effect=check):
            self.assertTrue(self.anchored()['pins_verified'])

    def repin_manifest(self, manifest):
        path = self.out/'manifest.json'
        path.write_text(json.dumps(manifest))
        anchor = json.loads(self.anchor.read_text())
        anchor['manifest'] = sha(path)
        self.anchor.write_text(json.dumps(anchor))
        self.pins['expected_anchor_sha256'] = sha(self.anchor)

    def test_pinned_traversal_manifest_rejected(self):
        manifest = json.loads((self.out/'manifest.json').read_text())
        manifest['../outside'] = '0'*64
        self.repin_manifest(manifest)
        with self.assertRaisesRegex(ValueError, 'invalid manifest entry'):
            self.anchored()

    def test_pinned_empty_ledger_rejected(self):
        path = self.out/'evidence/ledger.jsonl'
        path.write_bytes(b'')
        manifest = json.loads((self.out/'manifest.json').read_text())
        manifest[path.name] = sha(path)
        self.repin_manifest(manifest)
        with self.assertRaisesRegex(ValueError, 'empty ledger'):
            self.anchored()
