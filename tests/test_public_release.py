import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('inventory_under_test', Path(__file__).resolve().parents[1] / 'scripts/release_inventory.py')
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)

class PublicInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'pyproject.toml').write_text('[project]\nversion="1.0.0"\n')
        (self.root / 'source.txt').write_text('original')
        self.expected = {'profile': inv.PROFILE, 'release': '1.0.0', 'files': inv.files(self.root)}
        (self.root / inv.INVENTORY).write_text(json.dumps(self.expected))

    def test_draft_requires_lock_for_final(self):
        self.assertEqual(inv.verify(self.root)['status'], 'PASS')
        self.assertEqual(inv.verify(self.root, True)['status'], 'FAIL')

    def test_diagnostics(self):
        (self.root / 'source.txt').write_text('changed')
        (self.root / 'uv.lock').write_text('new')
        r = inv.verify(self.root)
        self.assertEqual(r['modified'], ['source.txt'])
        self.assertEqual(r['extra'], ['uv.lock'])
        self.assertEqual(r['status'], 'FAIL')
        (self.root / 'source.txt').unlink()
        self.assertEqual(inv.verify(self.root)['missing'], ['source.txt'])

    def test_seal_only_new_lock(self):
        (self.root / 'uv.lock').write_text('resolver output simulated')
        with patch.object(inv.subprocess, 'run') as run:
            r = inv.seal_lock(self.root)
            run.assert_called_once()
        self.assertTrue(r['lockfile_in_inventory'])
        self.assertEqual(r['status'], 'PASS')
        self.assertFalse(r['publication_ready'])
        (self.root / 'uv.lock').write_text('tampered')
        self.assertEqual(inv.verify(self.root, True)['modified'], ['uv.lock'])

    def test_seal_rejects_other_changes(self):
        (self.root / 'uv.lock').write_text('new')
        (self.root / 'source.txt').write_text('changed')
        before = (self.root / inv.INVENTORY).read_bytes()
        with patch.object(inv.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                inv.seal_lock(self.root)
            run.assert_not_called()
        self.assertEqual((self.root / inv.INVENTORY).read_bytes(), before)

    def test_seal_refuses_failed_uv_check(self):
        (self.root / 'uv.lock').write_text('invalid')
        before = (self.root / inv.INVENTORY).read_bytes()
        with patch.object(inv.subprocess, 'run', side_effect=inv.subprocess.CalledProcessError(1, 'uv')):
            with self.assertRaises(inv.subprocess.CalledProcessError):
                inv.seal_lock(self.root)
        self.assertEqual((self.root / inv.INVENTORY).read_bytes(), before)

    def test_secret_file_rejected(self):
        (self.root / 'private.pem').write_text('not a real key')
        with self.assertRaises(ValueError):
            inv.files(self.root)

    def test_symlink_rejected(self):
        (self.root / 'link').symlink_to(self.root / 'source.txt')
        with self.assertRaises(ValueError):
            inv.files(self.root)
