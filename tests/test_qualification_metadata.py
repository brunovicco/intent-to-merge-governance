import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class QualificationMetadataTests(unittest.TestCase):
    def test_generated_qualification_reports_use_the_project_version(self):
        project = tomllib.loads((ROOT/'pyproject.toml').read_text())['project']
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'qualification'
            subprocess.run([sys.executable, str(ROOT/'scripts/rc1_validate.py'), '--out', str(out)],
                           cwd=ROOT, check=True, capture_output=True, timeout=120)
            report = json.loads((out/'report.json').read_text())
            self.assertEqual(report['release'], project['version'])
            self.assertIn(f"<h1>{project['version']}</h1>", (out/'report.html').read_text())
            self.assertTrue(all(report[field] is False for field in
                                ('publication_ready', 'production_ready', 'merge_authority')))
