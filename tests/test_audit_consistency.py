"""Reject internally inconsistent evidence even with valid pins/signatures."""
import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from intent_merge.bundle import inventory, keygen, key_id, pack, pae, verify, PAYLOAD_TYPE
from intent_merge.core import canonical, digest, file_hash, load_config
from intent_merge.intent import build_graph, graph_mermaid, requirement_coverage
from intent_merge.runner import run, write_json
from intent_merge.trust import audit_anchored

ROOT = Path(__file__).resolve().parents[1]


class SemanticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.root = Path(tmp.name)
        spec = cls.root / 'spec.toml'
        spec.write_text((ROOT/'examples/spec.toml').read_text().replace(
            'allowed_paths = ["app/payments.py"]',
            'allowed_paths = ["app/payments.py", "docs/**"]'))
        cls.original = cls.root/'original'
        run('happy', cls.original, spec, ROOT/'examples/policy.toml')
        cls.private, cls.public = cls.root/'key.pem', cls.root/'key.pub'
        keygen(cls.private, cls.public)
        cls.bundle = cls.root/'bundle'
        pack(cls.original, cls.bundle, cls.private)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)/'run'
        shutil.copytree(self.original, self.out)
        self.ev = self.out/'evidence'
        self.events = [json.loads(line) for line in (self.ev/'ledger.jsonl').read_text().splitlines()]
        self.report = json.loads((self.ev/'report.json').read_text())

    def payload(self, kind):
        return next(e['payload'] for e in self.events if e['kind'] == kind)

    def reseal(self):
        prev = '0'*64
        proposal_hashes = {}
        for i, event in enumerate(self.events):
            if event['kind'] == 'checkpoint':
                cp = event['payload']['universal']
                cp['proposal_event_hash'] = proposal_hashes[cp['proposal_event_hash']]
            old_hash = event['hash']
            event.update(seq=i, prev=prev)
            event.pop('hash', None)
            event['hash'] = prev = digest(event)
            if event['kind'] == 'proposal':
                proposal_hashes[old_hash] = prev
        write_json(self.ev/'checkpoints.json',
                   [e['payload']['universal'] for e in self.events if e['kind'] == 'checkpoint'])
        (self.ev/'ledger.jsonl').write_text(''.join(json.dumps(e, sort_keys=True)+'\n' for e in self.events))
        self.report['ledger_root'] = prev
        spec = load_config(self.ev/'spec.toml')
        graph = build_graph(spec, self.events)
        write_json(self.ev/'intent-graph.json', graph)
        (self.ev/'intent-graph.mmd').write_text(graph_mermaid(graph))
        self.report['graph'] = {'nodes':len(graph['nodes']), 'edges':len(graph['edges'])}
        inputs = self.payload('policy_decision')['inputs']
        coverage = requirement_coverage(spec, inputs['checks'], inputs['paths'])
        self.report['requirement_coverage'] = coverage
        write_json(self.ev/'requirement-coverage.json', coverage)
        write_json(self.ev/'report.json', self.report)
        manifest = {p.name:file_hash(p) for p in self.ev.iterdir()}
        write_json(self.out/'manifest.json', manifest)
        write_json(self.out/'anchor.json', {'manifest':file_hash(self.out/'manifest.json'), 'ledger_root':prev})

    def anchored(self):
        anchor, trust = self.out/'anchor.json', self.out/'demo-trust.json'
        return audit_anchored(self.out, anchor, trust,
            expected_anchor_sha256=file_hash(anchor), expected_trust_sha256=file_hash(trust))

    def assert_rejected(self, message):
        self.reseal()
        with self.assertRaisesRegex(ValueError, message):
            self.anchored()

    def test_untampered_pinned_record(self):
        self.assertTrue(self.anchored()['pins_verified'])
        self.assertTrue(verify(self.bundle, self.public)['merged'])

    def test_report_candidate(self):
        self.report['candidate'] = 'f'*40
        self.assert_rejected('semantic evidence mismatch: terminal candidate')

    def test_report_base(self):
        self.report['base'] = 'f'*40
        self.assert_rejected('semantic evidence mismatch: report origin')

    def test_decision_scope(self):
        # Additional path is allowed by spec, low risk, and not observed.
        self.payload('policy_decision')['inputs']['paths'].append('docs/notes.md')
        self.assert_rejected('semantic evidence mismatch: decision checkpoint scope')

    def test_terminal_candidate(self):
        self.payload('merge_result')['candidate'] = 'f'*40
        self.assert_rejected('semantic evidence mismatch: terminal candidate')

    def test_approval_event_disagrees(self):
        self.payload('approvals')['approvals'] = []
        self.assert_rejected('semantic evidence mismatch: approval event')

    def test_report_history(self):
        self.report['history'][0]['head'] = 'f'*40
        self.assert_rejected('semantic evidence mismatch: history')

    def signed_copy(self):
        self.reseal()
        b = Path(tempfile.mkdtemp(dir=self.out.parent))/'signed'
        shutil.copytree(self.bundle, b)
        shutil.copyfile(self.out/'manifest.json', b/'manifest.json')
        shutil.copyfile(self.out/'anchor.json', b/'anchor.json')
        for p in self.ev.iterdir():
            shutil.copyfile(p, b/'evidence'/p.name)
        envelope = json.loads((b/'attestation.json').read_text())
        statement = json.loads(base64.b64decode(envelope['payload']))
        statement['predicate']['candidate'] = self.report['candidate']
        statement['predicate']['ledger_root'] = self.report['ledger_root']
        statement['subject'] = [{'name':name, 'digest':{'sha256':sha}} for name,sha in inventory(b).items()]
        key = serialization.load_pem_private_key(self.private.read_bytes(), password=None)
        payload = canonical(statement)
        envelope['payload'] = base64.b64encode(payload).decode()
        envelope['signatures'] = [{'keyid':key_id(key.public_key()),
                                   'sig':base64.b64encode(key.sign(pae(PAYLOAD_TYPE,payload))).decode()}]
        write_json(b/'attestation.json', envelope)
        return b

    def test_signed_inconsistent_predicate_and_report(self):
        self.report['candidate'] = 'f'*40
        with self.assertRaisesRegex(ValueError, 'semantic evidence mismatch: terminal candidate'):
            verify(self.signed_copy(), self.public)

    def replace_patch(self, transform):
        path = self.ev/'iteration-1.diff'
        original = path.read_bytes()
        changed = transform(original)
        self.assertNotEqual(original, changed)
        path.write_bytes(changed)
        cp = self.payload('checkpoint')
        cp['diff_hash'] = file_hash(path)
        cp['universal']['diff_sha256'] = cp['diff_hash']
        self.payload('convergence')['diff_bytes'] = len(changed)
        write_json(self.ev/'convergence.json',
                   [e['payload'] for e in self.events if e['kind'] == 'convergence'])
        write_json(self.ev/'checkpoints.json',
                   [e['payload']['universal'] for e in self.events if e['kind'] == 'checkpoint'])

    def test_signed_patch_path(self):
        self.replace_patch(lambda p: p.replace(b'app/payments.py', b'app/shadowed.py'))
        with self.assertRaisesRegex(ValueError, 'patch'):
            verify(self.signed_copy(), self.public)

    def test_signed_patch_content(self):
        self.replace_patch(lambda p: p.replace(b'raise ValueError', b'raise TypeError', 1))
        with self.assertRaisesRegex(ValueError, 'patch'):
            verify(self.signed_copy(), self.public)

    def test_signed_extra_patch_path(self):
        self.replace_patch(lambda p: p + p.replace(b'app/payments.py', b'app/shadowed.py'))
        with self.assertRaisesRegex(ValueError, 'patch'):
            verify(self.signed_copy(), self.public)

    def test_signed_missing_challenge_profile(self):
        self.payload('intent_registered').pop('challenge_profile')
        self.events = [e for e in self.events if not e['kind'].startswith('approval_challenge_')]
        with self.assertRaises(ValueError):
            verify(self.signed_copy(), self.public)


    def test_signed_unsupported_patch_structures(self):
        original = (self.ev/'iteration-1.diff').read_bytes()
        for suffix in (b'rename from app/payments.py\n', b'copy to app/other.py\n', b'@@ -1 +1 @@\n'):
            with self.subTest(suffix=suffix):
                self.replace_patch(lambda _: original + suffix)
                with self.assertRaisesRegex(ValueError, 'patch'):
                    verify(self.signed_copy(), self.public)

    def test_signed_current_profile_marker_mismatch(self):
        for field in ('schema_version', 'path_semantics', 'approval_profile', 'challenge_profile'):
            with self.subTest(field=field):
                init = self.payload('intent_registered')
                old = init[field]
                init[field] = 'unsupported'
                bundle = self.signed_copy()
                init[field] = old
                with self.assertRaisesRegex(ValueError, 'current lab profiles'):
                    verify(bundle, self.public)

    def test_signed_incomplete_challenge_events(self):
        self.events = [e for e in self.events if e['kind'] != 'approval_challenge_claimed']
        with self.assertRaisesRegex(ValueError, 'challenge evidence'):
            verify(self.signed_copy(), self.public)

    def test_signed_mixed_approval_envelopes(self):
        old = ROOT/'examples/amgb-v1/bundles/happy/evidence/ledger.jsonl'
        legacy = next(e['payload']['approvals'][0] for e in map(json.loads, old.read_text().splitlines())
                      if e['kind'] == 'approvals')
        self.payload('approvals')['approvals'].append(legacy)
        self.payload('policy_decision')['inputs']['approvals'].append(legacy)
        with self.assertRaisesRegex(ValueError, 'approval profile'):
            verify(self.signed_copy(), self.public)

    def test_historical_verification_is_explicit(self):
        from intent_merge.evidence_profile import HISTORICAL_V1
        corpus = ROOT/'examples/amgb-v1'
        with self.assertRaisesRegex(ValueError, 'current lab profiles'):
            verify(corpus/'bundles/happy', corpus/'signer.pub')
        self.assertTrue(verify(corpus/'bundles/happy', corpus/'signer.pub', profile=HISTORICAL_V1)['merged'])
        with self.assertRaisesRegex(ValueError, 'historical evidence profile'):
            verify(self.bundle, self.public, profile=HISTORICAL_V1)
