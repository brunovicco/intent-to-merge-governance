import copy, json, tempfile, unittest
from pathlib import Path
from intent_merge.intent import drift, validate_spec, requirement_coverage
from intent_merge.checkpoints import normalize_session
from intent_merge.core import load_config, file_hash
from intent_merge.fixtures import BASE, FIXED, DRIFTED, SIGNATURE_DRIFT, IMPORT_DRIFT
from intent_merge.runner import run, audit
ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'examples/spec.toml'; POLICY=ROOT/'examples/policy.toml'
PATH='app/payments.py'

class IntentTests(unittest.TestCase):
    def test_structural_rules(self):
        spec=load_config(SPEC)
        for source,expected in [(FIXED,None),(DRIFTED,'NG01'),(SIGNATURE_DRIFT,'NG02'),(IMPORT_DRIFT,'NG03')]:
            with self.subTest(expected=expected):
                result=drift(spec,{PATH:BASE},{PATH:source},[PATH])
                self.assertEqual(result['passed'],expected is None)
                self.assertEqual([f['id'] for f in result['findings'] if not f['passed']],[] if expected is None else [expected])
    def test_missing_symbol_and_invalid_syntax_fail_closed(self):
        for source in ['def broken(',FIXED.replace('def authorize','def renamed')]:
            self.assertFalse(drift(load_config(SPEC),{PATH:BASE},{PATH:source},[PATH])['passed'])
    def test_unmapped_path(self):
        result=drift(load_config(SPEC),{PATH:BASE},{PATH:FIXED},[PATH,'app/other.py'])
        self.assertFalse(result['passed'])
    def test_incomplete_mapping(self):
        spec=load_config(SPEC); spec['requirements'].pop()
        with self.assertRaises(ValueError): validate_spec(spec)
    def test_coverage_not_agent_claim(self):
        spec=load_config(SPEC)
        self.assertFalse(any(r['verified'] for r in requirement_coverage(spec,{},[PATH])))
    def test_portable_session_privacy_and_validation(self):
        raw={'schema_version':'1.0','provider':'openai','runtime':'codex','session_id':'demo-1','agent_id':'a','tool_types':['write','read','write'],'claimed_requirements':['R01'],'prompt':'not retained','output':'not retained'}
        normalized=normalize_session(raw)
        self.assertNotIn('prompt',normalized); self.assertNotIn('output',normalized); self.assertEqual(normalized['trust'],'self_reported'); self.assertEqual(normalized['tool_types'],['read','write'])
        with self.assertRaises(ValueError): normalize_session({**raw,'tool_types':['arbitrary text']})
        with self.assertRaises(ValueError): normalize_session([])
    def test_drift_with_functional_checks_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'drift'; r=run('intent-drift',out,SPEC,POLICY)
            self.assertTrue(all(x['verified'] for x in r['requirement_coverage']))
            self.assertFalse(r['merged']); self.assertEqual(r['history'][0]['passed'],11)
            graph=json.loads((out/'evidence/intent-graph.json').read_text()); ids={n['id'] for n in graph['nodes']}
            self.assertTrue(all(e['from'] in ids and e['to'] in ids for e in graph['edges']))
            self.assertTrue(any(n['kind']=='finding' and not n['passed'] for n in graph['nodes']))
    def test_graph_reconstruction_detects_inconsistent_derived_artifact(self):
        # Simulates an internally inconsistent export, not resistance to a compromised trust anchor.
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'run'; run('happy',out,SPEC,POLICY)
            graph=out/'evidence/intent-graph.json'; graph.write_text('{}')
            manifest=out/'manifest.json'; m=json.loads(manifest.read_text()); m[graph.name]=file_hash(graph); manifest.write_text(json.dumps(m))
            anchor=out/'anchor.json'; a=json.loads(anchor.read_text()); a['manifest']=file_hash(manifest); anchor.write_text(json.dumps(a))
            with self.assertRaisesRegex(ValueError,'intent graph mismatch'): audit(out,anchor,out/'demo-trust.json')
