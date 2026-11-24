"""Deterministic intent contracts, structural drift and trace graph.

AST checks are narrow structural invariants, not proof of semantic equivalence.
"""
from __future__ import annotations
import ast
from .core import digest, matches


def validate_spec(spec):
    criteria = spec['criteria']
    if not criteria or len(criteria) != len(set(criteria)):
        raise ValueError('criteria must be nonempty and unique')
    requirements = spec.get('requirements', [])
    ids = [r['id'] for r in requirements]
    mapped = [c for r in requirements for c in r['criteria']]
    if not ids or len(ids) != len(set(ids)) or set(mapped) != set(criteria):
        raise ValueError('requirements must uniquely identify and cover all acceptance criteria')
    for r in requirements:
        if not r['criteria'] or not r['paths'] or any(not matches(p, spec['allowed_paths']) for p in r['paths']):
            raise ValueError('requirement needs criteria and authorized paths')
    rules = spec.get('non_goals', [])
    if not rules or len({r['id'] for r in rules}) != len(rules):
        raise ValueError('non-goals must be nonempty and uniquely identified')
    for r in rules:
        if r['kind'] not in {'preserve_symbol', 'preserve_signature', 'no_new_imports'}:
            raise ValueError('unsupported non-goal: '+r['kind'])
        if not matches(r['path'], spec['allowed_paths']):
            raise ValueError('non-goal must target authorized path')
        if r['kind'] != 'no_new_imports' and not r.get('symbol'):
            raise ValueError('non-goal requires symbol')


def _symbol(tree, name):
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('missing or ambiguous symbol: '+name)
    return nodes[0]


def _imports(tree):
    return {ast.dump(n, include_attributes=False) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))}


def drift(spec, baseline, candidate, paths):
    findings = []
    for rule in spec['non_goals']:
        path, kind = rule['path'], rule['kind']
        try:
            old, new = ast.parse(baseline[path]), ast.parse(candidate[path])
            if kind == 'no_new_imports':
                passed = _imports(new) <= _imports(old)
            else:
                a, b = _symbol(old, rule['symbol']), _symbol(new, rule['symbol'])
                if kind == 'preserve_symbol':
                    passed = ast.dump(a) == ast.dump(b)
                else:
                    if not isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef)) or not isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        raise ValueError('signature rule requires function')
                    signature = lambda n: (type(n).__name__, ast.dump(n.args), ast.dump(n.returns) if n.returns else None, [ast.dump(d) for d in n.decorator_list])
                    passed = signature(a) == signature(b)
            detail = 'invariant preserved' if passed else 'structural invariant violated'
        except (KeyError, SyntaxError, ValueError) as exc:
            passed, detail = False, str(exc)
        findings.append({'id':rule['id'], 'kind':kind, 'path':path, 'passed':passed, 'detail':detail})
    for path in sorted(paths):
        if not any(matches(path, r['paths']) for r in spec['requirements']):
            findings.append({'id':'unmapped:'+path,'kind':'unmapped_path','path':path,'passed':False,'detail':'no requirement maps to path'})
    return {'passed':all(f['passed'] for f in findings),'findings':findings,'method':'python_ast_structural_v1'}


def requirement_coverage(spec, checks, paths):
    return [{'id':r['id'], 'description':r['description'], 'criteria':{c:checks.get(c) is True for c in r['criteria']}, 'changed_paths':sorted(p for p in paths if matches(p,r['paths'])), 'verified':all(checks.get(c) is True for c in r['criteria'])} for r in spec['requirements']]


def build_graph(spec, events):
    """Reconstruct a typed graph using only registered requirements and observed ledger events."""
    nodes, edges = {}, []
    def node(id, kind, **data): nodes[id] = {'id':id,'kind':kind,**data}; return id
    def edge(a,b,kind): edges.append({'from':a,'to':b,'kind':kind})
    root = node('intent:'+spec['id'],'intent',description=spec['intent'],digest=digest(spec))
    for r in spec['requirements']:
        rid = node('req:'+r['id'],'requirement',description=r['description']); edge(root,rid,'requires')
        for c in r['criteria']:
            cid = node('criterion:'+c,'criterion'); edge(rid,cid,'acceptance')
        for p in r['paths']:
            pid = node('path:'+p,'path'); edge(rid,pid,'maps_to')
    for r in spec['non_goals']:
        nid = node('non-goal:'+r['id'],'non_goal',description=r['description']); edge(root,nid,'constrains')
    checkpoints = {}; evaluations = {}; drifts = {}; final = None
    for e in events:
        p = e['payload']; kind = e['kind']
        if kind == 'checkpoint':
            head = p['binding']['head']; cid = node('commit:'+head,'commit',sha=head); cp = node('checkpoint:'+head,'checkpoint',digest=digest(p['universal'])); checkpoints[head]=cp; edge(cp,cid,'observes'); edge(root,cp,'has_checkpoint')
            for path in p['paths']:
                pid=node('path:'+path,'path'); edge(cid,pid,'changes')
        elif kind == 'intent_drift':
            head=p['binding']['head']; did=node('drift:'+head,'drift',passed=p['result']['passed']); drifts[head]=did; edge(checkpoints[head],did,'checked_by')
            for f in p['result']['findings']:
                fid=node('finding:'+head+':'+f['id'],'finding',passed=f['passed'],detail=f['detail']); edge(did,fid,'reports')
                if 'non-goal:'+f['id'] in nodes: edge(fid,'non-goal:'+f['id'],'checks')
        elif kind == 'evaluation':
            head=p['binding']['head']; eid=node('eval:'+head,'evaluation',checks=p['checks']); evaluations[head]=eid
            if head in checkpoints: edge(checkpoints[head],eid,'evaluated_by')
            for c in spec['criteria']:
                oid=node('outcome:'+head+':'+c,'check_result',passed=p['checks'].get(c) is True); edge(eid,oid,'produces'); edge(oid,'criterion:'+c,'checks')
        elif kind == 'policy_decision':
            head=p['inputs']['binding']['head']; final=node('decision:'+head,'decision',authorized=p['decision']['authorized'],reasons=p['decision']['reasons']); edge(root,final,'subject_to')
            for mapping in (checkpoints,evaluations,drifts):
                if head in mapping: edge(mapping[head],final,'evidence_for')
            for a in p['inputs']['approvals']:
                aid=node('approval:'+digest(a),'approval',actor=a['actor'],head=a['binding']['head']); edge(aid,final,'considered_by')
        elif kind == 'merge_result':
            mid=node('merge:'+p['candidate'],'merge_result',merged=p['merged'],main=p['main']); edge(final,mid,'determines')
    return {'schema_version':'1.0','intent_id':spec['id'],'nodes':list(nodes.values()),'edges':edges}


def graph_mermaid(graph):
    ids = {n['id']:f'N{i}' for i,n in enumerate(graph['nodes'])}
    lines=['flowchart TD']
    for n in graph['nodes']:
        label=n['kind']+': '+n['id'].split(':',1)[1][:45]; label=label.replace('"','').replace('<','').replace('>','')
        lines.append(f'    {ids[n["id"]]}["{label}"]')
    for e in graph['edges']:
        lines.append(f'    {ids[e["from"]]} -->|{e["kind"]}| {ids[e["to"]]}')
    return '\n'.join(lines)+'\n'
