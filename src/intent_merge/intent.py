"""Deterministic intent contracts, structural drift and trace graph.

AST checks are narrow structural invariants, not proof of semantic equivalence.
"""
from __future__ import annotations
import ast
from .core import digest, matches
from .path_policy import SEGMENT_V2, validate_patterns
from .policy_schema import names, require
from .checkpoints import ID


def validate_spec(spec, *, semantics=SEGMENT_V2):
    fields = {'id', 'intent', 'criteria', 'allowed_paths', 'requirements', 'non_goals'}
    require(isinstance(spec, dict) and set(spec) == fields, 'spec_fields')
    require(isinstance(spec['id'], str) and ID.fullmatch(spec['id']), 'spec_id')
    require(isinstance(spec['intent'], str) and spec['intent'].strip(), 'spec_intent')
    criteria, allowed = spec['criteria'], spec['allowed_paths']
    names(criteria, 'criteria', nonempty=True)
    if semantics == SEGMENT_V2:
        validate_patterns(allowed, nonempty=True)
    else:
        names(allowed, 'allowed_paths', nonempty=True)

    requirements, rules = spec['requirements'], spec['non_goals']
    require(isinstance(requirements, list) and requirements, 'requirements')
    require(isinstance(rules, list) and rules, 'non_goals')
    for requirement in requirements:
        require(isinstance(requirement, dict)
                and set(requirement) == {'id', 'description', 'criteria', 'paths'},
                'requirement_fields')
        require(isinstance(requirement['description'], str) and requirement['description'].strip(),
                'requirement_description')
        names(requirement['criteria'], 'requirement_criteria', nonempty=True)
        paths = requirement['paths']
        if semantics == SEGMENT_V2:
            validate_patterns(paths, nonempty=True)
        else:
            names(paths, 'requirement_paths', nonempty=True)
        require(all(matches(path, allowed, semantics=semantics) for path in paths),
                'requirement_path_outside_spec_scope')
    fields = {'id', 'description', 'kind', 'path'}
    for rule in rules:
        require(isinstance(rule, dict) and fields <= set(rule) <= fields | {'symbol'},
                'non_goal_fields')
        require(isinstance(rule['description'], str) and rule['description'].strip(),
                'non_goal_description')
        kind = rule['kind']
        require(kind in ('preserve_symbol', 'preserve_signature', 'no_new_imports'),
                'non_goal_kind')
        require(isinstance(rule['path'], str) and matches(rule['path'], allowed, semantics=semantics),
                'non_goal_path_outside_spec_scope')
        if kind != 'no_new_imports' or 'symbol' in rule:
            require(isinstance(rule.get('symbol'), str) and rule['symbol'].isidentifier(),
                    'non_goal_symbol')
    ids = [r['id'] for r in (*requirements, *rules)]
    require(all(isinstance(i, str) and ID.fullmatch(i) for i in ids)
            and len(ids) == len(set(ids)), 'duplicate_or_invalid_contract_ids')
    require({c for r in requirements for c in r['criteria']} == set(criteria),
            'requirement_criteria_coverage')


def _symbol(tree, name):
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('missing or ambiguous symbol: '+name)
    return nodes[0]


def _imports(tree):
    return {ast.dump(n, include_attributes=False) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))}


def drift(spec, baseline, candidate, paths, *, semantics=SEGMENT_V2):
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
        if not any(matches(path, r['paths'], semantics=semantics) for r in spec['requirements']):
            findings.append({'id':'unmapped:'+path,'kind':'unmapped_path','path':path,'passed':False,'detail':'no requirement maps to path'})
    return {'passed':all(f['passed'] for f in findings),'findings':findings,'method':'python_ast_structural_v1'}


def requirement_coverage(spec, checks, paths, *, semantics=SEGMENT_V2):
    return [{'id':r['id'], 'description':r['description'], 'criteria':{c:checks.get(c) is True for c in r['criteria']}, 'changed_paths':sorted(p for p in paths if matches(p,r['paths'], semantics=semantics)), 'verified':all(checks.get(c) is True for c in r['criteria'])} for r in spec['requirements']]


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
