"""Semantic reconciliation for the current single-file synthetic runner profile.

This checks recorded observations, not the existence of external Git objects.
Historical v1 replay deliberately retains its original decision semantics.
"""
from .approvals import valid_binding
from .core import digest
from .evidence_patch import PAYMENT_PATH, candidate_tree, rejected_paths, verify_patch


def _require(condition, detail):
    if not condition:
        raise ValueError('semantic evidence mismatch: ' + detail)


def verify_current_evidence(ev, spec, policy, events, report):
    """Reconcile the current lab's ledger, candidate scope and report."""
    def unique(kind):
        selected = [e for e in events if e['kind'] == kind]
        _require(len(selected) == 1, kind + ' inventory')
        return selected[0]

    initial = unique('intent_registered')
    termination = unique('termination')
    approvals = unique('approvals')
    decision = unique('policy_decision')
    terminal = unique('merge_result')
    _require(initial == events[0] and terminal == events[-1]
             and termination['seq'] < approvals['seq'] < decision['seq'] < terminal['seq'],
             'event order')
    init, inputs = initial['payload'], decision['payload']['inputs']
    result = terminal['payload']
    binding = inputs['binding']
    _require(valid_binding(binding), 'decision binding')
    for key in ('base', 'spec', 'policy', 'harness', 'path_semantics'):
        _require(binding[key] == init[key], 'decision ' + key)
    _require(inputs['current_head'] == binding['head'] == result['candidate'] == report['candidate'],
             'terminal candidate')
    _require(report['base'] == init['base'] and report['scenario'] == init['scenario'], 'report origin')
    _require(result['main'] == (inputs['current_head'] if result['merged'] else inputs['current_base']),
             'terminal target')
    _require(inputs['termination'] == termination['payload']['reason'] == report['termination'],
             'termination')
    _require(approvals['payload'] == {'approvals': inputs['approvals'], 'simulated': True},
             'approval event')

    checkpoints = [e for e in events if e['kind'] == 'checkpoint']
    evaluations = [e for e in events if e['kind'] == 'evaluation']
    proposals = [e for e in events if e['kind'] == 'proposal']
    proposal_map = {e['hash']: e for e in proposals}
    _require(len(checkpoints) == len(evaluations), 'checkpoint inventory')
    history = []
    used_proposals = set()
    expected_artifacts = {name for i in range(1, len(checkpoints) + 1)
                          for name in (f'candidate-{i}.py', f'iteration-{i}.diff')}
    recorded_artifacts = {p.name for p in ev.iterdir()
                          if p.name.startswith(('candidate-', 'iteration-'))}
    _require(recorded_artifacts == expected_artifacts, 'checkpoint artifact inventory')
    baseline = (ev / 'baseline.py').read_bytes()
    for i, (checkpoint, evaluation) in enumerate(zip(checkpoints, evaluations), 1):
        cp, evaluation_data = checkpoint['payload'], evaluation['payload']
        cp_binding = cp['binding']
        _require(valid_binding(cp_binding) and all(cp_binding[k] == init[k] for k in
                 ('base', 'spec', 'policy', 'harness', 'path_semantics')), 'checkpoint binding')
        prior_evaluation = evaluations[i-2]['seq'] if i > 1 else initial['seq']
        _require(cp['iteration'] == evaluation_data['iteration'] == i
                 and prior_evaluation < checkpoint['seq'] < evaluation['seq'] < decision['seq'], 'checkpoint order')
        _require(cp['author'] == inputs['author'], 'candidate author')
        proposal = proposal_map.get(cp['universal']['proposal_event_hash'])
        _require(proposal is not None and proposal['seq'] < checkpoint['seq']
                 and proposal['payload']['agent'] == cp['author'], 'proposal identity')
        # PAY-104 records only this file. Do not silently certify unobserved files.
        _require(set(proposal['payload']['files']) == {PAYMENT_PATH}, 'unsupported candidate inventory')
        candidate = (ev / f'candidate-{i}.py').read_bytes()
        _require(digest(candidate.decode('utf-8')) == proposal['payload']['files'][PAYMENT_PATH],
                 'proposal content')
        verify_patch((ev / f'iteration-{i}.diff').read_bytes(), baseline, candidate)
        _require(cp['tree'] == candidate_tree(candidate), 'checkpoint tree')
        expected_paths = [] if candidate == baseline else [PAYMENT_PATH]
        _require(cp['paths'] == expected_paths, 'checkpoint paths')
        checks = evaluation_data['checks']
        scope = not rejected_paths(expected_paths, spec, policy)
        _require(checks.get('scope') is scope and checks.get('trusted_harness') is True,
                 'scope or harness observation')
        score = sum(v is True for v in checks.values())
        _require(evaluation_data['score'] == score, 'evaluation score')
        source = cp['universal']['source']
        if source == 'agent_proposal':
            _require(prior_evaluation < proposal['seq'] < checkpoint['seq'] < termination['seq'] and proposal['payload']['iteration'] == i,
                     'proposal iteration')
            used_proposals.add(proposal['hash'])
            history.append({'iteration': i, 'passed': score, 'total': len(checks), 'head': cp_binding['head']})
        else:
            _require(source == 'harness_refresh' and i == len(checkpoints)
                     and i > 1 and termination['seq'] < checkpoint['seq'] < approvals['seq'], 'refresh order')
            previous = checkpoints[i-2]['payload']
            _require(previous['tree'] == cp['tree'] and previous['paths'] == cp['paths']
                     and previous['universal']['proposal_event_hash'] == proposal['hash']
                     and previous['binding']['head'] != cp_binding['head'], 'refresh candidate')
    _require(report['history'] == history and termination['payload']['iterations'] == len(history),
             'history')
    if inputs['termination'] == 'scope_rejected':
        rejection = unique('proposal_rejected')
        _require(bool(proposals) and proposals[-1]['seq'] < rejection['seq'] < termination['seq'],
                 'rejected proposal order')
        paths = sorted(proposals[-1]['payload']['files'])
        disallowed = rejected_paths(paths, spec, policy)
        _require(proposals[-1]['payload']['iteration'] == len(history) + 1
                 and proposals[-1]['payload']['agent'] == inputs['author']
                 and inputs['paths'] == paths and bool(disallowed)
                 and sorted(rejection['payload']['paths']) == disallowed
                 and inputs['checks'] == {'scope': False, 'trusted_harness': True}, 'rejected proposal scope')
        used_proposals.add(proposals[-1]['hash'])
    else:
        _require(not any(e['kind'] == 'proposal_rejected' for e in events), 'unexpected scope rejection')
        _require(bool(checkpoints), 'missing candidate checkpoint')
        cp, evaluation = checkpoints[-1]['payload'], evaluations[-1]['payload']
        _require(cp['binding'] == binding and cp['paths'] == inputs['paths']
                 and evaluation['checks'] == inputs['checks'], 'decision checkpoint scope or checks')
    _require(used_proposals == proposal_map.keys(), 'proposal inventory')
    if checkpoints:
        _require(checkpoints[-1]['payload']['binding'] == binding, 'latest candidate')
        # Stale-evaluation scenarios are recorded denials, not valid evidence.
        if inputs['eval_binding'] != binding:
            _require(not decision['payload']['decision']['authorized']
                     and 'stale_evaluation' in decision['payload']['decision']['reasons'], 'stale evaluation')
    else:
        _require(binding['head'] == init['base'] and inputs['eval_binding'] is None, 'initial candidate')
