"""Strict configuration checks for the current local decision profile."""
from .path_policy import validate_patterns, validate_pattern


def require(condition, message):
    if not condition:
        raise ValueError(message)


def names(value, field, *, nonempty=False):
    require(isinstance(value, list) and (not nonempty or bool(value))
            and all(isinstance(x, str) and bool(x.strip()) for x in value), field)
    require(len(value) == len(set(value)), field)


def validate_local_policy(policy):
    fields = {'version', 'max_iterations', 'max_no_progress', 'required_checks',
              'protected_paths', 'approvers', 'risk_rules'}
    require(isinstance(policy, dict) and fields <= set(policy)
            and set(policy) <= fields | {'convergence'}, 'policy_fields')
    require(type(policy['version']) is int and policy['version'] == 1, 'policy_version')
    for field in ('max_iterations', 'max_no_progress'):
        require(type(policy[field]) is int and policy[field] > 0, field)
    names(policy['required_checks'], 'required_checks', nonempty=True)
    validate_patterns(policy['protected_paths'])
    approvers = policy['approvers']
    require(isinstance(approvers, dict) and all(isinstance(k, str) and k.strip()
            and isinstance(v, str) and v.strip() for k, v in approvers.items()), 'approvers')
    rules = policy['risk_rules']
    require(isinstance(rules, list) and bool(rules), 'risk_rules')
    for rule in rules:
        require(isinstance(rule, dict) and set(rule) == {'path', 'level', 'required_roles'}, 'risk_rule_fields')
        validate_pattern(rule['path'])
        require(rule['level'] in ('low', 'medium', 'high'), 'risk_level')
        names(rule['required_roles'], 'required_roles')
        require(set(rule['required_roles']) <= set(approvers.values()), 'unknown_required_role')
    limits = policy.get('convergence', {})
    require(isinstance(limits, dict) and set(limits) <= {'max_cases', 'max_diff_bytes', 'max_reopened'}, 'convergence_fields')
    for field, value in limits.items():
        require(type(value) is int and value >= (0 if field == 'max_reopened' else 1), field)


def validate_scope_spec(spec):
    require(isinstance(spec, dict), 'spec_fields')
    validate_patterns(spec.get('allowed_paths'), nonempty=True)
    names(spec.get('criteria'), 'criteria', nonempty=True)


def invalid_configuration(spec, policy):
    """Return a stable denial without interpreting a malformed configuration."""
    try:
        validate_local_policy(policy)
        validate_scope_spec(spec)
    except (ValueError, TypeError) as exc:
        return {'authorized': False, 'risk': 'unknown', 'required_roles': [],
                'verified_roles': [], 'reasons': ['invalid_configuration:' + str(exc)],
                'status': 'INVALID_CONFIGURATION'}
    return None
