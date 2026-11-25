"""Trusted verification modes for PAY-104 evidence."""
from .approval_registry import PROFILE as REGISTRY_PROFILE
from .approvals import PROFILE as APPROVAL_PROFILE, current_envelope, valid_binding, valid_context
from .path_policy import LEGACY_V1, SEGMENT_V2

CURRENT = 'current'
HISTORICAL_V1 = 'historical-v1'
PROFILES = (CURRENT, HISTORICAL_V1)
CURRENT_MARKERS = {
    'schema_version': '0.4',
    'path_semantics': SEGMENT_V2,
    'approval_profile': APPROVAL_PROFILE,
    'challenge_profile': REGISTRY_PROFILE,
}
CHALLENGE_EVENTS = {'approval_challenge_issued', 'approval_challenge_claimed'}


def validate_profile(profile, events, inputs):
    init = events[0]['payload']
    if events[0]['kind'] != 'intent_registered':
        raise ValueError('invalid initial ledger event')
    approval_events = [e['payload'].get('approvals') for e in events if e['kind'] == 'approvals']
    approvals = inputs['approvals']
    if not isinstance(approvals, list) or approval_events != [approvals]:
        raise ValueError('semantic evidence mismatch: approval event')
    challenges = [e['kind'] for e in events if e['kind'].startswith('approval_challenge_')]
    if profile == CURRENT:
        if any(init.get(k) != v for k, v in CURRENT_MARKERS.items()):
            raise ValueError('audit requires current lab profiles and schema')
        if sorted(challenges) != sorted(CHALLENGE_EVENTS):
            raise ValueError('incomplete or unsupported approval challenge evidence')
        if not valid_context(inputs.get('approval_context')):
            raise ValueError('invalid recorded approval context')
        if not all(current_envelope(a) and valid_binding(a['binding']) for a in approvals):
            raise ValueError('mixed or unsupported approval profile')
        return SEGMENT_V2
    if profile == HISTORICAL_V1:
        bindings = [inputs['binding'], inputs['eval_binding'],
                    *(e['payload']['binding'] for e in events if e['kind'] == 'checkpoint')]
        if (init.get('schema_version') != '0.4'
                or init.get('path_semantics', LEGACY_V1) != LEGACY_V1
                or {'approval_profile', 'challenge_profile'} & init.keys()
                or challenges or 'approval_context' in inputs
                or any(b is not None and (not isinstance(b, dict)
                       or b.get('path_semantics', LEGACY_V1) != LEGACY_V1) for b in bindings)
                or any(not isinstance(a, dict) or set(a) != {'actor', 'binding', 'signature'}
                       for a in approvals)):
            raise ValueError('mixed or unsupported historical evidence profile')
        return LEGACY_V1
    raise ValueError('unsupported evidence verification profile')
