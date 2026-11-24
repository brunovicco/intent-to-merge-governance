"""Provider-neutral checkpoint contract. Imported metadata is never merge authority."""
from __future__ import annotations
import re
from .core import digest

ID = re.compile(r'^[a-zA-Z0-9_.:-]{1,100}$')
TOOL_TYPES = {'read','write','test','shell','search','other'}


def normalize_session(raw):
    """Allowlisted portable export, not a parser for any vendor's private log format.
    Reject free-form identifiers; do not retain prompts, arguments or outputs.
    """
    if not isinstance(raw,dict): raise ValueError('session must be an object')
    if raw.get('schema_version') != '1.0': raise ValueError('unsupported session schema')
    keys = ('provider','runtime','session_id','agent_id')
    if any(not isinstance(raw.get(k),str) or not ID.fullmatch(raw[k]) for k in keys):
        raise ValueError('invalid session identifiers')
    tools=raw.get('tool_types',[]); reqs=raw.get('claimed_requirements',[])
    if not isinstance(tools,list) or not all(isinstance(t,str) and t in TOOL_TYPES for t in tools): raise ValueError('unknown tool category')
    if not isinstance(reqs,list) or not all(isinstance(r,str) and ID.fullmatch(r) for r in reqs): raise ValueError('invalid requirement identifier')
    return {'schema_version':'1.0',**{k:raw[k] for k in keys},'tool_types':sorted(set(tools)),'claimed_requirements':sorted(set(reqs)),'trust':'self_reported'}


def make_checkpoint(intent_id, session, binding, tree, paths, diff_hash, proposal_hash, *, source='agent_proposal'):
    normalized=normalize_session(session)
    return {'schema_version':'1.0','intent_id':intent_id,'session':normalized,'session_digest':digest(normalized),'source':source,'binding':binding,'tree':tree,'paths':sorted(paths),'diff_sha256':diff_hash,'proposal_event_hash':proposal_hash,'trust':{'git_and_diff':'harness_observed','session_identity':'self_reported','independent_attestation':False}}
