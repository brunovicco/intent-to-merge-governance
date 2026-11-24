"""Conservative metadata projection from native CLI terminal events.

No token pricing estimates, no raw text, no tool payloads. Self-reported usage
is not billing evidence. Unknown schemas or ambiguous terminal totals are null.
"""
from __future__ import annotations
import math, re


def project(provider, events):
    terminals=[e for e in events if e.get('type')==('result' if provider=='claude' else 'turn.completed')]
    empty={'input_tokens':None,'output_tokens':None,'cached_input_tokens':None,'cache_creation_input_tokens':None,'cache_read_input_tokens':None,'reported_cost_usd':None,'models':[],'usage_source':None,'trust':'self_reported'}
    if len(terminals)!=1:return empty
    event=terminals[0];usage=event.get('usage');usage=usage if isinstance(usage,dict) else {}
    keys=('input_tokens','output_tokens','cache_creation_input_tokens','cache_read_input_tokens') if provider=='claude' else ('input_tokens','output_tokens','cached_input_tokens')
    for k in keys:
        v=usage.get(k)
        if type(v) is int and 0<=v<=10**12:empty[k]=v
    if any(empty[k] is not None for k in keys):empty['usage_source']='claude.result.usage' if provider=='claude' else 'codex.turn.completed.usage'
    if provider=='claude':
        cost=event.get('total_cost_usd')
        if type(cost) in (int,float) and 0<=cost<=10**6 and math.isfinite(cost):empty['reported_cost_usd']=cost
        model_usage=event.get('modelUsage')
        if isinstance(model_usage,dict):empty['models']=sorted(k for k in model_usage if isinstance(k,str) and re.fullmatch(r'claude-[A-Za-z0-9._-]{1,100}',k))[:20]
    # Never infer a model or cost from the executable name. Cache token semantics
    # differ between providers; fields are retained separately, never summed.
    return empty
