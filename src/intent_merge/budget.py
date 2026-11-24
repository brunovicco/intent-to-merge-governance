"""Replayable convergence admission controller for observed, not billed, usage.
Does not enforce provider-side hard token caps or drive real agents.
"""
from dataclasses import dataclass
from .operational import require

def normalized(provider,t):
    """Provider-specific token fields; never silently substitute missing usage."""
    require(provider in ('claude','codex'),'unknown provider')
    fields=('input_tokens','output_tokens','cache_creation_input_tokens','cache_read_input_tokens') if provider=='claude' else ('input_tokens','output_tokens','cached_input_tokens')
    if not isinstance(t,dict) or any(type(t.get(f)) is not int or t[f]<0 for f in fields):return None
    if provider=='claude':return {'input_total':t['input_tokens']+t['cache_creation_input_tokens']+t['cache_read_input_tokens'],'uncached':t['input_tokens'],'cache_write':t['cache_creation_input_tokens'],'cache_read':t['cache_read_input_tokens'],'output':t['output_tokens'],'trust':'self_reported'}
    require(t['cached_input_tokens']<=t['input_tokens'],'cached input exceeds total');return {'input_total':t['input_tokens'],'uncached':t['input_tokens']-t['cached_input_tokens'],'cache_write':None,'cache_read':t['cached_input_tokens'],'output':t['output_tokens'],'trust':'self_reported'}

@dataclass(frozen=True)
class Limits:
    attempts:int=3
    observed_tokens:int=250000
    elapsed_ms:int=120000
    def __post_init__(self):require(all(type(x) is int and x>0 for x in (self.attempts,self.observed_tokens,self.elapsed_ms)),'invalid limits')

class BudgetController:
    def __init__(self,limits):self.limits=limits;self.history=[];self.tokens=0;self.elapsed=0;self.seen=set();self.state='READY';self.pending=False
    def admit(self):
        if self.state!='READY' or self.pending:return False
        if len(self.history)>=self.limits.attempts or self.tokens>=self.limits.observed_tokens or self.elapsed>=self.limits.elapsed_ms:self.state='STOP_BUDGET';return False
        self.pending=True;return True
    def record(self,*,provider,telemetry,elapsed_ms,tree,passed,scope_valid):
        require(self.pending and self.state=='READY','attempt not admitted');require(type(elapsed_ms) is int and elapsed_ms>=0 and isinstance(tree,str) and tree and type(passed) is bool and type(scope_valid) is bool,'invalid observation')
        usage=normalized(provider,telemetry);self.pending=False;self.elapsed+=elapsed_ms
        if usage is not None:self.tokens+=usage['input_total']+usage['output']
        if not scope_valid:self.state='STOP_SCOPE'
        elif usage is None:self.state='STOP_UNKNOWN_USAGE'
        elif self.tokens>self.limits.observed_tokens or self.elapsed>self.limits.elapsed_ms:self.state='STOP_BUDGET'
        elif passed:self.state='PASSED'
        elif tree in self.seen:self.state='STOP_REPEAT'
        elif len(self.history)+1>=self.limits.attempts or self.tokens>=self.limits.observed_tokens or self.elapsed>=self.limits.elapsed_ms:self.state='STOP_BUDGET'
        self.seen.add(tree);r={'attempt':len(self.history)+1,'tree':tree,'usage':usage,'cumulative_observed_tokens':self.tokens,'cumulative_elapsed_ms':self.elapsed,'state':self.state,'merge_authority':False};self.history.append(r);return r
