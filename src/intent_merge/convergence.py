"""Pure replayable convergence state machine; no LLM scores or wall clock decisions."""
from __future__ import annotations

class Governor:
    def __init__(self, policy):
        self.policy=policy; self.history=[]; self.seen={}; self.best=None; self.stagnant=0; self.regressions=0; self.cases=0
    def observe(self, *, iteration, tree, checks, required, paths, case_count, diff_bytes, execution_ok=True):
        failed=sorted(k for k in required if checks.get(k) is not True)
        previous=set(self.history[-1]['failed']) if self.history else None
        resolved=sorted(previous-set(failed)) if previous is not None else []
        reopened=sorted(set(failed)-previous) if previous is not None else []
        self.regressions+=len(reopened); self.cases+=case_count
        if self.best is None or set(failed)<self.best:
            self.best=set(failed); self.stagnant=0
        else: self.stagnant+=1
        repeat=self.seen.get(tree); self.seen[tree]=iteration
        limits=self.policy.get('convergence',{})
        if not checks.get('intent_drift'): action='intent_drift'
        elif not execution_ok: action='execution_failed'
        elif self.cases>limits.get('max_cases',1000) or diff_bytes>limits.get('max_diff_bytes',100000): action='budget_exceeded'
        elif self.regressions>limits.get('max_reopened',2): action='regression_budget'
        elif not failed and paths: action='passed'
        elif repeat is not None: action='repeated_tree'
        elif self.stagnant>=self.policy['max_no_progress']: action='no_progress'
        elif iteration>=self.policy['max_iterations']: action='iteration_budget'
        else: action='continue'
        row={'iteration':iteration,'tree':tree,'failed':failed,'resolved':resolved,'reopened':reopened,'repeated_from':repeat,'cycle_length':iteration-repeat if repeat is not None else None,'no_progress':self.stagnant,'cumulative_cases':self.cases,'diff_bytes':diff_bytes,'regressions':self.regressions,'action':action}
        self.history.append(row); return row
