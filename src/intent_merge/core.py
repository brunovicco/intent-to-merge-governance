from __future__ import annotations
import hashlib, hmac, json, tomllib
from pathlib import Path
from dataclasses import dataclass
from typing import Protocol
from .path_policy import matches, SEGMENT_V2, LEGACY_V1
from .policy_schema import InvalidConfiguration, invalid_configuration
from .approvals import valid_context, valid_binding, verified_approval_actors
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def file_hash(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def unique_json_members(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON member')
        result[name] = value
    return result


def load_config(path):
    with open(path, 'rb') as f: return tomllib.load(f)


def load_user_config(path):
    """Parse user TOML. Filesystem errors remain operational failures."""
    try:
        return load_config(path)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise InvalidConfiguration('invalid_toml') from None


@dataclass(frozen=True)
class Proposal:
    files: dict[str, str]
    summary: str
    provider: str = "fixture"
    agent: str = "coding-agent"

class CodingAgent(Protocol):
    def propose(self, iteration: int, feedback: dict[str, bool]) -> Proposal: ...

class Ledger:
    def __init__(self): self.events = []
    def add(self, kind, **payload):
        event = {"seq": len(self.events), "kind": kind, "prev": self.events[-1]["hash"] if self.events else "0"*64, "payload": payload}
        event["hash"] = digest(event)
        self.events.append(event)
        return event["hash"]
    def write(self, path):
        Path(path).write_text(''.join(json.dumps(e, sort_keys=True)+'\n' for e in self.events))

def verify_chain(events):
    prev = "0"*64
    for i, e in enumerate(events):
        data = {k:v for k,v in e.items() if k != "hash"}
        if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != digest(data):
            raise ValueError(f"invalid evidence chain at {i}")
        prev = e["hash"]
    if not events: raise ValueError("empty ledger")
    return prev


def approval(actor, binding, keys):
    """Legacy fixture helper retained solely for historical compatibility."""
    payload = {"actor": actor, "binding": binding}
    key = keys[actor]
    if key.startswith("ed25519-private:"):
        signature = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key.split(":",1)[1])).sign(canonical(payload)).hex()
    else:  # Legacy v0.3 HMAC, local audit only.
        signature = hmac.new(bytes.fromhex(key), canonical(payload), hashlib.sha256).hexdigest()
    return {**payload, "signature": signature}


def _legacy_verified_actors(policy, binding, approvals, keys, author, *, historical=False):
    """Historical evidence only; never the fresh approval path."""
    seen = set()
    for a in approvals:
        actor = a.get("actor")
        if actor == author or actor in seen or actor not in policy["approvers"] or actor not in keys or a.get("binding") != binding:
            continue
        key = keys[actor]
        try:
            if key.startswith("ed25519-public:"):
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.split(":",1)[1])).verify(bytes.fromhex(a["signature"]), canonical({"actor":actor,"binding":binding}))
            elif historical and not key.startswith("ed25519-"):
                if not hmac.compare_digest(approval(actor,binding,keys)["signature"],str(a.get("signature",""))): continue
            else:
                continue
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
        seen.add(actor)
    return seen


def verified_actors(policy, binding, approvals, keys, author, *, approval_context=None, _historical_semantics=None):
    if approval_context is None and _historical_semantics in (LEGACY_V1, SEGMENT_V2):
        return _legacy_verified_actors(policy, binding, approvals, keys, author,
                                       historical=_historical_semantics == LEGACY_V1)
    return verified_approval_actors(policy, binding, approvals, keys, author, approval_context)


def evaluate_policy(spec, policy, paths, checks, binding, approvals, keys, *, author, termination, current_head, current_base, eval_binding, approval_context=None, _historical_semantics=None):
    if _historical_semantics != LEGACY_V1:
        invalid = invalid_configuration(spec, policy)
        if invalid is not None:
            return invalid
    actors = verified_actors(policy, binding, approvals, keys, author, approval_context=approval_context, _historical_semantics=_historical_semantics)
    decision = evaluate_decision(spec,policy,paths,checks,binding,actors,termination=termination,current_head=current_head,current_base=current_base,eval_binding=eval_binding, _historical_semantics=_historical_semantics)
    if (_historical_semantics is None or approval_context is not None) and not valid_context(approval_context):
        decision["authorized"] = False
        decision["reasons"].append("invalid_approval_context")
    if (_historical_semantics is None or approval_context is not None) and not valid_binding(binding):
        decision["authorized"] = False
        decision["reasons"].append("invalid_approval_binding")
    return decision


def evaluate_decision(spec, policy, paths, checks, binding, actors, *, termination, current_head, current_base, eval_binding, _historical_semantics=None):
    """Pure deterministic decision; unknown paths/rules/checks fail closed."""
    semantics = _historical_semantics or SEGMENT_V2
    if semantics not in (LEGACY_V1, SEGMENT_V2):
        raise ValueError("unknown path semantics")
    if semantics != LEGACY_V1:
        invalid = invalid_configuration(spec, policy)
        if invalid is not None:
            return invalid
    reasons = []
    if binding.get("path_semantics", LEGACY_V1) != semantics:
        reasons.append("path_semantics_mismatch")
    if termination != "passed": reasons.append("not_converged")
    if not paths: reasons.append("empty_change")
    if any(not matches(p, spec["allowed_paths"], semantics=semantics) for p in paths): reasons.append("outside_spec")
    if any(matches(p, policy["protected_paths"], semantics=semantics) for p in paths): reasons.append("protected_path")
    if current_head != binding["head"]: reasons.append("stale_head")
    if current_base != binding["base"]: reasons.append("stale_base")
    if eval_binding != binding: reasons.append("stale_evaluation")
    if binding.get("spec") != digest(spec) or binding.get("policy") != digest(policy): reasons.append("configuration_mismatch")
    required = set(spec["criteria"]) | set(policy["required_checks"])
    if "requirements" in spec: required |= {"intent_drift", "requirement_coverage", "checkpoint_binding"}
    for check in sorted(required):
        if checks.get(check) is not True: reasons.append("check_failed:"+check)
    roles = set(); rank = {"low":0,"medium":1,"high":2}; risk = "low"
    for p in paths:
        rules = [r for r in policy["risk_rules"] if matches(p, [r["path"]], semantics=semantics)]
        if not rules: reasons.append("unclassified_path:"+p)
        for rule in rules:
            roles.update(rule["required_roles"])
            if rank[rule["level"]] > rank[risk]: risk = rule["level"]
    valid = {policy["approvers"][actor] for actor in actors if actor in policy["approvers"]}
    for role in sorted(roles-valid): reasons.append("missing_approval:"+role)
    return {"authorized": not reasons, "risk": risk, "required_roles": sorted(roles), "verified_roles": sorted(valid), "reasons": reasons}
