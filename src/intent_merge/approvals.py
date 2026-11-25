"""Versioned, challenge-bound approvals for the synthetic local fixture.

The caller supplies a trusted decision context and evaluation time. This module
is stateless: it does not consume challenges or provide external authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROFILE = "itm-local-approval-v2"
AUDIENCE = "itm-pay104-synthetic-lab"
DOMAIN = b"ITM-LOCAL-APPROVAL-V2\0"
MAX_TTL = 300
_CONTEXT_FIELDS = {"profile", "audience", "nonce", "evaluated_at"}
_BODY_FIELDS = {
    "profile", "audience", "nonce", "actor", "role", "author", "key_id",
    "binding", "issued_at", "expires_at",
}


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def _name(value):
    return isinstance(value, str) and 0 < len(value) <= 100 and value.strip() == value


def valid_binding(value):
    return (
        isinstance(value, dict)
        and set(value) == {"head", "base", "spec", "policy", "harness", "path_semantics"}
        and all(_hex(value[k], 40) for k in ("head", "base"))
        and all(_hex(value[k], 64) for k in ("spec", "policy", "harness"))
        and value["path_semantics"] == "segment-v2"
    )


def valid_context(context):
    return (
        isinstance(context, dict)
        and set(context) == _CONTEXT_FIELDS
        and context["profile"] == PROFILE
        and context["audience"] == AUDIENCE
        and _hex(context["nonce"], 32)
        and type(context["evaluated_at"]) is int
        and context["evaluated_at"] >= 0
    )


def decision_context(nonce, evaluated_at):
    context = {
        "profile": PROFILE, "audience": AUDIENCE,
        "nonce": nonce, "evaluated_at": evaluated_at,
    }
    if not valid_context(context):
        raise ValueError("invalid approval context")
    return context


def _message(body):
    return DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _fingerprint(key):
    return hashlib.sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def _valid_lifetime(issued_at, expires_at):
    return (
        type(issued_at) is int and type(expires_at) is int
        and 0 <= issued_at < expires_at <= issued_at + MAX_TTL
    )


def sign_approval(actor, role, author, binding, context, key, *, issued_at, expires_at):
    """Issue a synthetic approval; the private key is not part of the envelope."""
    if not (valid_context(context) and valid_binding(binding)
            and all(_name(x) for x in (actor, role, author))
            and isinstance(key, Ed25519PrivateKey)
            and _valid_lifetime(issued_at, expires_at)):
        raise ValueError("invalid approval inputs")
    body = {
        "profile": PROFILE, "audience": AUDIENCE, "nonce": context["nonce"],
        "actor": actor, "role": role, "author": author,
        "key_id": _fingerprint(key.public_key()), "binding": dict(binding),
        "issued_at": issued_at, "expires_at": expires_at,
    }
    return {**body, "signature": key.sign(_message(body)).hex()}


def _public_key(value):
    prefix = "ed25519-public:"
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    raw = value[len(prefix):]
    if not _hex(raw, 64):
        return None
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))


def current_envelope(envelope):
    return (isinstance(envelope, dict) and set(envelope) == _BODY_FIELDS | {"signature"}
            and envelope["profile"] == PROFILE and envelope["audience"] == AUDIENCE)


def verified_approval_actors(policy, binding, approvals, keys, author, context):
    """Verify only v2 envelopes, against caller-supplied context, never envelope time."""
    if not (valid_context(context) and valid_binding(binding) and _name(author)
            and isinstance(approvals, list) and isinstance(keys, dict)):
        return set()
    public = {actor: _public_key(keys.get(actor)) for actor in policy["approvers"]}
    # Also include the author's registered key, if present, in the collision check.
    if author in keys:
        public[author] = _public_key(keys[author])
    ids = {actor: _fingerprint(key) for actor, key in public.items() if key is not None}
    counts = Counter(ids.values())
    verified = set()
    for envelope in approvals:
        if not current_envelope(envelope):
            continue
        actor = envelope["actor"]
        if not _name(actor) or actor == author or actor not in policy["approvers"]:
            continue
        if actor not in ids or counts[ids[actor]] != 1:
            continue
        if not (
            envelope["nonce"] == context["nonce"] and envelope["author"] == author
            and envelope["role"] == policy["approvers"][actor]
            and envelope["key_id"] == ids[actor] and envelope["binding"] == binding
            and _valid_lifetime(envelope["issued_at"], envelope["expires_at"])
            and envelope["issued_at"] <= context["evaluated_at"] < envelope["expires_at"]
            and _hex(envelope["signature"], 128)
        ):
            continue
        try:
            body = {k: envelope[k] for k in _BODY_FIELDS}
            public[actor].verify(bytes.fromhex(envelope["signature"]), _message(body))
        except (InvalidSignature, ValueError, TypeError):
            continue
        verified.add(actor)
    return verified
