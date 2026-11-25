"""Non-authorizing audit profiles. Pins are supplied by a trusted caller.

The anchored mode authenticates bytes against pre-established commitments. It
never establishes who controls a key, current approval status or merge authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
from pathlib import Path

from .core import unique_json_members
from .evidence_profile import CURRENT
from .runner import audit

SYNTHETIC = "synthetic-historical-v1"
ANCHORED = "externally-pinned-historical-v1"
MAX_METADATA = 1024 * 1024
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 512


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _read(path, limit):
    path = Path(path)
    _require(not path.is_symlink() and path.is_file(), "expected regular file")
    with path.open("rb") as file:
        data = file.read(limit + 1)
    _require(len(data) <= limit, "audit artifact too large")
    return data


def _decode(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_json_members)


def _pinned(path, expected):
    _require(_hex(expected), "expected external SHA-256 pin required")
    data = _read(path, MAX_METADATA)
    _require(_sha(data) == expected, "external pin mismatch")
    return data


def _public_trust(keys):
    _require(isinstance(keys, dict) and 0 < len(keys) <= 256, "invalid trust store")
    prefix = "ed25519-public:"
    for actor, key in keys.items():
        _require(isinstance(actor, str) and 0 < len(actor) <= 100
                 and actor.strip() == actor, "invalid trust identity")
        _require(isinstance(key, str) and key.startswith(prefix)
                 and _hex(key[len(prefix):]), "public Ed25519 keys required")
    _require(len(set(keys.values())) == len(keys), "duplicate approval key")


def _historical_result(result, profile):
    # The legacy 'merged' field describes the recorded local fixture only.
    return {**result, "trust_profile": profile, "current_authorization": False,
            "organizational_authority_verified": False, "merge_authority": False,
            "production_ready": False}


def audit_synthetic(out, anchor_path, trust_path, *, profile=CURRENT):
    """Compatibility mode; trust is not independently established."""
    return _historical_result(audit(out, anchor_path, trust_path, profile=profile), SYNTHETIC)


def audit_anchored(out, anchor_path, trust_path, *, expected_anchor_sha256,
                   expected_trust_sha256):
    """Replay a frozen, pin-bound snapshot of the current synthetic profile.

    Pin acquisition and custody are outside this function. No live candidate is
    executed, and a successful audit cannot grant current authorization.
    """
    anchor_bytes = _pinned(anchor_path, expected_anchor_sha256)
    trust_bytes = _pinned(trust_path, expected_trust_sha256)
    anchor = _decode(anchor_bytes)
    _require(isinstance(anchor, dict) and set(anchor) == {"manifest", "ledger_root"}
             and all(_hex(v) for v in anchor.values()), "invalid anchor schema")
    _public_trust(_decode(trust_bytes))

    source = Path(out)
    ev = source / "evidence"
    _require(not source.is_symlink() and source.is_dir() and not ev.is_symlink()
             and ev.is_dir(), "invalid audit directory")
    manifest_bytes = _read(source / "manifest.json", MAX_METADATA)
    _require(_sha(manifest_bytes) == anchor["manifest"], "manifest anchor mismatch")
    manifest = _decode(manifest_bytes)
    _require(isinstance(manifest, dict) and 0 < len(manifest) <= MAX_FILES,
             "invalid manifest inventory")
    for name, digest in manifest.items():
        _require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                 and name not in {".", ".."} and _hex(digest), "invalid manifest entry")
    _require({p.name for p in ev.iterdir()} == set(manifest), "artifact inventory mismatch")

    # The exact checked bytes, not the caller's mutable files, reach the auditor.
    # This is a private temporary copy, not a hostile same-user security boundary.
    with tempfile.TemporaryDirectory(prefix="itm-anchored-audit-") as tmp:
        stage = Path(tmp)
        staged_ev = stage / "evidence"
        staged_ev.mkdir()
        total = 0
        for name, digest in manifest.items():
            data = _read(ev / name, MAX_ARTIFACT)
            total += len(data)
            _require(total <= MAX_TOTAL, "audit snapshot too large")
            _require(_sha(data) == digest, "artifact integrity mismatch")
            (staged_ev / name).write_bytes(data)
        (stage / "manifest.json").write_bytes(manifest_bytes)
        (stage / "anchor.json").write_bytes(anchor_bytes)
        (stage / "approval-trust.json").write_bytes(trust_bytes)
        ledger = (staged_ev / "ledger.jsonl").read_bytes().splitlines()
        _require(bool(ledger), "empty ledger")
        first = _decode(ledger[0])
        _require(isinstance(first, dict) and first.get("kind") == "intent_registered"
                 and isinstance(first.get("payload"), dict), "invalid initial ledger event")
        result = audit(stage, stage / "anchor.json", stage / "approval-trust.json")
    return {**_historical_result(result, ANCHORED), "pins_verified": True,
            "anchor_sha256": expected_anchor_sha256,
            "trust_sha256": expected_trust_sha256,
            "pin_provenance": "caller_supplied_not_independently_attested"}
