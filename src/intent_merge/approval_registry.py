"""Single-use approval challenges for the synthetic local decision path.

SQLite serializes claims by trusted callers sharing one database. Neither the
registry nor a historical receipt establishes external merge authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .approvals import MAX_TTL, decision_context, valid_binding, valid_context

PROFILE = "itm-local-challenge-registry-v1"
_FIELDS = {"profile", "nonce", "binding", "author", "trust_digest", "issued_at", "expires_at"}
_REASONS = {"binding_mismatch", "author_mismatch", "trust_mismatch", "expired", "not_yet_valid"}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def trust_digest(keys):
    return hashlib.sha256(_json(keys).encode()).hexdigest()


def _name(value):
    return isinstance(value, str) and 0 < len(value) <= 100 and value.strip() == value


def _hex(value, n):
    return isinstance(value, str) and len(value) == n and all(c in "0123456789abcdef" for c in value)


def valid_challenge(challenge):
    return (
        isinstance(challenge, dict) and set(challenge) == _FIELDS
        and challenge["profile"] == PROFILE and _hex(challenge["nonce"], 32)
        and valid_binding(challenge["binding"]) and _name(challenge["author"])
        and _hex(challenge["trust_digest"], 64)
        and type(challenge["issued_at"]) is int and type(challenge["expires_at"]) is int
        and 0 <= challenge["issued_at"] < challenge["expires_at"] <= challenge["issued_at"] + MAX_TTL
    )


def claim_reason(challenge, context, binding, author, keys):
    """Deterministic historical validation of the recorded claim inputs only."""
    if not valid_challenge(challenge) or not valid_context(context):
        raise ValueError("invalid challenge or context")
    if context["nonce"] != challenge["nonce"]:
        raise ValueError("challenge nonce mismatch")
    now = context["evaluated_at"]
    if now < challenge["issued_at"]:
        return "not_yet_valid"
    if now >= challenge["expires_at"]:
        return "expired"
    if binding != challenge["binding"]:
        return "binding_mismatch"
    if author != challenge["author"]:
        return "author_mismatch"
    if trust_digest(keys) != challenge["trust_digest"]:
        return "trust_mismatch"
    return None


def gate_decision(decision, reason):
    if reason is None:
        return decision
    if reason not in _REASONS:
        raise ValueError("unknown challenge denial")
    return {**decision, "authorized": False,
            "reasons": [*decision["reasons"], "approval_challenge:" + reason]}


class ChallengeRejected(ValueError):
    """No claim was granted. Infrastructure failures also prevent decisions."""


class ApprovalRegistry:
    def __init__(self, path, *, create=False, clock=time.time):
        self.path = Path(path).absolute()
        self.clock = clock
        if create:
            # A fresh registry is explicit; never silently reset a missing DB.
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with self._connect() as db:
                db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), last_time INTEGER NOT NULL);
                    INSERT INTO metadata VALUES (1, -1);
                    CREATE TABLE challenges (
                        nonce TEXT PRIMARY KEY, body TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('ISSUED','CONSUMED','REJECTED','EXPIRED','REVOKED')),
                        changed_at INTEGER NOT NULL, reason TEXT
                    );
                    PRAGMA user_version=1;
                    COMMIT;
                """)
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError("unsupported approval registry schema")
            if db.execute("SELECT count(*) FROM metadata WHERE id=1").fetchone()[0] != 1:
                raise ValueError("invalid approval registry metadata")
            db.execute("SELECT nonce, body, state, changed_at, reason FROM challenges LIMIT 0")

    @contextmanager
    def _connect(self):
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("approval registry must be an existing regular file")
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _now(self, db):
        # Read time inside the transaction, not from the untrusted envelope.
        now = int(self.clock())
        if now < 0 or now < db.execute("SELECT last_time FROM metadata WHERE id=1").fetchone()[0]:
            raise ChallengeRejected("clock_rollback")
        db.execute("UPDATE metadata SET last_time=? WHERE id=1", (now,))
        return now

    def issue(self, binding, author, keys, *, ttl=MAX_TTL):
        if not valid_binding(binding) or not _name(author) or type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError("invalid challenge request")
        with self._transaction() as db:
            now = self._now(db)
            challenge = {"profile": PROFILE, "nonce": secrets.token_hex(16),
                         "binding": dict(binding), "author": author, "trust_digest": trust_digest(keys),
                         "issued_at": now, "expires_at": now + ttl}
            db.execute("INSERT INTO challenges VALUES (?, ?, 'ISSUED', ?, NULL)",
                       (challenge["nonce"], _json(challenge), now))
        return challenge

    def claim(self, nonce, binding, author, keys):
        """Burn one issued challenge before evaluation; mismatches burn it too.

        Only a trusted decision caller should have access. A crash after commit
        cannot reissue the same claim. A fresh challenge is required for retry.
        """
        if not _hex(nonce, 32):
            raise ChallengeRejected("invalid_nonce")
        with self._transaction() as db:
            now = self._now(db)
            row = db.execute("SELECT body, state FROM challenges WHERE nonce=?", (nonce,)).fetchone()
            if row is None or row[1] != "ISSUED":
                # Persist the clock watermark even for denied attempts.
                denial = "unknown_challenge" if row is None else "challenge_" + row[1].lower()
                result = None
            else:
                challenge = json.loads(row[0])
                context = decision_context(nonce, now)
                reason = claim_reason(challenge, context, binding, author, keys)
                state = "CONSUMED" if reason is None else ("EXPIRED" if reason == "expired" else "REJECTED")
                changed = db.execute(
                    "UPDATE challenges SET state=?, changed_at=?, reason=? WHERE nonce=? AND state='ISSUED'",
                    (state, now, reason, nonce),
                ).rowcount
                if changed != 1:
                    raise ChallengeRejected("claim_conflict")
                denial = None
                result = {"context": context, "state": state, "reason": reason}
        if denial is not None:
            raise ChallengeRejected(denial)
        return result

    def revoke(self, nonce):
        if not _hex(nonce, 32):
            raise ChallengeRejected("invalid_nonce")
        with self._transaction() as db:
            now = self._now(db)
            return db.execute(
                "UPDATE challenges SET state='REVOKED', changed_at=?, reason='revoked' WHERE nonce=? AND state='ISSUED'",
                (now, nonce),
            ).rowcount == 1


def verify_recorded_claim(events, inputs, keys):
    """Recompute recorded outcome; does not inspect or attest a live database."""
    kinds = [e["kind"] for e in events]
    if kinds.count("approval_challenge_issued") != 1 or kinds.count("approval_challenge_claimed") != 1:
        raise ValueError("missing or duplicate approval challenge evidence")
    issue, claim = (kinds.index(k) for k in ("approval_challenge_issued", "approval_challenge_claimed"))
    if not kinds.index("termination") < issue < kinds.index("approvals") < claim < kinds.index("policy_decision"):
        raise ValueError("invalid approval challenge event order")
    challenge = events[issue]["payload"]["challenge"]
    receipt = events[claim]["payload"]["receipt"]
    context = inputs.get("approval_context")
    if not isinstance(receipt, dict) or set(receipt) != {"context", "state", "reason"} or receipt["context"] != context:
        raise ValueError("invalid recorded claim")
    reason = claim_reason(challenge, context, inputs["binding"], inputs["author"], keys)
    state = "CONSUMED" if reason is None else ("EXPIRED" if reason == "expired" else "REJECTED")
    if receipt["reason"] != reason or receipt["state"] != state:
        raise ValueError("approval challenge outcome mismatch")
    return reason
