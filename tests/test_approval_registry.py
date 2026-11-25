import copy
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from intent_merge.approval_registry import (
    ApprovalRegistry, ChallengeRejected, gate_decision, verify_recorded_claim,
)
from intent_merge.approvals import decision_context


class ApprovalRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "challenges.sqlite"
        self.now = 100
        self.registry = ApprovalRegistry(self.path, create=True, clock=lambda: self.now)
        self.binding = {"head": "a"*40, "base": "b"*40, "spec": "c"*64,
                        "policy": "d"*64, "harness": "e"*64, "path_semantics": "segment-v2"}
        self.keys = {"reviewer": "ed25519-public:" + "f"*64}

    def issue(self, **kw):
        return self.registry.issue(self.binding, "agent", self.keys, **kw)

    def claim(self, challenge, **kw):
        args = dict(binding=self.binding, author="agent", keys=self.keys)
        args.update(kw)
        return self.registry.claim(challenge["nonce"], **args)

    def test_single_use(self):
        c = self.issue()
        self.assertEqual(self.claim(c)["state"], "CONSUMED")
        with self.assertRaisesRegex(ChallengeRejected, "challenge_consumed"):
            self.claim(c)

    def test_restart(self):
        c = self.issue()
        self.claim(c)
        self.registry = ApprovalRegistry(self.path, clock=lambda: self.now)
        with self.assertRaisesRegex(ChallengeRejected, "challenge_consumed"):
            self.claim(c)

    def test_outstanding_challenge_survives_restart(self):
        c = self.issue()
        self.registry = ApprovalRegistry(self.path, clock=lambda: self.now)
        self.assertEqual(self.claim(c)["state"], "CONSUMED")

    def test_concurrent_claims(self):
        c = self.issue()
        barrier = Barrier(8)
        def attempt(_):
            registry = ApprovalRegistry(self.path, clock=lambda: self.now)
            barrier.wait(timeout=10)
            try:
                return registry.claim(c["nonce"], self.binding, "agent", self.keys)["state"]
            except ChallengeRejected as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(attempt, range(8)))
        self.assertEqual(states.count("CONSUMED"), 1)
        self.assertEqual(states.count("challenge_consumed"), 7)

    def test_expiry_boundary(self):
        c = self.issue(ttl=10)
        self.now = 110
        self.assertEqual(self.claim(c)["state"], "EXPIRED")
        with self.assertRaisesRegex(ChallengeRejected, "challenge_expired"):
            self.claim(c)

    def test_last_valid_second(self):
        c = self.issue(ttl=10)
        self.now = 109
        self.assertEqual(self.claim(c)["state"], "CONSUMED")

    def test_revocation_terminal(self):
        c = self.issue()
        self.assertTrue(self.registry.revoke(c["nonce"]))
        self.assertFalse(self.registry.revoke(c["nonce"]))
        self.registry = ApprovalRegistry(self.path, clock=lambda: self.now)
        with self.assertRaisesRegex(ChallengeRejected, "challenge_revoked"):
            self.claim(c)

    def test_consumed_cannot_be_revoked_or_restored(self):
        c = self.issue()
        self.claim(c)
        self.assertFalse(self.registry.revoke(c["nonce"]))
        with self.assertRaisesRegex(ChallengeRejected, "challenge_consumed"):
            self.claim(c)

    def test_binding_mismatch_burns_challenge(self):
        c = self.issue()
        result = self.claim(c, binding={**self.binding, "head": "f"*40})
        self.assertEqual(result["reason"], "binding_mismatch")
        self.assertFalse(gate_decision({"authorized": True, "reasons": []}, result["reason"])["authorized"])
        with self.assertRaisesRegex(ChallengeRejected, "challenge_rejected"):
            self.claim(c)

    def test_author_mismatch(self):
        self.assertEqual(self.claim(self.issue(), author="other")["reason"], "author_mismatch")

    def test_trust_mismatch(self):
        self.assertEqual(self.claim(self.issue(), keys={})["reason"], "trust_mismatch")

    def test_clock_rollback_persisted(self):
        c = self.issue()
        self.now = 110
        self.issue()
        self.registry = ApprovalRegistry(self.path, clock=lambda: self.now)
        self.now = 109
        with self.assertRaisesRegex(ChallengeRejected, "clock_rollback"):
            self.claim(c)
        self.now = 110
        self.assertEqual(self.claim(c)["state"], "CONSUMED")

    def test_unknown_and_invalid_nonce(self):
        with self.assertRaisesRegex(ChallengeRejected, "unknown_challenge"):
            self.registry.claim("0"*32, self.binding, "agent", self.keys)
        with self.assertRaisesRegex(ChallengeRejected, "invalid_nonce"):
            self.registry.claim("invalid", self.binding, "agent", self.keys)

    def test_no_silent_database_reset(self):
        with self.assertRaises(FileExistsError):
            ApprovalRegistry(self.path, create=True)
        self.path.unlink()
        with self.assertRaises(ValueError):
            ApprovalRegistry(self.path)
        self.assertFalse(self.path.exists())

    def test_unknown_schema_rejected(self):
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "unsupported approval registry schema"):
            ApprovalRegistry(self.path)

    def test_invalid_issue(self):
        for ttl in (0, 301, True):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.issue(ttl=ttl)

    def test_recorded_claim_replay_is_historical(self):
        c = self.issue()
        receipt = self.claim(c)
        events = [
            {"kind": "termination"},
            {"kind": "approval_challenge_issued", "payload": {"challenge": c}},
            {"kind": "approvals"},
            {"kind": "approval_challenge_claimed", "payload": {"receipt": receipt}},
            {"kind": "policy_decision"},
        ]
        inputs = {"binding": self.binding, "author": "agent", "approval_context": receipt["context"]}
        self.assertIsNone(verify_recorded_claim(events, inputs, self.keys))
        tampered = copy.deepcopy(events)
        tampered[3]["payload"]["receipt"]["state"] = "REVOKED"
        with self.assertRaisesRegex(ValueError, "outcome mismatch"):
            verify_recorded_claim(tampered, inputs, self.keys)
        with self.assertRaises(ValueError):
            verify_recorded_claim(events + [events[1]], inputs, self.keys)
        with self.assertRaises(ChallengeRejected):
            self.claim(c)

    def test_receipt_rejected_on_changed_context(self):
        c = self.issue()
        r = self.claim(c)
        events = [{"kind": "termination"}, {"kind": "approval_challenge_issued", "payload": {"challenge": c}},
                  {"kind": "approvals"}, {"kind": "approval_challenge_claimed", "payload": {"receipt": r}},
                  {"kind": "policy_decision"}]
        inputs = {"binding": self.binding, "author": "agent", "approval_context": decision_context(c["nonce"], 101)}
        with self.assertRaisesRegex(ValueError, "invalid recorded claim"):
            verify_recorded_claim(events, inputs, self.keys)
