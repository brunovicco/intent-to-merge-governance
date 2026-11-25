import copy
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from intent_merge.approvals import decision_context, sign_approval, MAX_TTL
from intent_merge.core import approval, digest, evaluate_policy, load_config
from intent_merge.path_policy import SEGMENT_V2

ROOT = Path(__file__).resolve().parents[1]


class ApprovalEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_config(ROOT / 'examples/spec.toml')
        self.policy = load_config(ROOT / 'examples/policy.toml')
        self.binding = {'head': 'a'*40, 'base': 'b'*40, 'spec': digest(self.spec),
                        'policy': digest(self.policy), 'harness': 'c'*64,
                        'path_semantics': SEGMENT_V2}
        self.ctx = decision_context('d'*32, 100)
        self.pairs = {actor: Ed25519PrivateKey.generate() for actor in ('reviewer', 'security', 'agent')}
        self.keys = {actor: 'ed25519-public:'+key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
                     for actor, key in self.pairs.items()}
        self.approvals = [self.issue(actor) for actor in ('reviewer', 'security')]

    def issue(self, actor, *, context=None, issued_at=90, expires_at=200, role=None, binding=None, author='agent'):
        return sign_approval(actor, role or self.policy['approvers'].get(actor, 'engineering'), author,
                             self.binding if binding is None else binding,
                             self.ctx if context is None else context, self.pairs[actor],
                             issued_at=issued_at, expires_at=expires_at)

    def decision(self, approvals=None, **kwargs):
        args = dict(paths=['app/payments.py'], checks={k: True for k in self.policy['required_checks']},
                    binding=self.binding, approvals=self.approvals if approvals is None else approvals,
                    keys=self.keys, author='agent', termination='passed', current_head=self.binding['head'],
                    current_base=self.binding['base'], eval_binding=self.binding, approval_context=self.ctx)
        args.update(kwargs)
        return evaluate_policy(self.spec, self.policy, **args)

    def test_valid_two_signers(self):
        self.assertTrue(self.decision()['authorized'])

    def test_expiry_boundary(self):
        self.assertFalse(self.decision(approval_context=decision_context('d'*32, 200))['authorized'])
        self.assertTrue(self.decision(approval_context=decision_context('d'*32, 199))['authorized'])

    def test_not_yet_valid(self):
        self.assertFalse(self.decision(approval_context=decision_context('d'*32, 89))['authorized'])

    def test_wrong_challenge(self):
        self.assertFalse(self.decision(approval_context=decision_context('e'*32, 100))['authorized'])

    def test_missing_context(self):
        result = self.decision(approval_context=None)
        self.assertFalse(result['authorized'])
        self.assertIn('invalid_approval_context', result['reasons'])

    def test_wrong_audience(self):
        ctx = {**self.ctx, 'audience': 'another-service'}
        self.assertFalse(self.decision(approval_context=ctx)['authorized'])

    def test_invalid_lifetime(self):
        for issued, expires in ((90, 90), (90, 90+MAX_TTL+1), (True, 100)):
            with self.subTest(issued=issued, expires=expires), self.assertRaises(ValueError):
                self.issue('reviewer', issued_at=issued, expires_at=expires)

    def test_changed_candidate(self):
        binding = {**self.binding, 'head': 'f'*40}
        result = self.decision(binding=binding, current_head=binding['head'], eval_binding=binding)
        self.assertFalse(result['authorized'])

    def test_wrong_role_signed(self):
        self.assertFalse(self.decision([self.issue('reviewer', role='security'), self.approvals[1]])['authorized'])

    def test_wrong_author_signed(self):
        self.assertFalse(self.decision([self.issue('reviewer', author='other'), self.approvals[1]])['authorized'])

    def test_tampered_envelope(self):
        for key, value in (('expires_at', 201), ('key_id', '0'*64), ('signature', '0'*128), ('profile', 'legacy')):
            with self.subTest(key=key):
                changed = {**self.approvals[0], key: value}
                self.assertFalse(self.decision([changed, self.approvals[1]])['authorized'])

    def test_malformed_envelopes(self):
        for value in (None, [], {'actor': []}, {**self.approvals[0], 'actor': []},
                      {**self.approvals[0], 'unexpected': True}):
            with self.subTest(value=value):
                self.assertFalse(self.decision([value, self.approvals[1]])['authorized'])

    def test_duplicate_does_not_fill_other_role(self):
        result = self.decision([self.approvals[0], self.approvals[0]])
        self.assertEqual(result['verified_roles'], ['engineering'])
        self.assertFalse(result['authorized'])

    def test_shared_approver_key_rejected(self):
        self.pairs['security'] = self.pairs['reviewer']
        keys = {**self.keys, 'security': self.keys['reviewer']}
        self.assertFalse(self.decision([self.issue('reviewer'), self.issue('security')], keys=keys)['authorized'])

    def test_author_key_collision_rejected(self):
        self.assertFalse(self.decision(keys={**self.keys, 'agent': self.keys['reviewer']})['authorized'])

    def test_legacy_ed25519_only_historical(self):
        private = {actor: 'ed25519-private:'+key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
                   for actor, key in self.pairs.items()}
        legacy = [approval(actor, self.binding, private) for actor in ('reviewer', 'security')]
        self.assertFalse(self.decision(legacy)['authorized'])
        self.assertTrue(self.decision(legacy, approval_context=None, _historical_semantics=SEGMENT_V2)['authorized'])

    def test_private_key_cannot_verify(self):
        private = 'ed25519-private:'+self.pairs['reviewer'].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.assertFalse(self.decision(keys={**self.keys, 'reviewer': private})['authorized'])

    def test_domain_separation(self):
        from intent_merge.core import canonical
        body = {k: v for k, v in self.approvals[0].items() if k != 'signature'}
        legacy_signature = self.pairs['reviewer'].sign(canonical(body)).hex()
        self.assertFalse(self.decision([{**body, 'signature': legacy_signature}, self.approvals[1]])['authorized'])
