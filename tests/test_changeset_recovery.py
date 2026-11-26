"""Fault injection on local bare fixtures, with no remote access."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intent_merge import changeset, hardening
from intent_merge.changeset_demo import config_keys, fixture
from intent_merge.core import Ledger, digest


class ChangesetObservationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.config, self.keys = config_keys()
        self.repos = fixture(self.root / 'repos', 'compatible')
        self.plan = changeset.plan(self.config, self.repos)
        self.approvals = [changeset.approve(self.config, self.plan, n, self.keys[n]) for n in self.plan['order']]
        self.args = (self.config, self.plan, self.approvals, self.repos, self.keys['executor'])
        self.bases = {n: c['base'] for n, c in self.plan['components'].items()}
        self.heads = {n: c['head'] for n, c in self.plan['components'].items()}
        self.db = self.root / 'state.sqlite'

    def actual(self):
        return {n: changeset.ref(p, 'refs/heads/main') for n, p in self.repos.items()}

    def verify_manual(self, receipt, phase):
        self.assertEqual(receipt['status'], 'MANUAL_INTERVENTION')
        self.assertEqual(receipt['events'][-2]['payload']['phase'], phase)
        self.assertIsNone(receipt['events'][-1]['payload']['refs'])
        result = changeset.verify_receipt(self.config, receipt, digest(self.config))
        self.assertEqual(result['status'], 'MANUAL_INTERVENTION')
        self.assertFalse(result['merge_authority'])

    def fail_after_write(self, direction='forward', *, module=changeset):
        original_git, original_ref = module.git, module.ref
        state = {'failed': False, 'writes': []}

        def git(repo, *args, **kwargs):
            result = original_git(repo, *args, **kwargs)
            if args[0] == 'update-ref':
                state['writes'].append(args)
                if direction == 'forward' or args[2] == self.bases['payments']:
                    state['failed'] = True
            return result

        def ref(repo, name):
            if state['failed'] and name == 'refs/heads/main':
                raise OSError('synthetic observation failure')
            return original_ref(repo, name)

        return state, patch.object(module, 'git', side_effect=git), patch.object(module, 'ref', side_effect=ref)

    @staticmethod
    def fail_checkout(stage, component, repos):
        if stage == 'before_merge' and component == 'checkout':
            raise ValueError('synthetic merge failure')

    def test_read_failure_after_forward_write(self):
        state, git, ref = self.fail_after_write()
        with git, ref:
            receipt = changeset.execute(*self.args)
        self.verify_manual(receipt, 'forward_write')
        self.assertEqual(len(state['writes']), 1)
        self.assertEqual(self.actual(), {**self.bases, 'payments': self.heads['payments']})
        self.assertEqual(receipt['events'][-3]['kind'], 'write_intent')

    def test_read_failure_after_compensation_write(self):
        state, git, ref = self.fail_after_write('compensate')
        with git, ref:
            receipt = changeset.execute(*self.args, fault=self.fail_checkout)
        self.verify_manual(receipt, 'compensation_write')
        self.assertEqual(len(state['writes']), 2)
        self.assertEqual(self.actual(), self.bases)  # Only the test observes restoration.

    def test_read_failure_in_merge_exception_handler(self):
        failing = False
        original = changeset.ref

        def fault(stage, component, repos):
            nonlocal failing
            if stage == 'before_merge' and component == 'checkout':
                failing = True
                raise ValueError('precheck failed')

        def ref(repo, name):
            if failing:
                raise OSError('read failed')
            return original(repo, name)

        with patch.object(changeset, 'ref', side_effect=ref):
            receipt = changeset.execute(*self.args, fault=fault)
        self.verify_manual(receipt, 'merge_precheck')
        self.assertEqual(self.actual(), {**self.bases, 'payments': self.heads['payments']})

    def test_read_failure_in_compensation_exception_handler(self):
        failing = False
        original = changeset.ref

        def fault(stage, component, repos):
            nonlocal failing
            self.fail_checkout(stage, component, repos)
            if stage == 'before_compensate':
                failing = True
                raise ValueError('precheck failed')

        def ref(repo, name):
            if failing:
                raise OSError('read failed')
            return original(repo, name)

        with patch.object(changeset, 'ref', side_effect=ref):
            receipt = changeset.execute(*self.args, fault=fault)
        self.verify_manual(receipt, 'compensation_precheck')
        self.assertEqual(self.actual(), {**self.bases, 'payments': self.heads['payments']})

    def test_terminal_read_failure(self):
        original = changeset.ref
        original_git = changeset.git
        writes = 0
        observed_after_last = 0

        def git(repo, *args, **kwargs):
            nonlocal writes
            result = original_git(repo, *args, **kwargs)
            if args[0] == 'update-ref':
                writes += 1
            return result

        def ref(repo, name):
            nonlocal observed_after_last
            if writes == 3 and name == 'refs/heads/main':
                observed_after_last += 1
                if observed_after_last > 3:
                    raise OSError('final observation failed')
            return original(repo, name)

        with patch.object(changeset, 'git', side_effect=git), patch.object(changeset, 'ref', side_effect=ref):
            receipt = changeset.execute(*self.args)
        self.verify_manual(receipt, 'finish')
        self.assertEqual(self.actual(), self.heads)

    def test_resigned_unknown_cannot_be_success(self):
        _, git, ref = self.fail_after_write()
        with git, ref:
            receipt = changeset.execute(*self.args)
        forged = copy.deepcopy(receipt)
        ledger = Ledger()
        for event in forged['events']:
            data = event['payload']
            if event['kind'] == 'finish':
                data = {'status': 'COMPLETED', 'refs': self.heads}
            ledger.add(event['kind'], **data)
        forged['events'] = ledger.events
        forged['status'] = 'COMPLETED'
        forged.pop('signature')
        forged['signature'] = changeset.sign('receipt', forged, self.keys['executor'])
        with self.assertRaisesRegex(ValueError, 'unknown refs'):
            changeset.verify_receipt(self.config, forged, digest(self.config))

    def run_durable(self, **kwargs):
        coordinator = hardening.DurableChangeSet(self.db)
        try:
            return coordinator.run(*self.args, **kwargs)
        finally:
            coordinator.close()

    def check_persisted_manual(self, state, direction):
        self.assertEqual(state['status'], 'MANUAL_INTERVENTION')
        self.assertEqual(state['pending']['direction'], direction)
        changeset.verify_sig('durable-state', {k: v for k, v in state.items() if k != 'signature'}, state['signature'], self.config['executor_key'])
        before = self.actual()
        with patch.object(hardening, 'git', wraps=hardening.git) as git:
            self.assertEqual(self.run_durable(compensate=True), state)
            self.assertFalse(any(call.args[1] == 'update-ref' for call in git.call_args_list))
        self.assertEqual(self.actual(), before)

    def test_durable_read_failure_after_cas(self):
        state, git, ref = self.fail_after_write(module=hardening)
        with git, ref:
            result = self.run_durable()
        self.assertEqual(len(state['writes']), 1)
        self.assertEqual(result['completed'], [])
        self.check_persisted_manual(result, 'forward')

    def crash_after_first_cas(self):
        def fault(stage, component, repos):
            if stage == 'after_cas' and component == 'payments':
                raise RuntimeError('simulated process interruption')
        with self.assertRaises(RuntimeError):
            self.run_durable(fault=fault)

    def test_durable_read_failure_during_recovery(self):
        self.crash_after_first_cas()
        with patch.object(hardening, 'ref', side_effect=OSError('unavailable')):
            result = self.run_durable()
        self.check_persisted_manual(result, 'forward')

    def test_durable_read_failure_after_compensation(self):
        self.crash_after_first_cas()
        state, git, ref = self.fail_after_write('compensate', module=hardening)
        with git, ref:
            result = self.run_durable(compensate=True)
        self.assertEqual(len(state['writes']), 1)
        self.assertEqual(result['completed'], ['payments'])
        self.check_persisted_manual(result, 'compensate')
        self.assertEqual(self.actual(), self.bases)


if __name__ == '__main__':
    unittest.main()
