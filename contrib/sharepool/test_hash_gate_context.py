#!/usr/bin/env python3
"""A changing native tip cannot mix height/hash responses or hide bad policy."""
from collections import Counter
import unittest

from hash_mining_gate import HashMiningGate
from hash_snapshot import MAX_SNAPSHOT_BYTES, rules_hash
from native_mining_gate import REGTEST_GENESIS


class ContextRPC:
    def __init__(self, version=8):
        self.version, self.height = version, 2
        self.hashes = {0: REGTEST_GENESIS, 1: '01' * 32, 2: '02' * 32}
        self.tip = self.hashes[self.height]
        self.after_info = None
        self.profile = {'mode': {4: 'hash-only-v4', 7: 'hash-only-v7-compact-tides',
            8: 'hash-only-v8-vardiff-tides'}[version], 'rules': f'{rules_hash(version):064x}',
            'max_snapshot_bytes': MAX_SNAPSHOT_BYTES, 'activation_height': 102}
        self.counts = Counter()
        self.lookup_error = None
        self.lookup_override = None
        self.final_tip_override = None

    def advance(self, *, same_height=False):
        if not same_height:
            self.height += 1
        self.tip = f'{int(self.tip, 16) + 1:064x}'
        self.hashes[self.height] = self.tip

    def __call__(self, method, *args):
        self.counts[method] += 1
        if method == 'getbestblockhash':
            if self.counts[method] % 2 == 0 and self.final_tip_override is not None:
                return self.final_tip_override
            return self.tip
        if method == 'getblockchaininfo':
            result = {'chain': 'regtest', 'blocks': self.height}
            if self.after_info is not None:
                self.after_info(self)
            return result
        if method == 'getsharepoolhashstatus':
            return dict(self.profile)
        if method == 'getblockhash':
            if args[0] != 0:
                if self.lookup_error is not None:
                    raise self.lookup_error
                if self.lookup_override is not None:
                    return self.lookup_override
            return self.hashes[args[0]]
        raise AssertionError(method)


class GateContextTests(unittest.TestCase):
    @staticmethod
    def gate(rpc):
        gate = object.__new__(HashMiningGate)
        gate.rpc, gate.profile_version = rpc, rpc.version
        gate.rules, gate.activation_height = rules_hash(rpc.version), 102
        gate.mode = rpc.profile['mode']
        return gate

    def test_stable_capture_preserves_legacy_and_v8_contexts(self):
        for version in (4, 7, 8):
            with self.subTest(version=version):
                rpc = ContextRPC(version)
                self.assertEqual(self.gate(rpc)._context(), (2, rpc.tip))
                self.assertEqual(rpc.counts['getbestblockhash'], 2)
                self.assertEqual(rpc.counts['getblockchaininfo'], 1)

    def test_height_tip_race_restarts_complete_capture(self):
        rpc = ContextRPC()
        def once(current):
            current.after_info = None
            current.advance()
        rpc.after_info = once
        self.assertEqual(self.gate(rpc)._context(), (3, rpc.tip))
        self.assertEqual(rpc.counts['getblockchaininfo'], 2)
        self.assertEqual(rpc.counts['getsharepoolhashstatus'], 2)
        self.assertEqual(rpc.counts['getbestblockhash'], 4)

    def test_same_height_reorg_retries_without_accepting_old_branch(self):
        rpc = ContextRPC()
        before = rpc.tip
        def once(current):
            current.after_info = None
            current.advance(same_height=True)
        rpc.after_info = once
        self.assertEqual(self.gate(rpc)._context(), (2, rpc.tip))
        self.assertNotEqual(before, rpc.tip)
        self.assertEqual(rpc.counts['getblockchaininfo'], 2)

    def test_shorter_reorg_can_retry_removed_height_lookup(self):
        rpc = ContextRPC()
        def once(current):
            current.after_info = None
            del current.hashes[2]
            current.height, current.tip = 1, current.hashes[1]
        rpc.after_info = once
        self.assertEqual(self.gate(rpc)._context(), (1, rpc.tip))
        self.assertEqual(rpc.counts['getblockchaininfo'], 2)

    def test_continuously_moving_tip_is_bounded_and_fails_closed(self):
        rpc = ContextRPC()
        rpc.after_info = lambda current: current.advance()
        with self.assertRaisesRegex(ValueError, 'native tip changed during context capture'):
            self.gate(rpc)._context()
        self.assertEqual(rpc.counts['getblockchaininfo'], 3)
        self.assertEqual(rpc.counts['getbestblockhash'], 6)

    def test_bad_profile_or_genesis_is_not_retried_even_as_tip_changes(self):
        for mutate in (lambda rpc: rpc.profile.update(mode='wrong'),
                       lambda rpc: rpc.profile.update(rules='ff' * 32),
                       lambda rpc: rpc.profile.update(activation_height=True),
                       lambda rpc: rpc.profile.update(max_snapshot_bytes=1),
                       lambda rpc: rpc.hashes.update({0: 'ff' * 32})):
            rpc = ContextRPC()
            gate = self.gate(rpc)
            def change(current):
                current.advance()
                mutate(current)
            rpc.after_info = change
            with self.assertRaisesRegex(ValueError, 'active native regtest hash-only v8 profile'):
                gate._context()
            self.assertEqual(rpc.counts['getblockchaininfo'], 1)

    def test_lookup_failure_without_observed_tip_change_preserves_error(self):
        rpc = ContextRPC()
        rpc.lookup_error = RuntimeError('native lookup unavailable')
        with self.assertRaisesRegex(RuntimeError, 'native lookup unavailable'):
            self.gate(rpc)._context()
        self.assertEqual(rpc.counts['getblockchaininfo'], 1)

    def test_stable_inconsistent_or_malformed_final_tip_is_not_retried(self):
        for field, value in (('lookup_override', 'ff' * 32), ('final_tip_override', 'not-a-hash')):
            rpc = ContextRPC()
            setattr(rpc, field, value)
            with self.assertRaisesRegex(ValueError, 'active native regtest hash-only v8 profile'):
                self.gate(rpc)._context()
            self.assertEqual(rpc.counts['getblockchaininfo'], 1)


if __name__ == '__main__':
    unittest.main()
