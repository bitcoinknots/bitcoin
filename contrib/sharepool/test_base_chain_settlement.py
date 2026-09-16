#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from dataclasses import replace
from decimal import Decimal
import tempfile
from pathlib import Path
import unittest

from base_chain_settlement import (BaseChainSettlement, ChainChanged, MAX_MONEY,
                                   NativeRPCError, SettlementCommitment, normalize_payouts)


def block_hash(number):
    return number.to_bytes(32, "big").hex()


class NativeNode:
    def __init__(self):
        self.genesis = block_hash(1)
        self.chain = [self.genesis]
        self.headers = {self.genesis: {"hash": self.genesis, "height": 0}}
        self.blocks, self.missing_bodies = {}, set()
        self.next_id = 1000
        self.change_on_second_tip = False
        self.tip_reads = 0

    def extend(self, count=1):
        for _ in range(count):
            self.next_id += 1
            identity = block_hash(self.next_id)
            self.headers[identity] = {"hash": identity, "height": len(self.chain),
                                      "previousblockhash": self.chain[-1]}
            self.chain.append(identity)

    def candidate(self, commitment, payouts):
        self.next_id += 1
        identity = block_hash(self.next_id)
        self.headers[identity] = {"hash": identity, "height": len(self.chain), "header_version": 2,
                                  "previousblockhash": self.chain[-1], "mm_rhs": commitment.root.hex()}
        self.blocks[identity] = {"hash": identity, "tx": [{"vin": [{"coinbase": "0101"}],
            "vout": [{"n": index, "value": Decimal(amount) / 100_000_000,
                      "scriptPubKey": {"hex": script}} for index, (script, amount) in enumerate(payouts)]}]}
        self.chain.append(identity)
        return identity

    def __call__(self, method, *params):
        if method == "getblockhash":
            return self.chain[params[0]]
        if method == "getbestblockhash":
            self.tip_reads += 1
            if self.change_on_second_tip and self.tip_reads % 2 == 0:
                self.extend()
            return self.chain[-1]
        if method == "getblockheader":
            if params[0] not in self.headers:
                raise NativeRPCError(-5, "Block not found")
            return self.headers[params[0]]
        if method == "getblock":
            if params[0] in self.missing_bodies:
                raise NativeRPCError(-1, "Block not available (pruned data)")
            if params[0] not in self.blocks:
                raise NativeRPCError(-5, "Block not found")
            return self.blocks[params[0]]
        raise AssertionError("observer called unexpected RPC: " + method)


class BaseChainSettlementTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "settlements.sqlite3"
        self.node = NativeNode()
        self.outputs = (("0014" + "11" * 20, 312_500_000),
                        ("6a24aa21a9ed" + "22" * 32, 0))
        self.commitment = self.make_commitment()
        self.observer = BaseChainSettlement(self.path, network_genesis=self.node.genesis, rpc=self.node)

    def tearDown(self):
        self.observer.close()
        self.directory.cleanup()

    def make_commitment(self, **changes):
        args = dict(network_genesis=self.node.genesis, pool_id=b"pool-A", rules_root=block_hash(2),
                    snapshot_root=block_hash(3), base_parent=self.node.chain[-1], payouts=self.outputs)
        args.update(changes)
        return SettlementCommitment.create(**args)

    def observe_candidate(self):
        identity = self.node.candidate(self.commitment, self.outputs)
        self.observer.observe(identity, self.commitment, self.outputs)
        return identity

    def test_commitment_binds_every_field_and_order(self):
        for field, value in (("network_genesis", block_hash(20)), ("pool_id", b"pool-B"),
                             ("rules_root", block_hash(21)), ("snapshot_root", block_hash(22)),
                             ("base_parent", block_hash(23)), ("payout_digest", block_hash(24))):
            self.assertNotEqual(self.commitment.root, replace(self.commitment, **{field: value}).root)
        self.assertNotEqual(self.commitment.root, self.make_commitment(payouts=tuple(reversed(self.outputs))).root)
        self.assertEqual(self.commitment, SettlementCommitment.from_object(self.commitment.to_object()))
        with self.assertRaises(ValueError):
            replace(self.commitment, version=2)

    def test_unknown_block_is_pending_then_accepted(self):
        identity = block_hash(self.node.next_id + 1)
        self.observer.observe(identity, self.commitment, self.outputs)
        self.assertEqual(self.observer.refresh()[0]["status"], "pending")
        self.assertEqual(self.node.candidate(self.commitment, self.outputs), identity)
        record = self.observer.refresh()[0]
        self.assertEqual((record["status"], record["confirmations"], record["descendants"]), ("immature", 1, 0))
        self.assertTrue(record["payload_verified"])

    def test_maturity_and_next_block_spend_boundaries(self):
        self.observe_candidate()
        self.node.extend(98)
        record = self.observer.refresh()[0]
        self.assertEqual((record["status"], record["confirmations"], record["spendable_next_block"]),
                         ("immature", 99, False))
        self.node.extend()
        record = self.observer.refresh()[0]
        self.assertEqual((record["status"], record["confirmations"], record["spendable_next_block"]),
                         ("immature", 100, True))
        self.node.extend()
        record = self.observer.refresh()[0]
        self.assertEqual((record["status"], record["confirmations"], record["descendants"]), ("mature", 101, 100))

    def test_base_chain_reorg_rolls_back_mature_settlement(self):
        identity = self.observe_candidate()
        self.node.extend(100)
        self.assertEqual(self.observer.refresh()[0]["status"], "mature")
        old_chain = list(self.node.chain)
        self.node.chain = [self.node.genesis]
        self.node.extend(102)
        record = self.observer.refresh()[0]
        self.assertEqual((record["block_hash"], record["status"], record["confirmations"]), (identity, "orphaned", 0))
        self.assertFalse(record["spendable_next_block"])
        self.node.chain = old_chain
        self.assertEqual(self.observer.refresh()[0]["status"], "mature")

    def test_checkpoint_fork_cannot_change_base_anchor(self):
        identity = self.observe_candidate()
        self.node.extend(100)
        before = self.observer.refresh()
        # Arbitrary accounting fork fields are irrelevant to native RPC answers.
        self.node.checkpoint_tip = block_hash(111)
        self.node.checkpoint_balances = {}
        self.assertEqual(self.observer.refresh(), before)
        self.assertEqual(self.observer.record(identity)["commitment"], self.commitment.to_object())

    def test_restart_preserves_exact_metadata_and_revalidates_status(self):
        identity = self.observe_candidate()
        expected = self.observer.refresh()[0]
        self.observer.close()
        self.observer = BaseChainSettlement(self.path, network_genesis=self.node.genesis, rpc=self.node)
        self.assertEqual(self.observer.record(identity), expected)
        self.node.extend(100)
        self.assertEqual(self.observer.refresh()[0]["status"], "mature")
        self.assertEqual(self.observer.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.observer.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.observer.db.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_duplicate_is_idempotent_and_conflicting_metadata_rejects(self):
        identity = self.observe_candidate()
        self.observer.observe(identity, self.commitment, list(self.outputs))
        self.assertEqual(len(self.observer.records()), 1)
        conflicting = replace(self.commitment, snapshot_root=block_hash(50))
        with self.assertRaisesRegex(ValueError, "conflicting metadata"):
            self.observer.observe(identity, conflicting, self.outputs)
        self.assertEqual(self.observer.record(identity)["commitment"], self.commitment.to_object())

    def test_network_mismatch_rejected_on_open_and_refresh(self):
        other = NativeNode()
        other.genesis, other.chain[0] = block_hash(88), block_hash(88)
        with self.assertRaisesRegex(ValueError, "another network"):
            BaseChainSettlement(self.path, network_genesis=other.genesis, rpc=other)
        with self.assertRaisesRegex(ValueError, "another network"):
            BaseChainSettlement(Path(self.directory.name) / "wrong.sqlite3", network_genesis=other.genesis, rpc=self.node)
        self.observe_candidate()
        self.observer.rpc = other
        with self.assertRaisesRegex(ValueError, "another network"):
            self.observer.refresh()
        self.assertEqual(self.observer.records()[0]["status"], "pending")

    def test_invalid_payouts_and_digest_reject_without_storage(self):
        invalid = [[], [("51", -1)], [("51", True)], [("51", 1.5)], [("GG", 1)],
                   [("AB", 1)], [("", 1)], [("51", 0)], [("51", MAX_MONEY), ("52", 1)]]
        for outputs in invalid:
            with self.subTest(outputs=outputs), self.assertRaises(ValueError):
                normalize_payouts(outputs)
        with self.assertRaisesRegex(ValueError, "payouts do not match"):
            self.observer.observe(block_hash(90), self.commitment, [("51", 123)])
        self.assertEqual(self.observer.records(), [])

    def test_wrong_header_root_or_parent_rejects_atomically(self):
        identity = self.observe_candidate()
        original = dict(self.node.headers[identity])
        for field, value in (("mm_rhs", self.commitment.root[::-1].hex()),
                             ("previousblockhash", block_hash(90)), ("header_version", 0)):
            self.node.headers[identity] = {**original, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "native header differs"):
                self.observer.refresh()
            self.assertEqual(self.observer.record(identity)["status"], "pending")
        self.node.headers[identity] = original
        self.assertEqual(self.observer.refresh()[0]["status"], "immature")

    def test_exact_native_coinbase_includes_witness_output(self):
        identity = self.observe_candidate()
        outputs = self.node.blocks[identity]["tx"][0]["vout"]
        original = [dict(item) for item in outputs]
        outputs.pop()
        with self.assertRaisesRegex(ValueError, "native coinbase differs"):
            self.observer.refresh()
        self.node.blocks[identity]["tx"][0]["vout"] = original
        self.assertEqual(self.observer.refresh()[0]["payouts"], self.outputs)

    def test_unavailable_body_pending_and_verified_body_can_be_pruned(self):
        identity = self.observe_candidate()
        self.node.missing_bodies.add(identity)
        self.assertEqual(self.observer.refresh()[0]["status"], "pending")
        self.node.missing_bodies.clear()
        self.assertEqual(self.observer.refresh()[0]["status"], "immature")
        self.node.missing_bodies.add(identity)
        self.node.extend(100)
        self.assertEqual(self.observer.refresh()[0]["status"], "mature")

    def test_tip_race_does_not_commit_partial_status(self):
        identity = self.observe_candidate()
        self.node.change_on_second_tip = True
        with self.assertRaises(ChainChanged):
            self.observer.refresh()
        self.assertEqual(self.observer.record(identity)["status"], "pending")
        self.assertFalse(self.observer.record(identity)["payload_verified"])

    def test_unexpected_rpc_error_propagates_without_status_changes(self):
        identity = self.observe_candidate()
        def failing(method, *params):
            if method == "getblock":
                raise NativeRPCError(-32603, "internal error")
            return self.node(method, *params)
        self.observer.rpc = failing
        with self.assertRaises(NativeRPCError):
            self.observer.refresh()
        self.assertEqual(self.observer.record(identity)["status"], "pending")

    def test_fractional_satoshi_native_output_rejects(self):
        identity = self.observe_candidate()
        self.node.blocks[identity]["tx"][0]["vout"][0]["value"] = "0.000000001"
        with self.assertRaisesRegex(ValueError, "integer number of satoshis"):
            self.observer.refresh()

    def test_corrupted_persisted_metadata_is_not_trusted(self):
        identity = self.observe_candidate()
        self.observer.db.execute("UPDATE settlements SET commitment_root=? WHERE block_hash=?", (block_hash(77), identity))
        with self.assertRaisesRegex(ValueError, "persisted settlement metadata"):
            self.observer.refresh()

    def test_generic_misc_rpc_error_is_not_missing_data(self):
        self.observe_candidate()
        def failing(method, *params):
            if method == "getblock":
                raise NativeRPCError(-1, "Unexpected database failure")
            return self.node(method, *params)
        self.observer.rpc = failing
        with self.assertRaises(NativeRPCError):
            self.observer.refresh()

    def test_concurrent_refresh_cannot_overwrite_a_new_observation(self):
        identity = self.observe_candidate()
        other = BaseChainSettlement(self.path, network_genesis=self.node.genesis, rpc=self.node)
        raced = False
        def racing(method, *params):
            nonlocal raced
            if method == "getblockheader" and params[0] == identity and not raced:
                raced = True
                other.refresh()
            return self.node(method, *params)
        self.observer.rpc = racing
        try:
            with self.assertRaisesRegex(ChainChanged, "another observer"):
                self.observer.refresh()
            self.assertEqual(self.observer.record(identity)["status"], "immature")
        finally:
            other.close()


if __name__ == "__main__":
    unittest.main()
