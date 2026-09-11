#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial settlement/chain tests: simulation rules, not Knots consensus."""

from dataclasses import replace
from pathlib import Path
import random
from tempfile import TemporaryDirectory
import unittest

from proof_fixtures import make_share
from settlement_sim import (
    ANCHOR_HASH, MAX_SHARES, REWARD, Candidate, Node, SnapshotBundle,
    decode_coinbase, inclusion_proof, make_candidate, merkle_root, payout_plan, verify_inclusion,
)
from test_framework.messages import CTxInWitness


def bundle(parent=ANCHOR_HASH, height=1, tags=None, seed=0, previous=bytes(32), sequence=0):
    tags = tags if tags is not None else [f"node-{i:02}".encode() for i in range(12)]
    shares = tuple(make_share(tag, parent, height, nonce_seed=seed + i)
                   for i, tag in enumerate(tags))
    return SnapshotBundle(parent, height, shares, sequence=sequence, previous_settlement=previous)


def deliver(node, snapshot, block=None):
    block = block if block is not None else make_candidate(snapshot)
    node.supply_snapshot(snapshot.root, snapshot)
    return block, node.submit(block)


class SettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = bundle()
        cls.base_block = make_candidate(cls.base)

    def test_canonical_order_and_metadata_binding(self):
        original = self.base
        self.assertEqual(original.root, replace(original, shares=original.shares[::-1]).root)
        for changes in ({"parent_hash": ANCHOR_HASH + 1}, {"height": 2},
                        {"sequence": 1}, {"previous_settlement": b"x" * 32},
                        {"pool_id": b"other"}, {"network_id": b"other"},
                        {"reward": REWARD + 1}, {"shares": original.shares[:-1]}):
            with self.subTest(changes=changes.keys()):
                self.assertNotEqual(original.root, replace(original, **changes).root)

    def test_every_snapshot_leaf_has_count_bound_inclusion_proof(self):
        leaves, root = self.base.leaves, self.base.root
        for index, leaf in enumerate(leaves):
            with self.subTest(index=index):
                proof = inclusion_proof(leaves, index)
                self.assertTrue(verify_inclusion(leaf, index, len(leaves), proof, root))
                self.assertFalse(verify_inclusion(leaf + b"!", index, len(leaves), proof, root))
                self.assertFalse(verify_inclusion(leaf, index, len(leaves) + 1, proof, root))
                self.assertFalse(verify_inclusion(leaf, index, len(leaves), proof[:-1], root))
        self.assertNotEqual(merkle_root([b"a", b"b", b"c"]), merkle_root([b"a", b"b", b"c", b"c"]))
        self.assertFalse(verify_inclusion(b"", 0, 0, (), merkle_root([])))

    def test_wrong_peer_snapshot_cannot_poison_block_validity(self):
        node = Node("receiver")
        self.assertEqual(node.submit(self.base_block), "pending")
        wrong = replace(self.base, sequence=99)
        self.assertFalse(node.supply_snapshot(self.base.root, wrong))
        self.assertEqual(node.states[self.base_block.block_id], "pending")
        self.assertNotIn(self.base.root, node.snapshots)
        self.assertTrue(node.supply_snapshot(self.base.root, self.base))
        self.assertEqual(node.tip, self.base_block.block_id)

    def test_mutable_metadata_is_copied_and_cached_root_is_rechecked(self):
        previous = bytearray(b"x" * 32)
        invalid = replace(self.base, previous_settlement=previous)
        original_root = invalid.root
        candidate = make_candidate(invalid)
        node = Node("immutable-cache")
        self.assertEqual(deliver(node, invalid, candidate)[1], "invalid")
        previous[:] = bytes(32)
        self.assertEqual(invalid.root, original_root)
        node.revalidate()
        self.assertEqual(node.states[candidate.block_id], "invalid")
        receiver = Node("corrupt-cache")
        receiver.submit(self.base_block)
        receiver.snapshots[self.base.root] = replace(self.base, sequence=123)
        receiver.revalidate()
        self.assertEqual(receiver.states[self.base_block.block_id], "pending")
        self.assertEqual(receiver.reasons[self.base_block.block_id], "cached-snapshot-mismatch")
        receiver.supply_snapshot(self.base.root, self.base)
        self.assertEqual(receiver.tip, self.base_block.block_id)

    def test_wrong_coinbase_payload_can_be_replaced_by_authentic_payload(self):
        node = Node("receiver")
        other = make_candidate(self.base, payout_override=((b"attacker", REWARD),))
        self.assertEqual(node.submit(Candidate(self.base_block.header, other.coinbase)), "wrong-block-payload")
        self.assertNotIn(self.base_block.block_id, node.blocks)
        self.assertEqual(deliver(node, self.base, self.base_block)[1], "valid")

    def test_uncommitted_coinbase_witness_cannot_poison_header_id(self):
        node = Node("witness-mutation")
        node.supply_snapshot(self.base.root, self.base)
        tx = decode_coinbase(self.base_block.coinbase)
        original_txid = tx.sha256
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(32)]
        tx.rehash()
        self.assertEqual(tx.sha256, original_txid)
        mutated = Candidate(self.base_block.header, tx.serialize())
        self.assertEqual(mutated.block_id, self.base_block.block_id)
        self.assertEqual(node.submit(mutated), "wrong-block-payload")
        self.assertFalse(node.blocks)
        self.assertEqual(node.submit(self.base_block), "valid")

    def test_malformed_block_delivery_does_not_crash_or_poison_cache(self):
        node = Node("malformed")
        for candidate in (Candidate(b"", self.base_block.coinbase),
                          Candidate(self.base_block.header[:-1], self.base_block.coinbase),
                          Candidate(self.base_block.header, b""),
                          Candidate(self.base_block.header, self.base_block.coinbase[:-1])):
            with self.subTest(header_bytes=len(candidate.header), coinbase_bytes=len(candidate.coinbase)):
                self.assertEqual(node.submit(candidate), "wrong-block-payload")
                self.assertFalse(node.blocks)
        self.assertEqual(deliver(node, self.base, self.base_block)[1], "valid")

    def test_missing_snapshot_stalls_descendants_then_data_arrival_retries(self):
        child_snapshot = bundle(self.base_block.block_id, 2, previous=self.base.root)
        child = make_candidate(child_snapshot)
        node = Node("delayed")
        node.supply_snapshot(child_snapshot.root, child_snapshot)
        self.assertEqual(node.submit(child), "pending")
        self.assertEqual(node.reasons[child.block_id], "missing-parent")
        self.assertEqual(node.submit(self.base_block), "pending")
        self.assertEqual(node.states[child.block_id], "pending")
        self.assertEqual(node.tip, ANCHOR_HASH)
        self.assertEqual(node.balances, {})
        node.supply_snapshot(self.base.root, self.base)
        self.assertEqual(node.tip, child.block_id)
        self.assertEqual(sum(node.balances.values()), 2 * REWARD)

    def test_duplicate_share_is_invalid_committed_data(self):
        invalid = replace(self.base, shares=(*self.base.shares, self.base.shares[0]))
        block = make_candidate(invalid, payout_override=payout_plan(self.base))
        node = Node("duplicate")
        self.assertEqual(deliver(node, invalid, block)[1], "invalid")
        self.assertIn("duplicate", node.reasons[block.block_id])
        self.assertEqual(node.consumed_shares, set())

    def test_committed_forged_tag_or_coinbase_proof_is_invalid(self):
        for changes in ({"declared_tag": b"forged"}, {"coinbase": self.base.shares[1].coinbase}):
            with self.subTest(changes=changes.keys()):
                invalid_share = replace(self.base.shares[0], **changes)
                invalid = replace(self.base, shares=(invalid_share, *self.base.shares[1:]))
                block = make_candidate(invalid, payout_override=payout_plan(self.base))
                self.assertEqual(deliver(Node("binding"), invalid, block)[1], "invalid")

    def test_mined_job_refreshes_accumulate_against_absolute_tag_work_budget(self):
        # 13 valid distinct shares; one tag has work 4 against its budget of 2.
        tags = [s.declared_tag for s in self.base.shares] + [self.base.shares[0].declared_tag]
        over_budget = bundle(tags=tags, seed=100)
        self.assertEqual(len({s.share_id for s in over_budget.shares}), 13)
        node = Node("work-budget")
        block, state = deliver(node, over_budget)
        self.assertEqual(state, "invalid")
        self.assertEqual(node.reasons[block.block_id], "work-budget")

    def test_old_issued_snapshot_is_not_replaced_by_latest_or_local_inventory(self):
        node = Node("old-job")
        node.supply_snapshot(self.base.root, self.base)
        newer = bundle(seed=100, sequence=1)
        node.supply_snapshot(newer.root, newer)
        node.known_shares.update(s.share_id for s in newer.shares)
        self.assertEqual(node.submit(self.base_block), "valid")
        self.assertEqual(node.latest_snapshot, newer.root)
        self.assertEqual(node.consumed_shares, {s.share_id for s in self.base.shares})
        self.assertTrue(node.consumed_shares.isdisjoint(node.known_shares))

    def test_snapshot_context_must_match_block_chain_and_rules(self):
        for changes in ({"network_id": b"other-network"}, {"pool_id": b"other-pool"},
                        {"previous_settlement": b"x" * 32}, {"reward": REWARD + 1},
                        {"sequence": -1}, {"sequence": True}):
            with self.subTest(changes=changes):
                invalid = replace(self.base, **changes)
                block = make_candidate(invalid, payout_override=payout_plan(self.base))
                node = Node("context")
                self.assertEqual(deliver(node, invalid, block)[1], "invalid")
                self.assertEqual(node.reasons[block.block_id], "snapshot-context")

    def test_previous_window_share_cannot_be_replayed_in_child(self):
        invalid = replace(self.base, parent_hash=self.base_block.block_id, height=2,
                          previous_settlement=self.base.root)
        child = make_candidate(invalid, payout_override=payout_plan(self.base))
        node = Node("replay")
        deliver(node, self.base, self.base_block)
        self.assertEqual(deliver(node, invalid, child)[1], "invalid")
        self.assertEqual(node.tip, self.base_block.block_id)

    def test_payouts_reject_underpay_overpay_wrong_recipient_and_reallocation(self):
        correct = payout_plan(self.base)
        self.assertEqual(sum(amount for _, amount in correct), REWARD)
        self.assertEqual(payout_plan(replace(self.base, shares=self.base.shares[::-1])), correct)
        malformed = [((correct[0][0], correct[0][1] + delta), *correct[1:]) for delta in (-1, 1)]
        malformed += [((b"attacker", correct[0][1]), *correct[1:]),
                      ((correct[0][0], correct[0][1] + 1), (correct[1][0], correct[1][1] - 1), *correct[2:])]
        for payouts in malformed:
            with self.subTest(payouts=payouts[:2]):
                node = Node("payouts")
                block = make_candidate(self.base, payout_override=payouts)
                self.assertEqual(deliver(node, self.base, block)[1], "invalid")
                self.assertEqual(node.reasons[block.block_id], "payouts")

    def test_nonempty_work_can_pass_with_any_number_of_groups(self):
        # A lone tag may supply all recorded work; there is no percentage rule.
        for groups in (0, 1, 2, 9, 10, 12):
            with self.subTest(groups=groups):
                snapshot = bundle(tags=[f"group-{i}".encode() for i in range(groups)])
                block = make_candidate(snapshot, payout_override=((b"bootstrap", REWARD),)) if not groups else None
                self.assertEqual(deliver(Node("bootstrap"), snapshot, block)[1], "valid" if groups else "invalid")

    def test_absolute_budget_uses_rate_times_duration_and_allows_exact_boundary(self):
        snapshot = bundle(tags=[b"only-node", b"only-node"], seed=100)
        block = make_candidate(snapshot)  # Two shares credit work 4 to one tag.
        for rate, seconds, expected in ((1, 3, "invalid"), (1, 4, "valid"), (2, 2, "valid")):
            with self.subTest(rate=rate, seconds=seconds):
                node = Node("absolute-budget", cap_hashes_per_second=rate, window_seconds=seconds)
                self.assertEqual(deliver(node, snapshot, block)[1], expected)

    def test_omitted_work_can_conceal_a_tag_exceeding_its_absolute_budget(self):
        omitted = tuple(make_share(b"node-00", ANCHOR_HASH, 1, nonce_seed=100 + i) for i in range(12))
        full = replace(self.base, shares=(*self.base.shares, *omitted))
        node = Node("auditor")
        node.known_shares.update(s.share_id for s in full.shares)
        self.assertEqual(deliver(node, self.base, self.base_block)[1], "valid")
        self.assertEqual(deliver(Node("full-history"), full)[1], "invalid")

    def test_competing_proposals_are_not_automatically_invalid(self):
        alternative = bundle(seed=100)  # Same pool, parent, sequence, different root.
        node = Node("conflict")
        deliver(node, self.base, self.base_block)
        self.assertEqual(deliver(node, alternative)[1], "valid")
        self.assertTrue(node.conflicts)
        self.assertEqual(node.tip, self.base_block.block_id)
        self.assertEqual(sum(node.balances.values()), REWARD)

    def test_same_rules_tie_then_more_work_converges_and_undoes_old_settlement(self):
        other = bundle(tags=[f"other-{i}".encode() for i in range(12)], seed=100)
        other_block = make_candidate(other)
        left, right = Node("left"), Node("right")
        deliver(left, self.base, self.base_block)
        deliver(right, other, other_block)
        deliver(left, other, other_block)
        deliver(right, self.base, self.base_block)
        self.assertNotEqual(left.tip, right.tip)
        extension = bundle(other_block.block_id, 2, tags=[s.declared_tag for s in other.shares], previous=other.root)
        extension_block = make_candidate(extension)
        for node in (left, right):
            deliver(node, extension, extension_block)
        self.assertEqual(left.tip, right.tip)
        self.assertEqual(left.tip, extension_block.block_id)
        self.assertEqual(left.balances, right.balances)
        self.assertEqual(left.consumed_shares, right.consumed_shares)
        self.assertTrue({s.share_id for s in self.base.shares}.isdisjoint(left.consumed_shares))
        self.assertTrue({s.declared_tag for s in self.base.shares}.isdisjoint(left.balances))
        self.assertEqual(sum(left.balances.values()), 2 * REWARD)

    def test_more_chain_work_does_not_override_absolute_work_budget_validity(self):
        over_budget = bundle(tags=[s.declared_tag for s in self.base.shares] + [b"node-00"], seed=100)
        winner = make_candidate(over_budget)
        strict, relaxed = Node("strict"), Node("relaxed", cap_hashes_per_second=2, window_seconds=2)
        for node in (strict, relaxed):
            deliver(node, self.base, self.base_block)
            deliver(node, over_budget, winner)
        child_snapshot = bundle(winner.block_id, 2, previous=over_budget.root)
        child = make_candidate(child_snapshot)
        for node in (strict, relaxed):
            deliver(node, child_snapshot, child)
        self.assertEqual(strict.states[winner.block_id], "invalid")
        self.assertEqual(strict.reasons[child.block_id], "invalid-ancestor")
        self.assertEqual(strict.tip, self.base_block.block_id)
        self.assertEqual(relaxed.tip, child.block_id)

    def test_different_absolute_budgets_reconverge_on_more_work_common_valid_branch(self):
        over_budget = bundle(tags=[s.declared_tag for s in self.base.shares] + [b"node-00"], seed=100)
        rejected_root = make_candidate(over_budget)
        relaxed_child_snapshot = bundle(rejected_root.block_id, 2, previous=over_budget.root)
        relaxed_child = make_candidate(relaxed_child_snapshot)
        strict, relaxed = Node("strict"), Node("relaxed", cap_hashes_per_second=2, window_seconds=2)
        for node in (strict, relaxed):
            deliver(node, self.base, self.base_block)
            deliver(node, over_budget, rejected_root)
            deliver(node, relaxed_child_snapshot, relaxed_child)
        self.assertNotEqual(strict.tip, relaxed.tip)

        common_child_snapshot = bundle(self.base_block.block_id, 2, previous=self.base.root)
        common_child = make_candidate(common_child_snapshot)
        for node in (strict, relaxed):
            deliver(node, common_child_snapshot, common_child)
        self.assertEqual(strict.tip, common_child.block_id)
        self.assertEqual(relaxed.tip, relaxed_child.block_id)  # Equal work retains its old branch.

        common_tip_snapshot = bundle(common_child.block_id, 3, previous=common_child_snapshot.root)
        common_tip = make_candidate(common_tip_snapshot)
        for node in (strict, relaxed):
            deliver(node, common_tip_snapshot, common_tip)
        self.assertEqual(strict.tip, common_tip.block_id)
        self.assertEqual(strict.tip, relaxed.tip)
        self.assertEqual(strict.balances, relaxed.balances)
        self.assertEqual(strict.consumed_shares, relaxed.consumed_shares)
        self.assertEqual(sum(relaxed.balances.values()), 3 * REWARD)
        self.assertTrue({s.share_id for s in over_budget.shares}.isdisjoint(relaxed.consumed_shares))
        self.assertEqual(strict.states[rejected_root.block_id], "invalid")
        self.assertEqual(relaxed.states[rejected_root.block_id], "valid")

    def test_repeated_delivery_and_persistence_do_not_double_settle(self):
        node = Node("persistent", cap_hashes_per_second=2, window_seconds=3)
        deliver(node, self.base, self.base_block)
        expected_balances, expected_consumed = dict(node.balances), set(node.consumed_shares)
        for _ in range(3):
            deliver(node, self.base, self.base_block)
            node.revalidate()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "node.json"
            node.save(path)
            restored = Node.restore(path)
        self.assertEqual(restored.tip, node.tip)
        self.assertEqual(restored.cap_hashes_per_second, 2)
        self.assertEqual(restored.window_seconds, 3)
        self.assertEqual(restored.balances, expected_balances)
        self.assertEqual(restored.consumed_shares, expected_consumed)

    def test_snapshot_bound_limits_admission(self):
        with self.assertRaises(ValueError):
            replace(self.base, shares=(self.base.shares[0],) * (MAX_SHARES + 1))

    def test_fifty_delivery_permutations_converge_without_double_settlement(self):
        alternate = bundle(tags=[f"alternate-{i}".encode() for i in range(12)])
        alternate_block = make_candidate(alternate)
        child_snapshot = bundle(self.base_block.block_id, 2, previous=self.base.root)
        child = make_candidate(child_snapshot)
        messages = [("block", b) for b in (self.base_block, alternate_block, child)]
        messages += [("snapshot", s) for s in (self.base, alternate, child_snapshot)]
        messages += [("block", child), ("snapshot", self.base)]
        expected = Node("reference")
        deliver(expected, self.base, self.base_block)
        deliver(expected, child_snapshot, child)
        for seed in range(50):
            with self.subTest(seed=seed):
                shuffled = list(messages)
                random.Random(seed).shuffle(shuffled)
                node = Node("permutation-" + str(seed))
                for kind, payload in shuffled:
                    if kind == "block":
                        node.submit(payload)
                    else:
                        node.supply_snapshot(payload.root, payload)
                self.assertEqual(node.tip, child.block_id)
                self.assertEqual(node.balances, expected.balances)
                self.assertEqual(node.consumed_shares, expected.consumed_shares)


if __name__ == "__main__":
    unittest.main()
