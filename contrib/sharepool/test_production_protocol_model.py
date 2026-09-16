#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Finite model checks; no native consensus or deployment assertions."""

from collections import Counter
import itertools
import unittest

from production_protocol_model import (BoundedCarry, Credit, Event, Membership,
    Miner, accounting_scope, allocate_reward, coupled_trace, experiment,
    reference_weights, replay, rolling_weights)


def share(number, owner="alice", scope="A", work=1, block=False, native_work=8):
    return Event(number, float(number), owner, scope, work, native_work, block, f"{number:064x}")


class ProductionProtocolModelTest(unittest.TestCase):
    def test_stable_script_scope_and_cross_chain_separation(self):
        chain, anchor = bytes(32), b"\x00\x14" + b"a" * 20
        scope = accounting_scope(chain, anchor)
        self.assertEqual(scope, accounting_scope(chain, anchor))
        self.assertNotEqual(scope, accounting_scope(bytes([1]) * 32, anchor))
        self.assertNotEqual(scope, accounting_scope(chain, b"\x00\x14" + b"b" * 20))

    def test_same_member_cannot_relabel_or_redirect_job_scope(self):
        registry = Membership()
        member = b"\x00\x14" + b"m" * 20
        first, second = accounting_scope(bytes(32), b"anchor-A"), accounting_scope(bytes(32), b"anchor-B")
        registry.register(member, first)
        registry.register(member, first)
        registry.check_job(member, first)
        with self.assertRaisesRegex(ValueError, "migration"):
            registry.register(member, second)
        with self.assertRaisesRegex(ValueError, "anchored membership"):
            registry.check_job(member, second)
        with self.assertRaises(ValueError):
            registry.check_job(b"unregistered", first)

    def test_capacity_backpressure_preserves_old_and_defers_canonical_prefix(self):
        ledger = BoundedCarry(25)
        older = Credit(1, 20, "abandoned", "old", 5, 10)
        ledger.admit_prefix([older])
        candidates = [Credit(2, 3, "A", "alice", 1, 10), Credit(2, 1, "A", "bob", 1, 10)]
        accepted, deferred = ledger.admit_prefix(candidates)
        self.assertEqual([credit.proof_id for credit in accepted], [1])
        self.assertEqual([credit.proof_id for credit in deferred], [3])
        self.assertEqual(ledger.pending, [older, candidates[1]])
        self.assertEqual(ledger.used, 20)

    def test_abandoned_pool_can_saturate_fixed_state_indefinitely(self):
        ledger = BoundedCarry(30)
        abandoned = [Credit(1, number, f"abandoned-{number}", "old", 1, 10) for number in range(3)]
        ledger.admit_prefix(abandoned)
        newcomer = Credit(100, 20, "live", "new", 1, 10)
        for _ in range(100):
            self.assertEqual(ledger.settle("live", 30, 100), ([], {}))
            self.assertEqual(ledger.admit_prefix([newcomer]), ([], [newcomer]))
            self.assertEqual(ledger.pending, abandoned)

    def test_settlement_only_spends_selected_pool_prefix_and_never_readmits(self):
        ledger = BoundedCarry(100)
        credits = [Credit(1, 1, "A", "alice", 1, 10), Credit(1, 2, "B", "bob", 3, 10),
                   Credit(2, 3, "A", "carol", 3, 10)]
        ledger.admit_prefix(credits)
        selected, payout = ledger.settle("A", 10, 100)
        self.assertEqual(selected, [credits[0]])
        self.assertEqual(payout, {"alice": 100})
        self.assertEqual(ledger.pending, credits[1:])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ledger.admit_prefix([credits[0]])

    def test_invalid_batch_does_not_partially_mutate(self):
        ledger = BoundedCarry(100)
        credit = Credit(1, 1, "A", "alice", 1, 10)
        with self.assertRaises(ValueError):
            ledger.admit_prefix([credit, credit])
        self.assertEqual(ledger.pending, [])
        self.assertEqual(ledger.admitted_ids, set())

    def test_weighted_windows_match_expanded_unit_oracle(self):
        for owners in itertools.product(("alice", "bob"), repeat=3):
            for amounts in itertools.product((1, 2, 3), repeat=3):
                history = [share(index, owner, work=work) for index, (owner, work) in enumerate(zip(owners, amounts))]
                units = [owner for owner, work in zip(owners, amounts) for _ in range(work)]
                for window in range(1, 11):
                    expected = dict(Counter(units[-window:]))
                    self.assertEqual(rolling_weights(history, window), expected)
                    self.assertEqual(reference_weights(history, window), expected)

    def test_reward_rounding_conserves_every_satoshi_without_cross_pool_payment(self):
        for reward in (0, 1, 2, 101, 5_000_000_200):
            payouts = allocate_reward({"alice": 1, "bob": 1, "carol": 1}, reward)
            self.assertEqual(sum(payouts.values()), reward)
            self.assertLessEqual(max(payouts.values(), default=0) - min(payouts.values(), default=0), 1)
        self.assertEqual(allocate_reward({"bob": 1, "alice": 1}, 1), {"alice": 1})

    def test_winning_work_is_not_in_own_block_or_next_parent_cutoff(self):
        trace = [share(1, "alice"), share(2, "bob", block=True),
                 share(3, "carol", block=True), share(4, "dave", block=True)]
        result = replay(trace, reward=120)
        first, second, third = result["blocks"]
        self.assertEqual(first["admitted_ids"], [trace[0].proof_id])
        self.assertNotIn(trace[1].proof_id, first["admitted_ids"])
        self.assertEqual(result["admission_heights"][trace[1].proof_id], 2)
        self.assertEqual(second["payouts"]["parent_cutoff"], {"alice": 120})
        self.assertEqual(third["payouts"]["parent_cutoff"], {"alice": 60, "bob": 60})
        self.assertEqual([block["payout_cutoff_height"] for block in result["blocks"]], [0, 1, 2])

    def test_native_parent_and_live_cutoffs_are_not_conflated(self):
        result = replay([share(1, "alice"), share(2, "bob", block=True)], reward=10)
        block = result["blocks"][0]
        self.assertEqual(block["payouts"]["parent_cutoff"], {"bob": 10})
        self.assertEqual(block["payouts"]["live_cutoff"], {"alice": 10})
        self.assertIn("parent_cutoff", block["fallback_policies"])

    def test_pool_a_admission_in_b_block_does_not_spend_b_reward(self):
        trace = [share(1, "alice", "A"), share(2, "bob", "B", block=True),
                 share(3, "carol", "A", block=True)]
        result = replay(trace, reward=10)
        self.assertEqual(result["blocks"][0]["payouts"]["parent_cutoff"], {"bob": 10})
        self.assertEqual(result["blocks"][1]["payouts"]["parent_cutoff"], {"alice": 10})

    def test_rolling_entitlement_can_leave_window_without_ever_being_paid(self):
        trace = [share(1, "alice", "A"), share(2, "carol", "B", block=True)]
        trace += [share(number, "bob", "A") for number in range(3, 11)]
        trace += [share(11, "carol", "B", block=True), share(12, "bob", "A", block=True)]
        result = replay(trace, window_blocks=1, reward=100)
        self.assertIn(trace[0].proof_id, result["admission_heights"])
        self.assertEqual(result["blocks"][-1]["payouts"]["parent_cutoff"], {"bob": 100})
        self.assertEqual(result["totals"]["parent_cutoff"].get("alice", 0), 0)

    def test_native_winners_are_same_hash_events_at_every_easier_share_target(self):
        easy = list(coupled_trace(17, 32, (Miner("alice", "A", 1.0, 1),), 32))
        hard = list(coupled_trace(17, 32, (Miner("alice", "A", 1.0, 8),), 32))
        self.assertLess(len(hard), len(easy))
        self.assertGreater(sum(event.is_block for event in hard), 0)
        self.assertEqual([(event.event_id, event.time) for event in easy if event.is_block],
                         [(event.event_id, event.time) for event in hard if event.is_block])
        easy_ids = {event.event_id for event in easy}
        self.assertTrue(all(event.event_id in easy_ids for event in hard))

    def test_same_admitted_cutoff_has_exact_per_block_parity_on_coupled_traces(self):
        miners = (Miner("alice", "A", 0.2, 1), Miner("bob", "A", 0.3, 4), Miner("carol", "B", 0.5, 2))
        for budget in (None, 3):
            result = replay(coupled_trace(330, 16, miners, 32), admission_limit=budget)
            self.assertGreater(len(result["blocks"]), 0)
            for block in result["blocks"]:
                self.assertEqual(block["payouts"]["parent_cutoff"], block["payouts"]["same_cutoff_reference"])
                self.assertEqual(sum(block["payouts"]["parent_cutoff"].values()), 1_000_000)
            self.assertEqual(result["accepted_proofs"], result["anchored_proofs"] + len(result["unanchored_proof_ids"]))

    def test_capacity_carry_uses_earlier_interval_before_later_hash_order(self):
        trace = [share(5), share(2), share(9, block=True), share(1), share(10, block=True), share(11, block=True)]
        result = replay(trace, admission_limit=1)
        self.assertEqual([block["admitted_ids"] for block in result["blocks"]],
                         [[trace[1].proof_id], [trace[0].proof_id], [trace[3].proof_id]])
        self.assertEqual(result["accepted_proofs"], result["anchored_proofs"] + len(result["unanchored_proof_ids"]))

    def test_difficulty_increase_can_require_previously_outside_history(self):
        history = [share(1, "alice", work=4), share(2, "bob", work=4)]
        self.assertEqual(rolling_weights(history, 4), {"bob": 4})
        self.assertEqual(rolling_weights(history, 8), {"alice": 4, "bob": 4})
        trace = list(coupled_trace(42, 2, (Miner("alice", "A", 1.0),), 16, ((600, 32),)))
        self.assertTrue(any(event.time < 600 and event.native_work == 16 for event in trace))
        self.assertTrue(any(event.time >= 600 and event.native_work == 32 for event in trace))

    def test_report_labels_backlog_and_variance_evidence_limits(self):
        result = experiment(seed=7, trials=2, intervals=4, base_resolution=16)
        self.assertEqual(len(result["cases"]), 4)
        for case in result["cases"]:
            self.assertEqual(case["same_cutoff_mismatched_block_payouts"], 0)
            self.assertEqual(case["total_accepted_proofs"], case["total_anchored_proofs"] + case["total_unanchored_at_end"])
        self.assertIn("no native node or ASIC", result["kind"])
        self.assertIn("empty", result["initial_history"])

    def test_invalid_targets_duplicates_and_budgets(self):
        for call in (lambda: list(coupled_trace(1, 1, (Miner("alice", "A", 0.5),), 8)),
                     lambda: list(coupled_trace(1, 1, (Miner("alice", "A", 1, 9),), 8)),
                     lambda: replay([share(1), share(1)]), lambda: replay([], admission_limit=0),
                     lambda: allocate_reward({}, 10), lambda: BoundedCarry(0),
                     lambda: experiment(trials=513), lambda: accounting_scope(b"short", b"script")):
            with self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
