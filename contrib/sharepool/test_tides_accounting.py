#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact TIDES arithmetic and shared native vectors; no PoW or network claims."""

from collections import Counter, defaultdict
from dataclasses import FrozenInstanceError
import itertools
import json
from pathlib import Path
import unittest

from tides_accounting import (EmptyWindow, FEE_DENOMINATOR, IssuedJob, MAX_MONEY,
    MAX_WORK, OutputBudgetExceeded, PoolLog, Share, evaluate_job, is_payout_script,
    known_answer_vectors)


POOL_A, POOL_B, JOB_ID = b"A" * 32, b"B" * 32, b"J" * 32
ALICE, BOB, CAROL, OPERATOR = (b"\x00\x14" + bytes([number]) * 20 for number in range(1, 5))


def share(sequence, script=ALICE, work=1, *, pool=POOL_A, fee=0, proof_id=None):
    return Share(sequence, proof_id if proof_id is not None else sequence.to_bytes(32, "big"), pool, script, work, fee)


def log_of(shares, pool=POOL_A):
    log = PoolLog(pool)
    for value in shares:
        log.append(value)
    return log


def forward_oracle(rows, network_work, reward):
    """Independent interval intersections, not the implementation's reverse scan."""
    available = sum(int(row["work"]) for row in rows)
    requested, count = network_work * 8, min(available, network_work * 8)
    begin = available - count
    cursor, weights, selected = 0, defaultdict(int), []
    for row in rows:
        next_cursor = cursor + int(row["work"])
        overlap = max(0, next_cursor - max(begin, cursor))
        if overlap:
            weights[row["payout_script"]] += overlap
            selected.append((row["sequence"], overlap))
        cursor = next_cursor
    payouts = {script: reward * work // count for script, work in weights.items()}
    return {"window_work": str(requested), "eligible_work": str(count),
            "weights": {script: str(work) for script, work in weights.items()},
            "payouts": {script: amount for script, amount in payouts.items() if amount},
            "rounding_residue": reward - sum(payouts.values()),
            "oldest_sequence": selected[0][0], "oldest_work": str(selected[0][1])}


class TidesAccountingTest(unittest.TestCase):
    def test_shared_native_fixture_matches_independent_forward_oracle(self):
        path = Path(__file__).resolve().parents[2] / "src/test/data/sharepool_tides.json"
        fixtures = json.loads(path.read_text())
        self.assertEqual(fixtures, known_answer_vectors())
        self.assertEqual(len(fixtures["cases"]), 11)
        for case in fixtures["cases"]:
            with self.subTest(case=case["name"]):
                expected = forward_oracle(case["shares"], int(case["network_work"]),
                                          case["subsidy"] + case["transaction_fees"])
                self.assertEqual(case["expected"], expected)
                pool = bytes.fromhex(case["pool_id"])
                log = log_of([Share(row["sequence"], bytes.fromhex(row["proof_id"]), pool,
                                    bytes.fromhex(row["payout_script"]), int(row["work"]))
                              for row in case["shares"]], pool)
                result = evaluate_job(log.issue_job(JOB_ID, int(case["network_work"]),
                                                    case["subsidy"], case["transaction_fees"]))
                self.assertEqual(result.rounding_residue, expected["rounding_residue"])
                self.assertEqual({script.hex(): amount for script, amount in result.outputs}, expected["payouts"])

    def test_small_windows_equal_explicit_unit_expansion(self):
        for owners in itertools.product((ALICE, BOB), repeat=3):
            for amounts in itertools.product((1, 2, 3), repeat=3):
                log = log_of([share(index, owner, work) for index, (owner, work) in enumerate(zip(owners, amounts), 1)])
                units = [owner for owner, amount in zip(owners, amounts) for _ in range(amount)]
                expected = dict(Counter(units[-8:]))
                for reward in (0, 1, 101):
                    result = evaluate_job(log.issue_job(JOB_ID, 1, reward))
                    self.assertEqual({value.payout_script: value.work for value in result.address_rewards}, expected)
                    self.assertEqual(sum(amount for _, amount in result.outputs) + result.rounding_residue, reward)

    def test_startup_uses_available_work_denominator(self):
        result = evaluate_job(log_of([share(1, ALICE, 1), share(2, BOB, 3)]).issue_job(JOB_ID, 10, 100))
        self.assertEqual((result.requested_work, result.counted_work, result.available_work), (80, 4, 4))
        self.assertEqual(dict(result.outputs), {ALICE: 25, BOB: 75})

    def test_oldest_boundary_is_clipped_without_altering_distinct_record(self):
        old = share(1, ALICE, 4)
        log = log_of([old, share(2, BOB, 4), share(3, CAROL, 1)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 80))
        self.assertEqual([(item.share.sequence, item.included_work) for item in result.contributions], [(1, 3), (2, 4), (3, 1)])
        self.assertEqual(result.contributions[0].share, old)
        self.assertEqual(log.shares[0].work, 4)
        self.assertEqual(dict(result.outputs), {ALICE: 30, BOB: 40, CAROL: 10})

    def test_aggregate_same_payout_address_before_satoshi_floor(self):
        log = log_of([share(1, ALICE), share(2, BOB), share(3, ALICE)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 2))
        self.assertEqual(dict(result.outputs), {ALICE: 1})
        self.assertEqual([(value.payout_script, value.gross) for value in result.address_rewards], [(ALICE, 1), (BOB, 0)])
        self.assertEqual(result.rounding_residue, 1)

    def test_no_largest_remainder_bonus_or_fractional_balance(self):
        log = log_of([share(1, ALICE), share(2, BOB)])
        job = log.issue_job(JOB_ID, 1, 1)
        first, second = evaluate_job(job), evaluate_job(job)
        self.assertEqual(first, second)
        self.assertEqual(first.outputs, ())
        self.assertEqual(first.rounding_residue, 1)
        self.assertEqual(tuple(value.gross for value in first.address_rewards), (0, 0))

    def test_subsidy_and_transaction_fees_are_both_shared(self):
        result = evaluate_job(log_of([share(1, ALICE), share(2, BOB, 3)]).issue_job(JOB_ID, 4, 100, 12))
        self.assertEqual(result.job.reward, 112)
        self.assertEqual(dict(result.outputs), {ALICE: 28, BOB: 84})

    def test_issued_cutoff_cannot_be_padded_after_work_is_found(self):
        log = log_of([share(1, ALICE)])
        job = log.issue_job(JOB_ID, 1, 100)
        original = evaluate_job(job)
        log.append(share(2, BOB, 7))  # Could be the winning work or delayed work.
        self.assertEqual(job.cutoff_sequence, 1)
        self.assertEqual(job.cutoff_proof_id, share(1).proof_id)
        self.assertEqual(evaluate_job(job), original)
        newer = log.issue_job(b"K" * 32, 1, 100)
        self.assertEqual(dict(evaluate_job(newer).outputs), {ALICE: 12, BOB: 87})
        with self.assertRaises(FrozenInstanceError):
            job.transaction_fees = 999

    def test_repeated_blocks_do_not_reset_or_consume_window(self):
        log = log_of([share(1, ALICE, 8), share(2, BOB, 8)])
        before = log.shares
        first = evaluate_job(log.issue_job(JOB_ID, 2, 100))
        second = evaluate_job(log.issue_job(b"K" * 32, 2, 100))
        self.assertEqual(first.outputs, second.outputs)
        self.assertEqual(log.shares, before)
        self.assertEqual(dict(first.outputs), {ALICE: 50, BOB: 50})

    def test_difficulty_increase_recovers_older_history(self):
        log = log_of([share(1, ALICE, 8), share(2, BOB, 8)])
        lower = evaluate_job(log.issue_job(JOB_ID, 1, 100))
        higher = evaluate_job(log.issue_job(b"K" * 32, 2, 100))
        self.assertEqual(dict(lower.outputs), {BOB: 100})
        self.assertEqual(dict(higher.outputs), {ALICE: 50, BOB: 50})
        self.assertEqual(lower.contributions[0].share.sequence, 2)
        self.assertEqual(higher.contributions[0].share.sequence, 1)

    def test_pools_are_isolated_and_cross_pool_append_is_atomic(self):
        a = log_of([share(1, ALICE, 4)])
        b = log_of([share(1, BOB, 100, pool=POOL_B)], POOL_B)
        self.assertEqual(dict(evaluate_job(a.issue_job(JOB_ID, 1, 100)).outputs), {ALICE: 100})
        self.assertEqual(dict(evaluate_job(b.issue_job(JOB_ID, 1, 100)).outputs), {BOB: 100})
        before = a.shares
        with self.assertRaises(ValueError):
            a.append(share(2, CAROL, pool=POOL_B))
        self.assertEqual(a.shares, before)

    def test_duplicate_and_noncontiguous_admissions_are_rejected(self):
        log = log_of([share(1)])
        for invalid in (share(3), share(2, proof_id=share(1).proof_id)):
            with self.assertRaises(ValueError):
                log.append(invalid)
        self.assertEqual(log.shares, (share(1),))
        with self.assertRaises(ValueError):
            IssuedJob(JOB_ID, POOL_A, (share(1), share(3)), 1, 100, 0)

    def test_fee_flags_remain_individual_and_are_aggregated_by_address_and_rate(self):
        log = log_of([share(1, ALICE, 1, fee=10_000), share(2, ALICE, 1, fee=10_000),
                      share(3, ALICE, 2, fee=20_000), share(4, BOB, 4)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 1000, fee_recipient=OPERATOR))
        self.assertEqual(dict(result.outputs), {ALICE: 493, BOB: 500, OPERATOR: 7})
        self.assertEqual([(item.fee_ppm, item.work, item.amount) for item in result.fee_buckets if item.payout_script == ALICE],
                         [(10_000, 2, 2), (20_000, 2, 5)])
        self.assertEqual(result.rounding_residue, 0)
        with self.assertRaises(FrozenInstanceError):
            log.shares[0].fee_ppm = 0

    def test_fee_deductions_use_per_bucket_floors_and_do_not_take_rounding_residue(self):
        log = log_of([share(1, ALICE, fee=20_000), share(2, BOB)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 101, fee_recipient=OPERATOR))
        self.assertEqual(dict(result.outputs), {ALICE: 49, BOB: 50, OPERATOR: 1})
        self.assertEqual((result.operator_fee, result.rounding_residue), (1, 1))
        self.assertEqual(sum(amount for _, amount in result.outputs) + result.rounding_residue, 101)

    def test_fee_recipient_can_also_be_a_miner_and_gets_one_aggregate_output(self):
        log = log_of([share(1, ALICE, fee=FEE_DENOMINATOR), share(2, BOB)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 100, fee_recipient=BOB))
        self.assertEqual(dict(result.outputs), {BOB: 100})
        self.assertEqual(result.operator_fee, 50)
        self.assertEqual(result.address_rewards[0].net, 0)

    def test_output_budget_fails_complete_proposal_without_silently_omitting_miners(self):
        log = log_of([share(1, ALICE, fee=10_000), share(2, BOB)])
        before = log.shares
        with self.assertRaises(OutputBudgetExceeded):
            evaluate_job(log.issue_job(JOB_ID, 1, 1000, max_outputs=2, fee_recipient=OPERATOR))
        self.assertEqual(log.shares, before)
        result = evaluate_job(log.issue_job(JOB_ID, 1, 1000, max_outputs=3, fee_recipient=OPERATOR))
        self.assertEqual(len(result.outputs), 3)

    def test_empty_window_is_distinct_and_has_no_implicit_coordinator_payout(self):
        with self.assertRaises(EmptyWindow):
            evaluate_job(PoolLog(POOL_A).issue_job(JOB_ID, 1, 100))

    def test_zero_output_budget_only_allows_no_positive_entitlements(self):
        log = log_of([share(1)])
        result = evaluate_job(log.issue_job(JOB_ID, 1, 0, max_outputs=0))
        self.assertEqual((result.outputs, result.rounding_residue), ((), 0))
        with self.assertRaises(OutputBudgetExceeded):
            evaluate_job(log.issue_job(JOB_ID, 1, 1, max_outputs=0))

    def test_large_work_and_monetary_multiplication_are_exact(self):
        log = log_of([share(1, ALICE, MAX_WORK), share(2, BOB, MAX_WORK)])
        result = evaluate_job(log.issue_job(JOB_ID, 1 << 253, MAX_MONEY))
        self.assertEqual(result.counted_work, 1 << 256)
        self.assertEqual(result.contributions[0].included_work, 1)
        self.assertEqual(dict(result.outputs), {BOB: MAX_MONEY - 1})
        self.assertEqual(result.rounding_residue, 1)

    def test_only_supported_exact_script_shapes_are_accepted(self):
        scripts = (ALICE, b"\x76\xa9\x14" + b"a" * 20 + b"\x88\xac",
                   b"\xa9\x14" + b"a" * 20 + b"\x87", b"\x00\x20" + b"a" * 32,
                   b"\x51\x20" + b"a" * 32)
        self.assertTrue(all(is_payout_script(script) for script in scripts))
        for invalid in (b"\x51", bytearray(ALICE), "address", b"\x00\x14" + b"a" * 21):
            self.assertFalse(is_payout_script(invalid))
            with self.assertRaises(ValueError):
                share(1, invalid)

    def test_invalid_work_fees_reward_and_mutable_history_fail(self):
        for call in (lambda: share(1, work=0), lambda: share(1, work=MAX_WORK + 1),
                     lambda: share(True), lambda: share(1, fee=-1),
                     lambda: share(1, fee=FEE_DENOMINATOR + 1),
                     lambda: PoolLog(b"short"),
                     lambda: PoolLog(bytes(32)), lambda: share(1, proof_id=bytes(32)),
                     lambda: log_of([share(1)]).issue_job(bytes(32), 1, 100),
                     lambda: log_of([share(1, fee=1)]).issue_job(JOB_ID, 1, 100),
                     lambda: log_of([share(1)]).issue_job(JOB_ID, 1, MAX_MONEY, 1),
                     lambda: IssuedJob(JOB_ID, POOL_A, [share(1)], 1, 100, 0),
                     lambda: evaluate_job("unissued")):
            with self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
