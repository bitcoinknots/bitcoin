#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent exact oracles and reproducibility checks for the calibration model."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
import itertools
from pathlib import Path
import statistics
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))

from tides_calibration import (ArrivalWindow, HASH_SPACE, ILLUSTRATIVE_BITS,
    MINER_WEIGHTS, Proof, REWARD, Scenario, analytic_profile, assigned_work,
    native_target, payouts_from_batches, share_layout_bytes, shares_per_native,
    simulate, stationary_allocation_rsd, summarize, target_shift_for_allocation_rsd,
    variance_decomposition)


class ExactWorkTests(unittest.TestCase):
    def test_known_bitcoin_compact_and_exact_power_assignment(self):
        self.assertEqual(native_target(0x1d00ffff), 65535 << 208)
        self.assertEqual(assigned_work(0x1d00ffff), 1 << 22)
        self.assertEqual(assigned_work(0x207fffff), 1)
        self.assertEqual(assigned_work(ILLUSTRATIVE_BITS), 1 << 68)
        self.assertEqual(shares_per_native(ILLUSTRATIVE_BITS, 14),
                         16 * shares_per_native(ILLUSTRATIVE_BITS, 10))

    def test_invalid_and_noncanonical_compacts(self):
        for bits in (0, -1, 1 << 32, True, 0x1d80ffff, 0x23000001, 0x02000100, 0x01000001):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                native_target(bits)

    def test_converter_and_exact_sizes_match_independent_native_codec(self):
        from hash_snapshot import EnvelopeV2, Share, share_target, rules_hash, TIDES_VERSION
        for bits in (0x207fffff, 0x1d00ffff, 0x18008000, 0x17034219, 0x01010000):
            self.assertEqual(share_target(bits, TIDES_VERSION),
                             HASH_SPACE // assigned_work(bits) - 1)
        for script in (b"\x00\x14" + b"a" * 20, b"\x51\x20" + b"b" * 32):
            envelope = EnvelopeV2(1, rules_hash(6), 3, 4, 5, b"c" * 32, script, version=6)
            proof = Share(b"\x00\x00\x00\x80" + bytes(160), envelope, bytes(64))
            self.assertEqual(len(proof.serialize()), sum(share_layout_bytes(len(script)).values()))
        self.assertEqual(sum(share_layout_bytes(22).values()), 512)
        self.assertEqual(sum(share_layout_bytes(34).values()), 524)

    def test_sampling_variance_matches_exhaustive_bernoulli_labels(self):
        # 2 full proofs plus half the oldest. Each of 8 owner assignments has
        # equal probability; no use of the model's payout calculation here.
        values = [(a / 2 + b + c) / 2.5 for a, b, c in itertools.product((0, 1), repeat=3)]
        exact_rsd = statistics.pstdev(values) / statistics.fmean(values)
        self.assertAlmostEqual(stationary_allocation_rsd(0.5, Fraction(5, 2)), exact_rsd)

    def test_profile_knob_is_explicit_and_resource_cost_scales(self):
        p10, p14 = (analytic_profile(ILLUSTRATIVE_BITS, n) for n in (10, 14))
        self.assertAlmostEqual(p14["minimum_unique_proof_bytes_per_day"],
                               p10["minimum_unique_proof_bytes_per_day"] * 16)
        self.assertEqual([target_shift_for_allocation_rsd(ILLUSTRATIVE_BITS, a, 0.05)
                          for a in MINER_WEIGHTS[:3]], [12, 16, 19])


class WindowTests(unittest.TestCase):
    def test_independent_arrival_oracle_and_rounding(self):
        window = ArrivalWindow(Fraction(5, 2))
        owners = [0, 1, 2, 0]
        for i, owner in enumerate(owners):
            window.append(i + 1, owner)
        # At t=4: owner0=1, owner2=1, owner1=0.5 of the window's 2.5.
        self.assertEqual(window.pay(4, 11, 3), {0: 4, 1: 2, 2: 4})
        self.assertEqual(window.pay(0, 11, 3), {3: 11})
        # Timestamp cutoff excludes newer work even though the object has it.
        self.assertEqual(window.pay(2, 11, 3), {0: 5, 1: 5})

    def test_numeric_boundary_and_proportional_comparator(self):
        old = [Proof(90, 0, 1, 1), Proof(10, 1, 1, 1)]
        new = [Proof(5, 2, 2, 2)]
        self.assertEqual(payouts_from_batches([old, new], Fraction(2), 100, 3), {0: 50, 2: 50})
        self.assertEqual(payouts_from_batches([old, new], Fraction(2), 100, 3, "proportional"),
                         {0: 25, 1: 25, 2: 50})
        flipped = [replace(p, proof_id=100 - p.proof_id) for p in old]
        self.assertNotEqual(payouts_from_batches([old, new], Fraction(2), 100, 3),
                            payouts_from_batches([flipped, new], Fraction(2), 100, 3))
        self.assertEqual(payouts_from_batches([old, new], Fraction(2), 100, 3, "proportional"),
                         payouts_from_batches([flipped, new], Fraction(2), 100, 3, "proportional"))

    def test_singleton_batches_equal_arrival_oracle_for_every_cutoff(self):
        window = ArrivalWindow(Fraction(11, 3))
        batches = []
        for i, owner in enumerate((0, 1, 0, 2, 3, 1, 2, 0, 0)):
            proof = Proof(i + 1, owner, i + 1, i + 1)
            batches.append([proof])
            window.append(i + 1, owner)
            for policy in ("numeric", "proportional"):
                self.assertEqual(window.pay(i + 1, 101, 3),
                    payouts_from_batches(batches, Fraction(11, 3), 101, 3, policy))

    def test_bootstrap_and_zero_floor(self):
        self.assertEqual(payouts_from_batches([], Fraction(2), 13, 1), {1: 13})
        proofs = [Proof(i + 1, i, 1, 1) for i in range(4)]
        self.assertEqual(payouts_from_batches([proofs], Fraction(4), 1, 3), {})
        self.assertEqual(payouts_from_batches([proofs], Fraction(4), 0, 3), {})


class CoupledSimulationTests(unittest.TestCase):
    def setUp(self):
        self.scenario = Scenario(pool_fraction=0.01, reference_shift=10,
                                 measured_pool_blocks=2, warmup_pool_blocks=1)

    def test_seed_replay_conserves_admitted_expired_and_pending_work(self):
        run = simulate(77, self.scenario)
        self.assertEqual(run, simulate(77, self.scenario))
        c = Counter(run["counts"])
        self.assertEqual(c["eligible_current_proofs"], c["admitted_current_proofs"] +
                         c["expired_current_proofs"] + c["remaining_current_proofs"])
        self.assertLessEqual(c["pool_native_solutions"],
                             c["eligible_current_proofs"] + c["stale_current_proofs"])
        self.assertEqual(run["payouts"]["same_target_arrival"], run["payouts"]["dense_arrival"])
        for label, pay in run["payouts"].items():
            total = sum(pay)
            self.assertLessEqual(total, REWARD * c["measured_pool_blocks"])
            self.assertLessEqual(REWARD * c["measured_pool_blocks"] - total, 4 * c["measured_pool_blocks"])

    def test_nonfinite_duration_and_invalid_budget_are_rejected(self):
        for settings in ({"measured_pool_blocks": float("nan")}, {"warmup_pool_blocks": float("inf")},
                         {"pool_fraction": True}, {"batch_limit": 1.5}, {"batch_limit": True}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                simulate(77, replace(self.scenario, **settings))

    def test_pool_only_expiry_is_not_hidden_by_reference(self):
        all_native = simulate(77, self.scenario)
        pool_only = simulate(77, replace(self.scenario, admission="pool-only"))
        a, b = Counter(all_native["counts"]), Counter(pool_only["counts"])
        self.assertEqual(a["pool_native_solutions"], b["pool_native_solutions"])
        self.assertEqual(all_native["payouts"]["same_target_arrival"], pool_only["payouts"]["same_target_arrival"])
        self.assertGreater(b["expired_current_proofs"], a["expired_current_proofs"])
        self.assertGreater(a["admitted_current_proofs"], b["admitted_current_proofs"])

    def test_saturated_queue_records_backpressure_and_expiry(self):
        run = simulate(77, replace(self.scenario, batch_limit=1))
        self.assertGreater(run["counts"]["deferred_proof_block_opportunities"], 0)
        self.assertGreater(run["counts"]["expired_current_proofs"], 0)

    def test_long_refresh_explicitly_loses_pool_solutions(self):
        run = simulate(77, replace(self.scenario, refresh_seconds=6000))
        self.assertGreater(run["counts"]["stale_pool_native_solutions"], 0)
        self.assertGreater(run["counts"]["stale_current_proofs"], 0)

    def test_native_find_is_same_share_event_and_excluded_from_frozen_job(self):
        # At this easy target every dense event is a current share. With a
        # refresh longer than the run, all jobs freeze at activation cutoff0;
        # accepted blocks therefore bootstrap their own recipient, and no proof
        # can appear in its own payout job. There is at most one accepted block.
        s = replace(self.scenario, bits=0x207fffff, pool_fraction=1,
                    reference_shift=10, refresh_seconds=1e9,
                    propagation_seconds=0, submission_seconds=0,
                    warmup_pool_blocks=0, measured_pool_blocks=10)
        run = simulate(77, s)
        c = Counter(run["counts"])
        self.assertEqual(c["dense_hash_success_events"],
                         c["eligible_current_proofs"] + c["stale_current_proofs"])
        self.assertEqual(c["measured_pool_blocks"], 1)
        self.assertEqual(sorted(run["payouts"]["numeric"]), [0, 0, 0, REWARD])

    def test_summary_resamples_independent_runs_and_keeps_covariance(self):
        runs = [simulate(seed, self.scenario) for seed in range(4)]
        summary = summarize(runs, self.scenario, 91)
        self.assertEqual(summary["runs"], 4)
        self.assertEqual(summary["measured_seconds_per_run"], 120000)
        for miner in summary["miners"]:
            comparison = miner["paired_comparisons"]["same_target_arrival_versus_dense_arrival"]
            self.assertEqual(comparison["paired_normalized_reward_difference"]["mean"], 0)
            ratio = comparison["sample_total_reward_variance_ratio"]
            self.assertIn(ratio, (None, 1))

    def test_variance_decomposition_retains_nonzero_covariance(self):
        values = variance_decomposition([2, 4, 7, 8], [2, 3, 5, 7])
        self.assertNotEqual(values["twice_block_luck_allocation_covariance"], 0)
        self.assertAlmostEqual(values["total_reward_variance"], values["fixed_split_block_luck_variance"] +
            values["allocation_residual_variance"] + values["twice_block_luck_allocation_covariance"])


if __name__ == "__main__":
    unittest.main()
