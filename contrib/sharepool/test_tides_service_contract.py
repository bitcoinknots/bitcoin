#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent oracle checks for accelerated candidate variance calibration."""

from dataclasses import replace
from fractions import Fraction
import itertools
import unittest

from tides_calibration import MINER_WEIGHTS, REWARD, Proof, Scenario, payouts_from_batches, shares_per_native, simulate
from tides_service_contract import CachedCohortPayouts, capacity_bounds, capacity_predicates, compact_size_length, compare_to_ideal, run_fast


class CohortCacheTests(unittest.TestCase):
    def test_all_prefixes_cutoffs_policies_and_owners_match_simple_oracle(self):
        for labels in itertools.product((0, 1), repeat=5):
            proofs = [Proof(i + 1, owner, i + 1, i // 2 + 1) for i, owner in enumerate(labels)]
            batches = [[], proofs[:2], [], proofs[2:4], proofs[4:], []]
            cache = CachedCohortPayouts()
            for end in range(1, len(batches) + 1):
                for size in (Fraction(1, 3), Fraction(1), Fraction(5, 2), Fraction(4), Fraction(9)):
                    for policy in ("numeric", "proportional"):
                        self.assertEqual(cache(batches[:end], size, 101, 3, policy),
                                         payouts_from_batches(batches[:end], size, 101, 3, policy))

    def test_replaced_prefix_and_shorter_branch_reset_derived_state(self):
        left = [[Proof(3, 0, 1, 1)], [Proof(1, 1, 2, 2)]]
        right = [[Proof(4, 2, 1, 1)], left[1]]
        cache = CachedCohortPayouts()
        for batches in (left, right, right[:1], left, [[]], []):
            for policy in ("numeric", "proportional"):
                self.assertEqual(cache(batches, Fraction(3, 2), 101, 3, policy),
                                 payouts_from_batches(batches, Fraction(3, 2), 101, 3, policy))

    def test_fractional_cohort_contributions_are_floored_only_after_aggregation(self):
        batches = [[Proof(1, 0, 1, 1), Proof(2, 1, 1, 1)], [Proof(3, 0, 2, 2)]]
        # One current share plus half of a two-share older cohort gives owner0
        # weight1.5/2, not floor(1/2)+floor(.5/2) separately.
        self.assertEqual(CachedCohortPayouts()(batches, Fraction(2), 3, 3, "proportional"), {0: 2})

    def test_cached_and_original_coupled_simulations_are_byte_equivalent(self):
        for shift in (10, 12, 14):
            scenario = Scenario(share_shift=shift, reference_shift=14, pool_fraction=0.1,
                                batch_limit=7, warmup_pool_blocks=0.5, measured_pool_blocks=0.5)
            self.assertEqual(run_fast(37, scenario), simulate(37, scenario))

    def test_same_target_reference_alias_does_not_double_credit(self):
        scenario = Scenario(share_shift=14, reference_shift=14, pool_fraction=1,
                            warmup_pool_blocks=0, measured_pool_blocks=1)
        result = run_fast(37, scenario)
        self.assertEqual(result["payouts"]["same_target_arrival"], result["payouts"]["dense_arrival"])


class ContractTests(unittest.TestCase):
    def test_identical_ideal_rewards_have_unit_ratio_and_zero_difference(self):
        s = Scenario(measured_pool_blocks=10)
        runs = []
        for blocks in (8, 9, 10, 11, 12, 13, 14, 15):
            amounts = [int(REWARD * weight) * blocks for weight in MINER_WEIGHTS]
            runs.append({"payouts": {"proportional": amounts, "ideal_fixed_split": amounts}})
        for result in compare_to_ideal(runs, s, 71, resamples=64):
            self.assertEqual(result["sample_total_reward_variance_ratio_to_ideal"], 1)
            self.assertEqual(result["whole_run_bootstrap_95_percent_variance_ratio_interval"], [1, 1])
            self.assertEqual(result["paired_reward_difference_normalized_to_expected"]["mean"], 0)
            self.assertTrue(result["variance_interval_within_engineering_target"])
            self.assertTrue(result["mean_interval_within_engineering_target"])

    def test_capacity_wire_uses_compact_indexes_and_distinguishes_shared_table(self):
        workload = dict(proof_count=100, expanded_bytes_per_origin=100_000,
                        transaction_references_per_origin=200)
        disjoint = capacity_predicates(**workload)
        shared = capacity_predicates(**workload, transaction_reuse="all_noncoinbase_shared")
        self.assertEqual(disjoint["demand"]["transaction_references"], 20_000)
        self.assertEqual(disjoint["demand"]["expanded_template_bytes"], 10_000_000)
        self.assertEqual(disjoint["demand"]["snapshot_wire_lower_bound_bytes"],
                         51200 + 100 * (32 + 164 + 1) + 20000 + 100 * (100000 - 165) + 20000)
        self.assertEqual(shared["demand"]["expanded_template_bytes"], 10_000_000)
        self.assertLess(shared["demand"]["snapshot_wire_lower_bound_bytes"],
                        disjoint["demand"]["snapshot_wire_lower_bound_bytes"])
        self.assertFalse(shared["sufficient_for_native_admission"])

    def test_coinbase_only_bodies_cannot_share_part_of_the_coinbase(self):
        workload = dict(proof_count=100, expanded_bytes_per_origin=512, transaction_references_per_origin=1)
        disjoint = capacity_predicates(**workload)
        shared = capacity_predicates(**workload, transaction_reuse="all_noncoinbase_shared")
        self.assertEqual(shared["assumptions"]["unique_coinbase_bytes_per_origin"], 347)
        self.assertEqual(shared["demand"], disjoint["demand"])

    def test_origin_ceiling_does_not_round_large_integer_counts_through_float(self):
        count = (1 << 53) + 1
        result = capacity_predicates(count, expanded_bytes_per_origin=512,
                                     transaction_references_per_origin=1, proofs_per_origin=2)
        self.assertEqual(result["demand"]["origins"], (count + 1) // 2)

    def test_capacity_rejects_workload_at_each_actual_constraint(self):
        origin = capacity_predicates(2049, expanded_bytes_per_origin=512, transaction_references_per_origin=1)
        self.assertFalse(origin["necessary_predicates"]["origins"])
        expanded = capacity_predicates(135, expanded_bytes_per_origin=4_000_000,
                                       transaction_references_per_origin=1000,
                                       transaction_reuse="all_noncoinbase_shared")
        self.assertFalse(expanded["necessary_predicates"]["expanded_template_bytes"])
        refs = capacity_predicates(1001, expanded_bytes_per_origin=100_000,
                                   transaction_references_per_origin=2000,
                                   transaction_reuse="all_noncoinbase_shared")
        self.assertFalse(refs["necessary_predicates"]["transaction_references"])
        wire = capacity_predicates(200, expanded_bytes_per_origin=100_000, transaction_references_per_origin=200)
        self.assertFalse(wire["necessary_predicates"]["snapshot_wire_lower_bound_bytes"])
        self.assertFalse(wire["not_ruled_out_by_necessary_bounds"])

    def test_capacity_invalid_assumptions_and_compact_boundaries(self):
        self.assertEqual([compact_size_length(n) for n in (0, 252, 253, 65535, 65536, 2**32)], [1, 1, 3, 3, 5, 9])
        for value in (-1, 1.0, True, 2**64):
            with self.assertRaises(ValueError):
                compact_size_length(value)
        for count in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                capacity_predicates(count, expanded_bytes_per_origin=512, transaction_references_per_origin=1)
        with self.assertRaises(ValueError):
            capacity_predicates(1, expanded_bytes_per_origin=200, transaction_references_per_origin=100)

    def test_density_range_covers_compact_target_rounding_positions(self):
        for shift in (10, 12, 14):
            for bits in (0x17034219, 0x17040000, 0x1707ffff, 0x18012345, 0x1d00ffff):
                density = shares_per_native(bits, shift)
                self.assertGreaterEqual(density, 1 << shift)
                self.assertLess(density, 1 << (shift + 1))

    def test_capacity_reports_all_native_limits_not_only_proof_count(self):
        rows = capacity_bounds()
        self.assertEqual([row["shift"] for row in rows], [10, 12, 14])
        for row in rows:
            density = row["proof_density_interval_away_from_easy_target_clamp"]
            self.assertGreaterEqual(row["proofs_per_expected_native_block"], density["inclusive_lower"])
            self.assertLess(row["proofs_per_expected_native_block"], density["exclusive_upper"])
            self.assertEqual(len(row["workload_feasibility_predicates"]), 16)
            full = row["examples_distinct_full_bodies"][-1]
            self.assertEqual(full["maximum_origins_by_512MiB_expanded_limit"], 134)
            self.assertLess(full["maximum_fraction_of_mean_proofs_if_every_proof_has_new_origin"], 0.11)
            self.assertLess(row["current_2million_reference_budget_mean_references_per_unique_job"], 2000)
        self.assertAlmostEqual(rows[2]["minimum_unique_proof_bytes_per_day"],
                               rows[0]["minimum_unique_proof_bytes_per_day"] * 16)


if __name__ == "__main__":
    unittest.main()
