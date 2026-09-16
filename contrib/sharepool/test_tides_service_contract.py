#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent oracle checks for accelerated candidate variance calibration."""

from dataclasses import replace
from fractions import Fraction
import itertools
import math
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))

from tides_calibration import MINER_WEIGHTS, REWARD, Proof, Scenario, payouts_from_batches, shares_per_native, simulate
from tides_service_contract import (CachedCohortPayouts, capacity_bounds, capacity_predicates,
    compact_size_length, compare_to_ideal, geometric_sum_quantile, resource_budget_report,
    run_fast, v6_dependency_resources, v6_history_resources, v6_mean_origin_envelope,
    v6_snapshot_resources)


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


class ResourceBudgetTests(unittest.TestCase):
    def test_geometric_quantiles_match_exact_fair_coin_binomial_tail(self):
        for count in range(1, 9):
            for probability in (0.5, 0.9, 0.99):
                actual = geometric_sum_quantile(2, count, probability)
                def cdf(n):
                    return 1 - sum(Fraction(math.comb(n, j), 2**n) for j in range(count))
                self.assertGreaterEqual(cdf(actual), Fraction(str(probability)))
                self.assertLess(cdf(actual - 1), Fraction(str(probability)))
        self.assertEqual(geometric_sum_quantile(1, 8), 8)
        self.assertEqual(geometric_sum_quantile(20114.210697376002), 92628)

    def test_origin_free_opening_matches_real_codec_across_count_prefixes(self):
        from hash_snapshot import EnvelopeV2, OriginCertificate, Snapshot, StateEntry, rules_hash
        from test_framework.messages import CTxOut, ser_uint256
        for script_size in (22, 34):
            prefix = b"\x00\x14" if script_size == 22 else b"\x51\x20"
            script = prefix + bytes(script_size - 2)
            envelope = EnvelopeV2(1, rules_hash(6), 4, 5, 6, bytes(32), script, version=6)
            for count in (0, 1, 252, 253):
                state = tuple(StateEntry(4, i) for i in range(count))
                certs = tuple(sorted((OriginCertificate(4, 5, i, i + 1) for i in range(count)),
                                     key=lambda c: ser_uint256(c.identity)))
                payouts = tuple(CTxOut(1, prefix + i.to_bytes(script_size - 2, "big")) for i in range(count))
                snapshot = Snapshot(envelope, bytes(64), post_state=state, payouts=payouts, certificates=certs)
                size = len(snapshot.serialize())
                estimate = v6_snapshot_resources(proofs=0, recent_proofs=count, origins=0,
                    recent_origins=count, recipients=count, script_bytes=script_size)
                self.assertEqual(estimate["bytes"]["snapshot_lower"], size)
                self.assertEqual(estimate["bytes"]["snapshot_upper"], size)

    def test_shared_table_bounds_and_coinbase_multiplier_match_real_transactions(self):
        from hash_snapshot import EnvelopeV2, Snapshot, TemplateRecord, rules_hash
        from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
        from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, ser_uint256
        for script_size in (22, 34):
            prefix = b"\x00\x14" if script_size == 22 else b"\x51\x20"
            for recipients in (3, 253):
                payouts = tuple(CTxOut(1, prefix + i.to_bytes(script_size - 2, "big")) for i in range(recipients))
                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(2, 0))]
                tx.vout = [CTxOut(1, payouts[0].scriptPubKey)]
                records, body_size, coinbase_size = [], None, None
                for number in range(5):
                    coinbase = create_coinbase(4)
                    coinbase.vin[0].scriptSig = bytes([number]) * 100
                    coinbase.vout = list(payouts)
                    block = create_block(5, coinbase, 6, height=4, header_v2=True, txlist=[tx])
                    add_witness_commitment(block)
                    coinbase_size = len(block.vtx[0].serialize_with_witness())
                    body_size = len(block.serialize())
                    records.append(TemplateRecord.from_block(block))
                records.sort(key=lambda t: ser_uint256(t.template_id))
                envelope = EnvelopeV2(1, rules_hash(6), 4, 5, 6, bytes(32), bytes(payouts[0].scriptPubKey), version=6)
                snapshot = Snapshot(envelope, bytes(64), templates=tuple(records), payouts=payouts)
                estimate = v6_snapshot_resources(proofs=0, recent_proofs=0, origins=5,
                    recent_origins=0, recipients=recipients, script_bytes=script_size,
                    body_bytes=body_size, noncoinbase_transactions=1)
                self.assertEqual(estimate["bytes"]["coinbase_per_origin_raw"], coinbase_size)
                self.assertEqual(estimate["bytes"]["unique_coinbases_raw"], 5 * coinbase_size)
                self.assertLessEqual(estimate["bytes"]["snapshot_lower"], len(snapshot.serialize()))
                self.assertGreaterEqual(estimate["bytes"]["snapshot_upper"], len(snapshot.serialize()))

    def test_certified_openings_remain_charged_and_future_job_reserves_one_origin(self):
        root = v6_snapshot_resources(proofs=100, recent_proofs=400, origins=2,
                                    recent_origins=8, recipients=3)
        opening = v6_snapshot_resources(proofs=0, recent_proofs=300, origins=0,
                                       recent_origins=6, recipients=3)
        graph = v6_dependency_resources(root, root, opening)
        self.assertEqual(graph["charged_origin_count_with_future_reservation"], 3)
        self.assertEqual(graph["depth_with_future_reservation"], 2)
        self.assertEqual(graph["closure_upper_bytes"],
                         2 * root["bytes"]["snapshot_upper"] + 2 * opening["bytes"]["snapshot_upper"])
        larger = v6_dependency_resources(root, root, opening, extra_origins=2046,
                                         extra_dependency_bytes=64 * 1024 * 1024, depth=64)
        self.assertFalse(larger["predicates"]["origins_within_2048"])
        self.assertFalse(larger["predicates"]["depth_within_64"])
        self.assertFalse(larger["predicates"]["closure_lower_within_64MiB"])

    def test_recipient_reservation_boundary_leaves_no_ordinary_transaction_claim(self):
        for script_size, cap, count in ((22, 4_000_000, 32245), (22, 800_000, 6439),
                                      (34, 4_000_000, 23246), (34, 800_000, 4642)):
            kwargs = dict(proofs=0, recent_proofs=0, origins=0, recent_origins=0, script_bytes=script_size)
            at = v6_snapshot_resources(**kwargs, recipients=count)
            over = v6_snapshot_resources(**kwargs, recipients=count + 1)
            self.assertLessEqual(at["coinbase_reservation_weight"], cap)
            self.assertGreater(over["coinbase_reservation_weight"], cap)

    def test_history_scan_scales_with_pool_fraction_but_retained_window_does_not(self):
        large = v6_history_resources(20000, 13 * 1024 * 1024, pool_fraction=0.1)
        small = v6_history_resources(20000, 13 * 1024 * 1024, pool_fraction=0.001)
        self.assertEqual(small["cold_full_snapshot_bytes_at_that_scan_length"],
                         100 * large["cold_full_snapshot_bytes_at_that_scan_length"])
        self.assertEqual(small["approximate_global_admissions_examined"],
                         100 * large["approximate_global_admissions_examined"])
        self.assertEqual(large["retained_one_pool_query_bytes"], 160000 * 150)
        self.assertEqual(small["retained_one_pool_query_bytes"], large["retained_one_pool_query_bytes"])
        oversized = v6_history_resources(20000, 1024, pool_fraction=1, oldest_cohort_proofs=400000)
        self.assertFalse(oversized["query_bytes_within_default_64MiB"])
        self.assertTrue(oversized["history_limits_are_local_resumable_not_consensus"])

    def test_mean_burst_and_density_reports_do_not_claim_production_admission(self):
        report = resource_budget_report()
        self.assertFalse(report["current_v6_SHIFT14_general_production_envelope_passes"])
        for case in report["workloads"]:
            self.assertFalse(case["sufficient_for_production_or_native_admission"])
            if case["load"] != "illustrative_mean":
                self.assertFalse(case["not_ruled_out_by_declared_4M_WU_necessary_bounds"])
        # Regardless of transaction sharing, proofs plus four recent-height
        # state cohorts alone exceed 16MiB near SHIFT14's upper density.
        upper = v6_snapshot_resources(proofs=32768, recent_proofs=4 * 32768,
            origins=0, recent_origins=0, recipients=0)
        self.assertFalse(upper["predicates"]["snapshot_lower_bound_within_16MiB"])

    def test_mean_origin_boundary_includes_repeated_leaf_state(self):
        result = v6_mean_origin_envelope(20115)
        self.assertEqual(result["maximum_origins_also_fitting_optimistic_dependency_forest"], 18)
        # Reconstruct both sides of the boundary independently with actual
        # vector-byte formulas, including origin-dependent certificates in
        # every leaf; the limit is not merely64MiB / one constant opening.
        for origins, expected in ((18, True), (19, False)):
            root = v6_snapshot_resources(proofs=20115, recent_proofs=80460,
                origins=origins, recent_origins=4 * origins, recipients=100)
            leaf_bytes = 284 + 64 + 32 + 32 + (1 + 1 + 1 + 3 + 1 + 1)
            leaf_bytes += 60345 * 36 + 3 * origins * 100 + 100 * 31
            self.assertEqual(2 * root["bytes"]["snapshot_upper"] + origins * leaf_bytes <= 64 * 1024 * 1024,
                             expected)
        self.assertEqual(v6_mean_origin_envelope(32768)["maximum_origins_also_fitting_optimistic_dependency_forest"], 0)

    def test_invalid_resource_inputs(self):
        valid = dict(proofs=1, recent_proofs=1, origins=1, recent_origins=1, recipients=1)
        for key, value in (("proofs", -1), ("recent_proofs", True), ("origins", 1.5),
                           ("script_bytes", 23), ("unique_coinbases", 2),
                           ("body_bytes", 100), ("transaction_sets", 0), ("script_sig_bytes", 101)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                v6_snapshot_resources(**(valid | {key: value}))
        for args in ((0,), (True,), (float("inf"),), (1e100,), (2, 0), (2, 9),
                     (2, 1, 1), (2, 1, 1e-100)):
            with self.assertRaises(ValueError):
                geometric_sum_quantile(*args)
        with self.assertRaises(ValueError):
            v6_history_resources(20000, 1024, pool_fraction=0)


if __name__ == "__main__":
    unittest.main()
