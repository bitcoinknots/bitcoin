#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Analytical regression checks; no node, hardware or third-party dependencies."""

import math
import copy
import unittest

from live_capacity_metrics import phase_counts
from share_difficulty_capacity import (finite_capacity_evidence, live_capacity_evidence, illustrative_shift,
    payout_capacity, production_capacity_report, report, scenario)


class ShareDifficultyCapacityTest(unittest.TestCase):
    def test_unit_mean_poisson_case(self):
        result = scenario(10, 1 / 1024, 1)
        self.assertEqual(result["expected_proofs"], 1)
        self.assertEqual(result["probability_zero_proofs"], math.exp(-1))
        self.assertEqual(result["relative_sampling_standard_deviation"], 1)

    def test_current_whole_network_storage_lower_bound(self):
        result = scenario(10, 1, 144)
        self.assertEqual(result["expected_proofs"], 147_456)
        self.assertEqual(result["expected_minimal_proof_bytes"], 72 * 1024 ** 2)
        self.assertEqual(result["expected_minimal_proof_bytes"],
                         result["expected_unique_proof_archive_bytes_per_day"])

    def test_more_proofs_reduce_variance_at_proportional_resource_cost(self):
        low = scenario(10, 0.0001, 1)
        high = scenario(14, 0.0001, 1)
        self.assertEqual(high["expected_proofs"], low["expected_proofs"] * 16)
        self.assertEqual(high["relative_sampling_standard_deviation"],
                         low["relative_sampling_standard_deviation"] / 4)
        self.assertEqual(high["expected_unique_proof_archive_bytes_per_day"],
                         low["expected_unique_proof_archive_bytes_per_day"] * 16)

    def test_underflow_does_not_erase_log_probability(self):
        result = scenario(18, 1, 144)
        self.assertEqual(result["probability_zero_proofs"], 0)
        self.assertEqual(result["log_probability_zero_proofs"], -37_748_736)

    def test_example_objective_is_met_and_previous_shift_fails(self):
        for fraction in (1, 0.1, 0.01, 0.001, 0.0001):
            for intervals in (1, 144):
                shift = illustrative_shift(fraction, intervals)
                achieved = scenario(shift, fraction, intervals)
                self.assertLessEqual(achieved["relative_sampling_standard_deviation"], 0.05)
                self.assertLessEqual(achieved["probability_zero_proofs"], 0.01)
                if shift:
                    previous = scenario(shift - 1, fraction, intervals)
                    self.assertTrue(previous["relative_sampling_standard_deviation"] > 0.05 or
                                    previous["probability_zero_proofs"] > 0.01)

    def test_all_requested_cases_and_wire_lower_bound(self):
        result = report()
        self.assertEqual(len(result["scenarios"]), 45)
        self.assertEqual(result["minimal_proof_bytes"], 512)
        self.assertEqual(result["proof_only_snapshot_upper_bound_ignoring_all_other_fields"], 32_768)
        self.assertEqual([item["expected_unique_proof_archive_bytes_per_day"]
                          for item in result["profiles"]],
                         [72 * 1024 ** 2, 1152 * 1024 ** 2, 18 * 1024 ** 3])

    def test_invalid_parameters(self):
        for args in ((-1, 1, 1), (True, 1, 1), (33, 1, 1), (10, 0, 1),
                     (10, 1.1, 1), (10, float("nan"), 1), (10, 1, 0), (10, 1, 1.5)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                scenario(*args)


def native_fixture():
    """Synthetic report shape for arithmetic checks; not benchmark evidence."""
    blocks = [{"height": height, "hash": f"{height:064x}", "admitted": 40,
               "native_accepted": True, "peer_ready": True} for height in (102, 103)]
    return {"schema": 1, "result": "passed", "profile": "hash-only-v7-compact-tides",
        "network": "isolated native regtest", "opaque_proof_fixtures": 0, "native_nodes": 2,
        "payout_oracle_verified": True, "peer_recovery_verified": True,
        "offered": 80, "acknowledged": 80, "admitted": 80, "peer_verified_admitted": 80,
        "expired": 0, "unresolved_receipts": 0, "final_backlog": 0,
        "current_acknowledged_backlog": 0, "peer_verification_backlog": 0,
        "seconds": 20, "configuration": {"miners": 10}, "limitations": ["test-only fixture"],
        "epochs": [{"epoch": 1, "seconds": 15, "admission_seconds": 4,
                    "origin_preparation_seconds": 5, "offered": 80, "acknowledged": 80,
                    "admitted": 80, "blocks": blocks}],
        "rewards": [{"height": block["height"], "new_admissions": 40, "payout_scripts": 7,
                     "exact_rational_window_and_coinbase_verified": True,
                     "whole_admission_height_cohorts_verified": True} for block in blocks]}


class NativeCapacityEvidenceTest(unittest.TestCase):
    def test_full_elapsed_and_ingress_rates_are_not_nested_timer_sums(self):
        source = native_fixture()
        source["measurements"] = {"gate.receive": {"total_seconds": 9999},
                                  "rpc.validation": {"total_seconds": 9999}}
        source["epochs"][0]["observed_serial_acknowledgements_per_second"] = 123456
        observed = finite_capacity_evidence(source)
        self.assertEqual(observed["observed_native_admissions_per_elapsed_second"], 4)
        self.assertEqual(observed["per_epoch"][0]["acknowledgements_per_ingress_second"], 20)
        self.assertEqual(observed["maximum_verified_payout_recipients_in_one_block"], 7)
        self.assertTrue(observed["final_receipts_drained_without_loss"])
        self.assertFalse(observed["sustained_capacity_qualified"])

    def test_native_acceptance_peer_confirmation_and_payout_oracle_are_required(self):
        source = native_fixture()
        mutations = [lambda s: s.update(result="failed"),
            lambda s: s.update(profile="hash-only-v6-tides"),
            lambda s: s.update(opaque_proof_fixtures=1),
            lambda s: s.update(payout_oracle_verified=False),
            lambda s: s["epochs"][0]["blocks"][0].update(peer_ready=False),
            lambda s: s["rewards"][0].update(exact_rational_window_and_coinbase_verified=False)]
        for mutate in mutations:
            changed = copy.deepcopy(source)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                finite_capacity_evidence(changed)

    def test_count_disagreement_duplicate_block_and_overlapping_epoch_time_rejected(self):
        mutations = [lambda s: s.update(admitted=81),
            lambda s: s["epochs"][0].update(acknowledged=79),
            lambda s: s["epochs"][0]["blocks"][1].update(hash=s["epochs"][0]["blocks"][0]["hash"]),
            lambda s: s["rewards"][0].update(new_admissions=39),
            lambda s: s["rewards"].append(s["rewards"][0]),
            lambda s: s.update(seconds=14),
            lambda s: s["epochs"][0].update(admission_seconds=11)]
        for mutate in mutations:
            changed = native_fixture()
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                finite_capacity_evidence(changed)

    def test_bad_numeric_evidence_is_not_silently_accepted(self):
        for name in ("offered", "admitted", "seconds"):
            for value in (True, -1, float("nan"), float("inf"), 10**1000):
                source = native_fixture()
                source[name] = value
                with self.subTest(name=name, value=str(value)), self.assertRaises(ValueError):
                    finite_capacity_evidence(source)


def live_fixture(duration=10):
    def event(stage, seconds, *ids):
        return {"stage": stage, "seconds": seconds, "proof_ids": [f"{identity:064x}" for identity in ids]}
    events = [event("offered", 1, 1, 2), event("acknowledged", 2, 1),
        event("admitted", 3, 1), event("peer_verified", 4, 1), event("offered", 11, 3),
        event("acknowledged", 12, 2, 3), event("admitted", 13, 2, 3), event("peer_verified", 14, 2, 3)]
    blocks = [{"height": height, "hash": f"{height:064x}", "admitted": count,
        "native_accepted": True, "peer_ready": True, "payout_recipients": count,
        "local_seconds": local, "peer_seconds": peer, "coinbase_weight": 1000 + count * 124,
        "native_weight": 3000 + count * 124}
        for height, count, local, peer in ((102, 1, 3.01, 4.01), (103, 2, 13.01, 14.01))]
    phase = phase_counts(events, seconds=duration)
    phase.update(scheduled_requests_due=3, source_unfulfilled_requests=3 - phase["offered"])
    return {"schema": 1, "result": "passed", "profile": "hash-only-v7-compact-tides",
        "network": "isolated native regtest", "native_nodes": 2, "payout_oracle_verified": True,
        "peer_verified": True, "configuration": {"duration_seconds": duration, "miners": 3},
        "live_and_drain_seconds": 15, "scheduled_requests": 3, "expired_acknowledged": 0,
        "rejected_before_ack": 0, "events": events, "blocks": blocks,
        "measured_phase": phase, "completed_run": phase_counts(events, seconds=15),
        "rewards": [{"height": block["height"], "new_admissions": block["admitted"],
            "payout_scripts": block["payout_recipients"], "exact_rational_window_and_coinbase_verified": True,
            "whole_admission_height_cohorts_verified": True} for block in blocks],
        "limitations": ["synthetic arithmetic fixture, not measured capacity"]}


class LiveCapacityEvidenceTest(unittest.TestCase):
    def test_recompute_phase_rates_without_credit_for_catchup_or_drain(self):
        result = live_capacity_evidence(live_fixture())
        self.assertEqual(result["observed_peer_verified_admissions_per_elapsed_second"], 0.1)
        self.assertEqual(result["completed_run_counts"]["peer_verified"], 3)
        self.assertEqual(result["source_unfulfilled_requests_at_cutoff"], 1)
        self.assertEqual(result["counts"]["unacknowledged_queue"], 1)
        self.assertFalse(result["fixed_phase_all_scheduled_work_confirmed"])
        self.assertEqual(result["maximum_phase_verified_payout_recipients_in_one_block"], 1)
        self.assertEqual(result["maximum_verified_payout_recipients_in_one_block"], 2)
        self.assertEqual(result["maximum_phase_verified_coinbase_weight"], 1124)
        self.assertEqual(result["maximum_verified_native_weight"], 3248)
        self.assertFalse(result["sustained_capacity_qualified"])

    def test_tampered_phase_rate_wrong_scheduling_or_unfinished_capture_rejected(self):
        mutations = [lambda s: s["measured_phase"].update(observed_peer_verified_per_second=.3),
            lambda s: s["measured_phase"].update(admitted=3),
            lambda s: s["measured_phase"].update(source_unfulfilled_requests=0),
            lambda s: s.update(scheduled_requests=4),
            lambda s: s.update(expired_acknowledged=1),
            lambda s: s.update(cleanup_error="producer still running"),
            lambda s: s["blocks"][0].update(payout_recipients=9),
            lambda s: s["blocks"][0].update(native_weight=1000),
            lambda s: s["blocks"][0].update(peer_ready=False)]
        for mutate in mutations:
            source = live_fixture()
            mutate(source)
            with self.subTest(source=source), self.assertRaises(ValueError):
                live_capacity_evidence(source)

    def test_zero_native_completions_at_cutoff_is_valid_evidence_not_a_zero_capacity_claim(self):
        result = production_capacity_report(live_fixture(duration=2))
        self.assertEqual(result["native_evidence"]["observed_native_admissions_per_elapsed_second"], 0)
        self.assertIsNone(result["minimum_seconds_per_equal_miner_share_at_observed_rate_screen"])
        for row in result["global_difficulty_scenarios"]:
            self.assertIsNone(row["monitored_rate_screen"]["required_over_observed_rate"])
            self.assertFalse(row["monitored_rate_screen"]["not_exceeding_observed_workload_rate"])
        self.assertEqual(result["result"], "production_capacity_not_established")


class ProductionCapacityScreenTest(unittest.TestCase):
    def test_difficulty_uses_exact_v7_assignment_and_not_historical_v4_1024_ratio(self):
        result = production_capacity_report(native_fixture(), pool_fraction=0.1, miners=10,
                                            reference_share_seconds=(30,))
        active = result["global_difficulty_scenarios"][0]
        self.assertEqual(active["shift"], 10)
        self.assertTrue(active["active"])
        self.assertAlmostEqual(active["network_proofs_per_second"], 2.0952302809766667)
        self.assertAlmostEqual(active["pool_proofs_per_second"], 0.20952302809766667)
        mean = 86400 * active["pool_proofs_per_second"] / 10
        self.assertAlmostEqual(active["expected_proofs_per_miner_in_observation"], mean)
        self.assertAlmostEqual(active["proof_count_relative_standard_deviation"], 1 / math.sqrt(mean))
        self.assertFalse(result["consensus_parameters_changed"])

    def test_reference_cadence_scales_to_monitored_network_not_only_pool(self):
        args = dict(pool_fraction=0.01, miners=10, reference_share_seconds=(10,))
        global_result = production_capacity_report(native_fixture(), **args)
        pool_only = production_capacity_report(native_fixture(), monitored_network_fraction=0.01, **args)
        global_reference = global_result["declared_reference_cadences"][0]
        pool_reference = pool_only["declared_reference_cadences"][0]
        self.assertEqual(global_reference["requested_pool_proofs_per_second"], 1)
        self.assertEqual(global_reference["implied_network_proofs_per_second_at_one_global_target"], 100)
        self.assertAlmostEqual(global_reference["candidate_monitored_rate_screen"]["required_proofs_per_second"],
            pool_reference["candidate_monitored_rate_screen"]["required_proofs_per_second"] * 100)
        self.assertEqual(global_reference["expected_proofs_per_miner_in_observation"], 8640)
        self.assertAlmostEqual(global_reference["proof_count_relative_standard_deviation"], 1 / math.sqrt(8640))
        self.assertFalse(global_result["payout_variance_equivalence_established"])
        self.assertEqual(global_result["result"], "production_capacity_not_established")

    def test_impossible_cadence_at_easy_target_is_reported_without_inventing_shift(self):
        result = production_capacity_report(native_fixture(), native_bits=0x207fffff,
            pool_fraction=0.1, miners=10, reference_share_seconds=(1,))
        reference = result["declared_reference_cadences"][0]
        self.assertIsNone(reference["minimum_analytical_shift_meeting_this_cadence"])
        self.assertIsNone(reference["candidate_monitored_rate_screen"])

    def test_headroom_and_recipient_coverage_do_not_create_production_pass(self):
        result = production_capacity_report(native_fixture(), pool_fraction=1, miners=10,
                                            required_rate_headroom=1)
        active = result["global_difficulty_scenarios"][0]["monitored_rate_screen"]
        self.assertTrue(active["not_exceeding_observed_workload_rate"])
        self.assertFalse(active["sustainable_capacity_established"])
        self.assertTrue(result["recipient_count_exceeds_native_fixture_coverage"])
        self.assertEqual(result["minimum_seconds_per_equal_miner_share_at_observed_rate_screen"], 2.5)

    def test_regular_cadence_example_can_exceed_consensus_counts_despite_compact_wire(self):
        result = production_capacity_report(native_fixture(), reference_share_seconds=(30,))
        reference = result["declared_reference_cadences"][0]
        self.assertEqual(reference["minimum_analytical_shift_meeting_this_cadence"], 18)
        screen = reference["candidate_monitored_rate_screen"]
        self.assertEqual(screen["v7_maximum_compact_shares_per_block"], 32768)
        self.assertEqual(screen["v7_maximum_mean_admissions_per_day_at_600_second_blocks"], 4_718_592)
        self.assertGreater(screen["expected_proof_arrivals_per_day"], 4_718_592)
        self.assertTrue(screen["mean_load_exceeds_v7_count_ceiling"])
        # Compact proof records do not remove the existing verification bound.
        self.assertAlmostEqual(reference["candidate_v7_compact_proof_component_bytes_per_day_lower_bound"],
            screen["required_proofs_per_second"] * 86400 * 33)

    def test_reservation_boundaries_both_contexts_and_transaction_headroom(self):
        for reduced, limit in ((False, 32245), (True, 6439)):
            at = payout_capacity(limit, reduced_data=reduced)
            above = payout_capacity(limit + 1, reduced_data=reduced)
            self.assertEqual(at["maximum_recipients_by_this_reservation_only"], limit)
            self.assertTrue(at["fits_declared_weight_budget"])
            self.assertFalse(above["fits_declared_weight_budget"])
            self.assertFalse(at["sufficient_for_native_admission"])
        self.assertLess(payout_capacity(100, non_payout_weight=400000)["maximum_recipients_by_this_reservation_only"], 32245)
        self.assertLess(payout_capacity(100, script_bytes=34)["maximum_recipients_by_this_reservation_only"], 32245)
        self.assertFalse(payout_capacity(0, non_payout_weight=4_000_000)["fits_declared_weight_budget"])
        self.assertFalse(payout_capacity(100, non_payout_weight=3_000_000, reduced_data=True)["fits_declared_weight_budget"])

    def test_invalid_scenario_inputs(self):
        for kwargs in ({"miners": True}, {"pool_fraction": 0}, {"pool_fraction": 1e-300},
                {"native_bits": 0}, {"required_rate_headroom": 0.5}, {"script_bytes": 23},
                {"non_payout_weight": -1}, {"reference_share_seconds": ()},
                {"reference_share_seconds": (float("nan"),)},
                {"observation_seconds": float("inf")},
                {"pool_fraction": 0.5, "monitored_network_fraction": 0.1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                production_capacity_report(native_fixture(), **kwargs)


if __name__ == "__main__":
    unittest.main()
