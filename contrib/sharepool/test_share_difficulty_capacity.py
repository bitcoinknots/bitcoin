#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Analytical regression checks; no node, hardware or third-party dependencies."""

import math
import unittest

from share_difficulty_capacity import illustrative_shift, report, scenario


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


if __name__ == "__main__":
    unittest.main()
