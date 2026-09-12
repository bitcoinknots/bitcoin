#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify conditional payout formulas independently by exact small enumerations."""

import itertools
import math
import unittest

from payout_variance_comparison import (age_opportunities, block_luck_and_ideal_pps,
    comparison_report, fixed_time_empty_window, fixed_window, overlapping_windows)


def enumerate_rewards(a, n, cutoffs):
    positions = sorted({i for end in cutoffs for i in range(end - n, end)})
    mean = second = 0
    for labels in itertools.product((0, 1), repeat=len(positions)):
        owners = dict(zip(positions, labels))
        probability = a ** sum(labels) * (1 - a) ** (len(labels) - sum(labels))
        reward = sum(sum(owners[i] for i in range(end - n, end)) / n for end in cutoffs)
        mean += probability * reward
        second += probability * reward * reward
    return mean, second - mean * mean


class PayoutVarianceComparisonTest(unittest.TestCase):
    def test_single_window_matches_enumerated_owner_labels(self):
        for a in (0.1, 0.25, 0.5):
            mean, variance = enumerate_rewards(a, 4, (4,))
            result = fixed_window(a, 4)
            self.assertAlmostEqual(result["expected_payout_fraction"], mean)
            self.assertAlmostEqual(result["payout_fraction_variance"], variance)

    def test_overlap_covariance_matches_enumeration(self):
        for cutoffs in ((3, 3), (3, 4), (3, 6), (3, 4, 5)):
            mean, variance = enumerate_rewards(0.2, 3, cutoffs)
            result = overlapping_windows(0.2, 3, cutoffs)
            self.assertAlmostEqual(result["expected_total_reward_units"], mean)
            self.assertAlmostEqual(result["total_reward_units_variance_conditional_on_cutoffs"], variance)

    def test_identical_windows_do_not_average_away_label_noise(self):
        single = fixed_window(0.01, 1024)
        repeated = overlapping_windows(0.01, 1024, (1024,) * 8)
        self.assertAlmostEqual(single["relative_allocation_standard_deviation"],
                               repeated["relative_standard_deviation_conditional_on_cutoffs"])

    def test_disjoint_windows_average_independent_label_noise(self):
        single = fixed_window(0.01, 1024)
        disjoint = overlapping_windows(0.01, 1024, [1024 * (i + 1) for i in range(8)])
        self.assertAlmostEqual(single["relative_allocation_standard_deviation"] / math.sqrt(8),
                               disjoint["relative_standard_deviation_conditional_on_cutoffs"])

    def test_network_age_opportunities_match_independent_winner_enumeration(self):
        for winning, count in ((False, 4), (True, 3)):
            chance = sum(0.01 ** sum(winners) * 0.99 ** (count - sum(winners))
                         for winners in itertools.product((0, 1), repeat=count) if any(winners))
            result = age_opportunities(0.01, winning)
            self.assertEqual(result["optimistic_matching_block_opportunities"], count)
            self.assertAlmostEqual(result["probability_at_least_one_matching_block"], chance)
        self.assertEqual(age_opportunities(1)["probability_at_least_one_matching_block"], 1)
        self.assertEqual(age_opportunities(1, True, 0)["probability_at_least_one_matching_block"], 0)

    def test_pps_same_mean_but_no_pool_block_luck_term(self):
        result = block_luck_and_ideal_pps(0.01, 0.01, 144)
        self.assertAlmostEqual(result["expected_reward_units_both_benchmarks"], 0.0144)
        self.assertAlmostEqual(result["ideal_fixed_split_block_luck_relative_standard_deviation"], 5 / 6)
        self.assertAlmostEqual(result["ideal_fixed_rate_pps_credit_relative_standard_deviation"], 1 / math.sqrt(14.7456))

    def test_empty_owner_fallback_does_not_preserve_each_miners_mean(self):
        result = fixed_time_empty_window(0.0001, 0.01)
        empty = math.exp(-0.4096)
        self.assertAlmostEqual(result["probability_empty_domain_window"], empty)
        self.assertAlmostEqual(result["expected_payout_fraction_if_miner_is_not_fallback_owner"], 0.01 * (1 - empty))
        self.assertAlmostEqual(result["expected_payout_fraction_if_miner_is_always_fallback_owner"], 0.01 * (1 - empty) + empty)

    def test_report_has_all_requested_miners_and_age_cases(self):
        result = comparison_report()
        self.assertEqual(len(result["conditional_single_payout_cases"]), 9)
        self.assertEqual(len(result["conditional_multiple_payout_cases"]), 9)
        self.assertEqual(len(result["same_hashrate_block_luck_and_pps_benchmarks"]), 30)
        self.assertEqual(len(result["current_age_eligibility_upper_bounds"]), 10)
        self.assertEqual(result["rolling_eight_work_unit_window"]["equal_work_proofs_at_shift10"], 8192)

    def test_invalid_parameters(self):
        for call in (lambda: fixed_window(0, 1), lambda: fixed_window(float("nan"), 1),
                     lambda: fixed_window(0.1, True), lambda: overlapping_windows(0.1, 3, (2,)),
                     lambda: overlapping_windows(0.1, 3, (4, 3)), lambda: age_opportunities(0.1, maximum_age=-1)):
            with self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
