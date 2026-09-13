#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exhaustively check the conditional covariance calculation using recipient labels."""

from fractions import Fraction
import itertools
import statistics
import unittest

from tides_calibration import Proof, Scenario, simulate
from tides_conditional_variance import ConditionalAllocation, run_conditioned, summarize_conditioned


class ConditionalVarianceTests(unittest.TestCase):
    def test_exhaustive_labels_match_quadratic_including_repeated_windows(self):
        # Two payout windows reuse proof2. The oldest boundary splits a two-proof
        # cohort in half, rather than selecting one owner by a proof hash.
        batches = [[Proof(i, 0, 0, 0) for i in (1, 2)], [Proof(3, 0, 0, 1)], [Proof(4, 0, 0, 2)]]
        acc = ConditionalAllocation()
        acc.observe(batches[:2], Fraction(2))
        acc.observe(batches, Fraction(5, 2))
        # Proof coefficients at the two payouts are (.25,.25,.5,0) and
        # (.1,.1,.4,.4); integrate all 2^4 equally likely independent labels.
        coefficients = [Fraction(35, 100), Fraction(35, 100), Fraction(9, 10), Fraction(4, 10)]
        amounts = [sum(c * label for c, label in zip(coefficients, labels))
                   for labels in itertools.product((0, 1), repeat=4)]
        expected_variance = statistics.pvariance(amounts)
        result = acc.statistics()
        self.assertAlmostEqual(0.5 * 0.5 * result["sum_squared_lifetime_proof_payout_coefficients"], float(expected_variance))
        self.assertAlmostEqual(result["total_payout_coefficient_mass"], 2)
        self.assertAlmostEqual(float(statistics.mean(amounts)), 1)
        for probability in (Fraction(1, 10), Fraction(1, 1000)):
            mean, square = Fraction(0), Fraction(0)
            for labels in itertools.product((0, 1), repeat=4):
                mass = probability ** sum(labels) * (1 - probability) ** (4 - sum(labels))
                amount = sum(c * label for c, label in zip(coefficients, labels))
                mean += mass * amount
                square += mass * amount * amount
            self.assertAlmostEqual(float(square - mean * mean),
                float(probability * (1 - probability)) * result["sum_squared_lifetime_proof_payout_coefficients"])
            self.assertEqual(mean, 2 * probability)

    def test_expired_window_proofs_do_not_receive_later_coefficients(self):
        batches = [[Proof(i, 0, 0, i)] for i in range(10)]
        acc = ConditionalAllocation()
        acc.observe(batches[:5], Fraction(2))
        acc.observe(batches, Fraction(2))
        self.assertAlmostEqual(acc.statistics()["sum_squared_lifetime_proof_payout_coefficients"], 1)

    def test_fractional_sample_and_unused_empty_cohorts(self):
        batch = [Proof(1, 0, 0, 0), Proof(2, 0, 0, 0)]
        acc = ConditionalAllocation()
        acc.observe([[], batch, []], Fraction(1, 3))
        self.assertAlmostEqual(acc.statistics()["sum_squared_lifetime_proof_payout_coefficients"], 0.5)

    def test_conditional_model_rejects_bootstrap_and_rewritten_history(self):
        acc = ConditionalAllocation()
        acc.observe([], 1)
        with self.assertRaises(ValueError):
            acc.statistics()
        acc = ConditionalAllocation()
        batch = [Proof(1, 0, 0, 0)]
        acc.observe([batch], 1)
        with self.assertRaises(ValueError):
            acc.observe([[Proof(2, 0, 0, 0)]], 1)

    def test_zero_block_variance_reports_unavailable_explicitly(self):
        run = {"conditional_label_integration": {"payout_count": 5,
            "sum_squared_lifetime_proof_payout_coefficients": .5}}
        with self.assertRaisesRegex(ValueError, "zero variance"):
            summarize_conditioned([run, run], Scenario(), 37)
        with self.assertRaisesRegex(ValueError, "two traces"):
            summarize_conditioned([run], Scenario(), 37)

    def test_conditional_instrumentation_keeps_actual_simulated_payouts(self):
        scenario = Scenario(pool_fraction=.1, share_shift=12, reference_shift=14,
                            warmup_pool_blocks=1, measured_pool_blocks=1)
        result = run_conditioned(37, scenario)
        result.pop("conditional_label_integration")
        self.assertEqual(result, simulate(37, scenario))


if __name__ == "__main__":
    unittest.main()
