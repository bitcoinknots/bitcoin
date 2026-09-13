#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Policy oracle invariants; native integration must be tested separately."""

from dataclasses import replace
from fractions import Fraction
import itertools
import unittest

from tides_admission_audit import Admission, cohort_allocate, legacy_rank_allocate, reproduce


class AdmissionAuditTests(unittest.TestCase):
    def test_finite_adversarial_reproduction(self):
        self.assertEqual(reproduce()["result"], "passed")

    def test_same_height_hash_relabeling_and_input_permutation_do_not_change_payouts(self):
        inputs = (Admission(4, 1, "A", "alice", 1), Admission(4, 2, "A", "bob", 2),
                  Admission(4, 3, "A", "carol", 5))
        expected = cohort_allocate(inputs, pool="A", window=Fraction(3, 2), reward=800)
        self.assertEqual(expected.payouts, {"alice": 100, "bob": 200, "carol": 500})
        for proof_ids in itertools.permutations((10, 20, 30)):
            changed = tuple(replace(entry, proof_id=proof) for entry, proof in zip(inputs, proof_ids))
            for permutation in itertools.permutations(changed):
                self.assertEqual(cohort_allocate(permutation, pool="A", window=Fraction(3, 2), reward=800), expected)

    def test_legacy_payout_changes_with_hash_rank(self):
        inputs = (Admission(1, 1, "A", "alice", 1), Admission(1, 2, "A", "bob", 1))
        before = legacy_rank_allocate(inputs, pool="A", window=1, reward=100)
        after = legacy_rank_allocate(tuple(replace(value, proof_id=3 - value.proof_id) for value in inputs),
                                     pool="A", window=1, reward=100)
        self.assertEqual(before.payouts, {"bob": 100})
        self.assertEqual(after.payouts, {"alice": 100})

    def test_partial_boundary_uses_every_member_of_that_height(self):
        inputs = (Admission(1, 1, "A", "alice", 1), Admission(1, 2, "A", "bob", 2),
                  Admission(2, 3, "A", "carol", 1))
        result = cohort_allocate(inputs, pool="A", window=2, reward=600)
        self.assertEqual(result.weights, {"alice": Fraction(1, 3), "bob": Fraction(2, 3), "carol": 1})
        self.assertEqual(result.payouts, {"alice": 100, "bob": 200, "carol": 300})
        truncated = cohort_allocate(inputs[1:], pool="A", window=2, reward=600)
        self.assertNotEqual(truncated.payouts, result.payouts)

    def test_aggregate_recipient_once_before_floor(self):
        inputs = (Admission(1, 1, "A", "alice", 1), Admission(1, 2, "A", "bob", 1),
                  Admission(2, 3, "A", "alice", 1))
        result = cohort_allocate(inputs, pool="A", window=2, reward=3)
        self.assertEqual(result.weights, {"alice": Fraction(3, 2), "bob": Fraction(1, 2)})
        self.assertEqual(result.payouts, {"alice": 2})
        self.assertEqual(result.residue, 1)
        self.assertEqual(int(Fraction(3, 2)) + int(Fraction(3, 4)), 1)

    def test_split_work_preserves_weight_and_recipient_split_cannot_increase_total_payout(self):
        unsplit = (Admission(1, 1, "A", "alice", 7), Admission(1, 2, "A", "bob", 3))
        split = (Admission(1, 3, "A", "alice", 3), Admission(1, 4, "A", "alice", 4), unsplit[1])
        options = dict(pool="A", window=Fraction(23, 7), reward=101)
        before, after = cohort_allocate(unsplit, **options), cohort_allocate(split, **options)
        self.assertEqual(before, after)
        addresses = (replace(split[0], recipient="alice_1"), replace(split[1], recipient="alice_2"), split[2])
        result = cohort_allocate(addresses, **options)
        self.assertLessEqual(result.payouts.get("alice_1", 0) + result.payouts.get("alice_2", 0), before.payouts["alice"])

    def test_pool_isolation_and_recipient_reuse(self):
        a = (Admission(1, 1, "A", "alice", 1), Admission(1, 2, "A", "bob", 1))
        b = (Admission(10, 3, "B", "alice", 1 << 200), Admission(10, 4, "B", "carol", 1))
        options = dict(pool="A", window=1, reward=100)
        self.assertEqual(cohort_allocate(a, **options), cohort_allocate(a + b, **options))

    def test_issued_job_tuple_is_unchanged_after_late_receipt(self):
        issued = (Admission(1, 1, "A", "alice", 1),)
        options = dict(pool="A", window=1, reward=100)
        before = cohort_allocate(issued, **options)
        later = issued + (Admission(2, 2, "A", "bob", 1),)
        self.assertEqual(cohort_allocate(issued, **options), before)
        self.assertNotEqual(cohort_allocate(later, **options), before)

    def test_native_rational_window_and_large_cohort_use_exact_unbounded_arithmetic(self):
        # A very hard canonical native target can assign 2^245 work per proof.
        # At 2^14+1 records, scaling by a full boundary cohort and satoshis can
        # exceed 512 bits. The independent oracle deliberately has no wraparound.
        work, reward = 1 << 245, 2_100_000_000_000_000
        inputs = tuple(Admission(1, i + 1, "A", "alice" if i % 2 else "bob", work) for i in range(16_385))
        window = Fraction(8 * (1 << 256), 2)
        result = cohort_allocate(inputs, pool="A", window=window, reward=reward)
        total = 16_385 * work
        self.assertGreater((window.numerator * total * reward).bit_length(), 512)
        self.assertEqual(result.payouts["alice"], reward * 8_192 // 16_385)
        self.assertEqual(result.payouts["bob"], reward * 8_193 // 16_385)
        self.assertEqual(sum(result.weights.values()), window)

    def test_bootstrap_and_invalid_evidence_are_outside_arithmetic_authority(self):
        with self.assertRaisesRegex(ValueError, "empty history"):
            cohort_allocate((), pool="A", window=1, reward=100)
        duplicate = Admission(1, 1, "A", "alice", 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            cohort_allocate((duplicate, duplicate), pool="A", window=1, reward=100)


if __name__ == "__main__":
    unittest.main()
