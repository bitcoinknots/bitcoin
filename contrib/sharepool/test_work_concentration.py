#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Arithmetic tests only; the supplied records are synthetic."""

from dataclasses import FrozenInstanceError
import unittest

from work_concentration import CreditedRecord, evaluate, expected_work


def records_for(weights):
    return [CreditedRecord(bytes([i]), bytes([i]), work)
            for i, work in enumerate(weights)]


class ConcentrationTest(unittest.TestCase):
    def test_exact_ten_percent_and_canonical_immutable_result(self):
        for count in (10, 11):
            records = records_for([100] * count)
            result = evaluate(records)
            self.assertTrue(result.passes)
            self.assertEqual(result.total_work, 100 * count)
            self.assertEqual(result.group_count, count)
            self.assertEqual(result, evaluate(reversed(records)))
            self.assertEqual(result.offenders, ())
            with self.assertRaises(FrozenInstanceError):
                result.total_work = 0

    def test_above_cap_by_one_work_unit_with_huge_integers(self):
        base = 10**100
        result = evaluate(records_for([base + 1, base - 1] + [base] * 8))
        self.assertEqual(result.total_work, 10 * base)
        self.assertFalse(result.passes)
        self.assertEqual(tuple(g.group_id for g in result.offenders), (b"\x00",))

    def test_many_groups_do_not_guarantee_compliance(self):
        result = evaluate(records_for([50] + [1] * 11))
        self.assertEqual(result.group_count, 12)
        self.assertFalse(result.passes)

    def test_equal_share_counts_can_have_unequal_work(self):
        easy = expected_work((1 << 256) - 1)
        harder = expected_work((1 << 255) - 1)
        self.assertFalse(evaluate(records_for([harder] + [easy] * 9)).passes)

    def test_same_tag_across_jobs_is_aggregated(self):
        records = [CreditedRecord(bytes([group, job]), bytes([group]), 5)
                   for group in range(10) for job in range(2)]
        result = evaluate(records)
        self.assertEqual((result.record_count, result.group_count), (20, 10))
        self.assertTrue(result.passes)
        records.append(CreditedRecord(b"another job", b"\x00", 1))
        self.assertFalse(evaluate(records).passes)

    def test_duplicate_share_ids_are_rejected_even_across_groups(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate([CreditedRecord(b"same", b"A", 1), CreditedRecord(b"same", b"B", 1)])

    def test_empty_input_does_not_pass(self):
        result = evaluate([])
        self.assertFalse(result.passes)
        self.assertEqual((result.record_count, result.group_count, result.total_work), (0, 0, 0))

    def test_invalid_work_and_target_inputs(self):
        for work in (-1, 0, True, False, 1.0, "1"):
            with self.assertRaises(ValueError):
                evaluate([CreditedRecord(b"share", b"tag", work)])
        for target in (-1, 0, True, False, 1.0, "1", 1 << 256):
            with self.assertRaises(ValueError):
                expected_work(target)
        self.assertEqual(expected_work(1), 1 << 255)
        self.assertEqual(expected_work((1 << 256) - 1), 1)


if __name__ == "__main__":
    unittest.main()
