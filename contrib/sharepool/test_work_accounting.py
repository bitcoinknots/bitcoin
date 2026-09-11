#!/usr/bin/env python3
"""Arithmetic tests only; the supplied records are synthetic."""

from dataclasses import FrozenInstanceError
import unittest

from work_accounting import CreditedRecord, evaluate, expected_work


def records_for(weights):
    return [CreditedRecord(bytes([i]), bytes([i]), work)
            for i, work in enumerate(weights)]


class WorkAccountingTest(unittest.TestCase):
    def test_canonical_immutable_result(self):
        for count in (1, 3, 12):
            records = records_for([100] * count)
            result = evaluate(records)
            self.assertEqual(result.total_work, 100 * count)
            self.assertEqual(result.group_count, count)
            self.assertEqual(result, evaluate(reversed(records)))
            with self.assertRaises(FrozenInstanceError):
                result.total_work = 0

    def test_arbitrary_precision_group_totals(self):
        base = 10**100
        result = evaluate(records_for([base + 1, base - 1]))
        self.assertEqual(result.total_work, 2 * base)
        self.assertEqual(result.groups[0].credited_work, base + 1)

    def test_whole_pool_can_be_accounted_to_one_group(self):
        result = evaluate([CreditedRecord(b"one", b"group", 40),
                           CreditedRecord(b"two", b"group", 60)])
        self.assertEqual(result.group_count, 1)
        self.assertEqual(result.groups[0].credited_work, result.total_work)
        self.assertEqual(result.total_work, 100)

    def test_equal_share_counts_can_have_unequal_work(self):
        easy = expected_work((1 << 256) - 1)
        harder = expected_work((1 << 255) - 1)
        result = evaluate(records_for([easy, harder]))
        self.assertEqual((easy, harder), (1, 2))
        self.assertEqual([g.credited_work for g in result.groups], [1, 2])

    def test_same_tag_across_jobs_is_aggregated(self):
        records = [CreditedRecord(bytes([group, job]), bytes([group]), 5)
                   for group in range(3) for job in range(2)]
        result = evaluate(records)
        self.assertEqual((result.record_count, result.group_count), (6, 3))
        self.assertEqual([g.credited_work for g in result.groups], [10, 10, 10])
        records.append(CreditedRecord(b"another job", bytes([0]), 1))
        self.assertEqual(evaluate(records).groups[0].credited_work, 11)

    def test_duplicate_share_ids_are_rejected_even_across_groups(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate([CreditedRecord(b"same", b"A", 1), CreditedRecord(b"same", b"B", 1)])

    def test_empty_input_has_zero_totals(self):
        result = evaluate([])
        self.assertEqual((result.record_count, result.group_count, result.total_work), (0, 0, 0))
        self.assertEqual(result.groups, ())

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
