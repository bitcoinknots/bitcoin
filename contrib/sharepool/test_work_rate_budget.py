#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Work-budget arithmetic tests using synthetic, already-credited records."""

from dataclasses import FrozenInstanceError
import unittest

from work_accounting import CreditedRecord, expected_work
from work_rate_budget import evaluate


class WorkRateBudgetTest(unittest.TestCase):
    def test_five_terahashes_per_second_exact_boundary_and_one_above(self):
        budget = 3_000_000_000_000_000
        kwargs = dict(cap_hashes_per_second=5_000_000_000_000, window_seconds=600)
        records = [CreditedRecord(bytes([i]), bytes([i]), budget) for i in range(10)]
        result = evaluate(records, **kwargs)
        self.assertEqual(result.budget_work, budget)
        self.assertTrue(result.passes)
        self.assertEqual(result.offenders, ())
        records.append(CreditedRecord(b"one more share", b"\x00", 1))
        result = evaluate(records, **kwargs)
        self.assertFalse(result.passes)
        self.assertEqual([(group.group_id, group.credited_work) for group in result.offenders],
                         [(b"\x00", budget + 1)])

    def test_different_miners_and_jobs_aggregate_under_same_group(self):
        records = [CreditedRecord(b"miner-A job-1 share-1", b"template-A", 40),
                   CreditedRecord(b"miner-B job-2 share-1", b"template-A", 60)]
        kwargs = dict(cap_hashes_per_second=10, window_seconds=10)
        result = evaluate(records, **kwargs)
        self.assertTrue(result.passes)
        self.assertEqual(result.accounting.group_count, 1)
        records.append(CreditedRecord(b"miner-C job-3 share-1", b"template-A", 1))
        self.assertFalse(evaluate(records, **kwargs).passes)

    def test_work_weights_not_equal_share_counts_control_budget(self):
        easy = expected_work((1 << 255) - 1)
        hard = expected_work((1 << 253) - 1)
        records = [CreditedRecord(b"easy", b"group-A", easy),
                   CreditedRecord(b"hard", b"group-B", hard)]
        result = evaluate(records, cap_hashes_per_second=5, window_seconds=1)
        self.assertEqual((easy, hard), (2, 8))
        self.assertEqual(tuple(group.group_id for group in result.offenders), (b"group-B",))

    def test_complete_configured_window_is_used(self):
        # One disclosed share has no meaningful first-to-last arrival interval.
        records = [CreditedRecord(b"only disclosed share", b"group-A", 100)]
        self.assertTrue(evaluate(records, cap_hashes_per_second=1, window_seconds=100).passes)
        self.assertFalse(evaluate(records, cap_hashes_per_second=1, window_seconds=99).passes)

    def test_empty_evidence_does_not_certify_zero_hashrate(self):
        result = evaluate([], cap_hashes_per_second=5, window_seconds=600)
        self.assertEqual(result.accounting.total_work, 0)
        self.assertEqual(result.offenders, ())
        self.assertFalse(result.passes)

    def test_single_group_can_account_for_all_work_within_its_budget(self):
        result = evaluate([CreditedRecord(b"only share", b"only group", 5)],
                          cap_hashes_per_second=5, window_seconds=1)
        self.assertEqual(result.accounting.group_count, 1)
        self.assertTrue(result.passes)

    def test_other_groups_do_not_change_a_groups_budget(self):
        records = [CreditedRecord(b"over budget", b"group-A", 6)]
        kwargs = dict(cap_hashes_per_second=5, window_seconds=1)
        self.assertFalse(evaluate(records, **kwargs).passes)
        records.extend(CreditedRecord(bytes([i]), bytes([i]), 5) for i in range(20))
        result = evaluate(records, **kwargs)
        self.assertFalse(result.passes)
        self.assertEqual(tuple(group.group_id for group in result.offenders), (b"group-A",))

    def test_positive_integer_configuration_excludes_boolean_and_float(self):
        for bad in (-1, 0, True, False, 1.0, "1", None):
            for field in ("cap_hashes_per_second", "window_seconds"):
                with self.subTest(field=field, value=bad):
                    kwargs = dict(cap_hashes_per_second=1, window_seconds=1)
                    kwargs[field] = bad
                    with self.assertRaisesRegex(ValueError, field):
                        evaluate([], **kwargs)

    def test_invalid_records_and_cross_group_duplicate_ids_are_rejected(self):
        kwargs = dict(cap_hashes_per_second=1, window_seconds=1)
        for work in (-1, 0, True, False, 1.0, "1"):
            with self.assertRaises(ValueError):
                evaluate([CreditedRecord(b"share", b"group", work)], **kwargs)
        for share_id, group_id in ((b"", b"group"), (b"share", b""), ("share", b"group")):
            with self.assertRaises(ValueError):
                evaluate([CreditedRecord(share_id, group_id, 1)], **kwargs)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate([CreditedRecord(b"same", b"A", 1), CreditedRecord(b"same", b"B", 1)],
                     **kwargs)

    def test_canonical_order_generator_input_and_immutable_result(self):
        records = [CreditedRecord(b"B share", b"B", 2), CreditedRecord(b"A share", b"A", 1)]
        kwargs = dict(cap_hashes_per_second=1, window_seconds=10)
        result = evaluate(iter(records), **kwargs)
        self.assertEqual(result, evaluate(reversed(records), **kwargs))
        self.assertEqual(tuple(group.group_id for group in result.accounting.groups),
                         (b"A", b"B"))
        with self.assertRaises(FrozenInstanceError):
            result.window_seconds = 20

    def test_arbitrary_precision_budget_preserves_boundary(self):
        cap = 10**100
        result = evaluate([CreditedRecord(b"huge share", b"group", cap * 600 + 1)],
                          cap_hashes_per_second=cap, window_seconds=600)
        self.assertEqual(result.budget_work, cap * 600)
        self.assertFalse(result.passes)


if __name__ == "__main__":
    unittest.main()
