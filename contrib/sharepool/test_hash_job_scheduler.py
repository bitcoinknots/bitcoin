#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Clock/event scheduling; actual native validity is covered by regtest."""
from dataclasses import dataclass
import threading
import unittest
from unittest.mock import patch

from hash_job_scheduler import HashJobScheduler


@dataclass(frozen=True)
class Payload:
    tip: str
    receipts: int
    number: int

    def serialize(self):
        return self


class Gate:
    def __init__(self):
        self.tip, self.receipts = "A", 0
        self.issued = []
        self.builds = self.authorizations = self.strict_checks = 0
        self.fail_context = self.on_build = self.on_strict = None
        self.enabled = True

    def make_native(self, *, sign_owner):
        self.builds += 1
        captured = Payload(self.tip, self.receipts, self.builds)
        if sign_owner(captured) != b"signed":
            raise ValueError("invalid signer")
        if self.on_build:
            self.on_build()
        return captured, captured

    def authorize(self, block, snapshot):
        self.authorizations += 1
        if block != snapshot or (block.tip, block.receipts) != (self.tip, self.receipts):
            raise ValueError("job changed during construction")
        self.issued.append(block)
        return block

    def ready_for_continued_work(self, auth):
        if self.fail_context:
            raise self.fail_context
        return (self.enabled and any(auth is value for value in self.issued) and
                auth.tip == self.tip and auth.receipts <= self.receipts)

    def ready_for_dispatch(self, auth):
        self.strict_checks += 1
        if self.on_strict:
            self.on_strict()
        return self.ready_for_continued_work(auth) and auth.receipts == self.receipts


class HashJobSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.gate = Gate()
        self.sent, self.withdrawals = [], []
        self.scheduler = self.make()

    def publish(self, auth):
        self.sent.append(auth)
        return True

    def make(self, **overrides):
        options = dict(sign_owner=lambda unused: b"signed", publish=self.publish,
                       withdraw=lambda: self.withdrawals.append(self.now), clock=lambda: self.now)
        options.update(overrides)
        return HashJobScheduler(self.gate, **options)

    def test_normal_cadence_and_acknowledgement_storm_keep_issued_cutoff(self):
        first = self.scheduler.poll()
        self.assertEqual(self.scheduler.next_refresh_at, 40)
        for t in range(1, 40):
            self.now, self.gate.receipts = t, t
            self.assertIsNone(self.scheduler.poll())
            self.assertIs(self.scheduler.active, first)
            self.assertEqual(self.scheduler.next_refresh_at, 40)
        self.assertFalse(self.gate.ready_for_dispatch(first))
        self.assertEqual(first.receipts, 0)
        self.now = 40
        second = self.scheduler.poll()
        self.assertEqual(second.receipts, 39)
        self.assertEqual(self.gate.builds, 2)
        self.assertEqual(self.scheduler.next_refresh_at, 80)
        self.assertEqual(self.scheduler.last_update_reason, "interval")
        self.assertEqual(self.withdrawals, [])

    def test_new_parent_and_same_height_branch_change_bypass_deadline(self):
        first = self.scheduler.poll()
        self.now, self.gate.tip = 2, "competing-parent"
        def build():
            self.assertIsNone(self.scheduler.active)
            self.assertEqual(self.withdrawals, [2])
        self.gate.on_build = build
        second = self.scheduler.poll()
        self.assertEqual(second.tip, "competing-parent")
        self.assertEqual(first.tip, "A")
        self.assertEqual(self.scheduler.next_refresh_at, 42)
        self.assertEqual(self.scheduler.last_update_reason, "context")
        self.assertIsNone(self.scheduler.poll())  # Duplicate block notification.

    def test_strict_initial_dispatch_is_not_replaced_by_continuation(self):
        def new_receipt():
            self.gate.receipts += 1
        self.gate.on_strict = new_receipt
        with self.assertRaisesRegex(ValueError, "before scheduled dispatch"):
            self.scheduler.poll()
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.scheduler.active)
        self.assertEqual(len(self.gate.issued), 1)
        # Caller-created/undispatched capabilities cannot become active.
        self.gate.on_strict = None
        self.scheduler.poll()
        self.assertEqual(self.gate.builds, 2)
        self.assertEqual(self.sent[0].receipts, 1)

    def test_receipt_or_parent_change_during_signing_refuses_handoff(self):
        for attribute, value in (("tip", "B"), ("receipts", 1)):
            with self.subTest(attribute=attribute):
                self.setUp()
                self.gate.on_build = lambda: setattr(self.gate, attribute, value)
                with self.assertRaisesRegex(ValueError, "during construction"):
                    self.scheduler.poll()
                self.assertFalse(self.sent)
                self.assertIsNone(self.scheduler.active)

    def test_ack_after_handoff_preserves_cutoff_but_parent_change_withdraws(self):
        def receipt_after_handoff(auth):
            self.gate.receipts += 1
            return self.publish(auth)
        self.scheduler = self.make(publish=receipt_after_handoff)
        first = self.scheduler.poll()
        self.assertEqual(first.receipts, 0)
        self.assertEqual(self.gate.receipts, 1)
        self.assertIsNone(self.scheduler.poll())
        self.scheduler.close()
        def tip_after_handoff(auth):
            self.gate.tip = "B"
            return self.publish(auth)
        other = self.make(publish=tip_after_handoff)
        with self.assertRaisesRegex(ValueError, "during scheduled dispatch"):
            other.poll()
        self.assertIsNone(other.active)
        self.assertEqual(len(self.withdrawals), 2)

    def test_signer_failure_retires_active_job_and_can_retry(self):
        signer = [b"signed"]
        self.scheduler = self.make(sign_owner=lambda unused: signer[0])
        self.scheduler.poll()
        self.now, signer[0] = 40, b"bad"
        with self.assertRaisesRegex(ValueError, "invalid signer"):
            self.scheduler.poll()
        self.assertIsNone(self.scheduler.active)
        self.assertIsNone(self.scheduler.next_refresh_at)
        self.assertEqual(self.withdrawals, [40])
        signer[0] = b"signed"
        self.scheduler.poll()
        self.assertEqual(len(self.sent), 2)

    def test_transport_failure_and_ambiguous_return_withdraw_possible_partial_send(self):
        def broken(auth):
            self.sent.append(auth)
            raise OSError("partial handoff")
        for callback, error in ((broken, OSError), (lambda unused: False, ValueError),
                                (lambda unused: None, ValueError)):
            with self.subTest(callback=callback):
                scheduler = self.make(publish=callback)
                before = len(self.withdrawals)
                with self.assertRaises(error):
                    scheduler.poll()
                self.assertIsNone(scheduler.active)
                self.assertEqual(len(self.withdrawals), before + 1)

    def test_native_profile_journal_or_closed_gate_failure_stops_active_work(self):
        self.scheduler.poll()
        self.gate.fail_context = ValueError("native profile or journal unavailable")
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.scheduler.poll()
        self.assertIsNone(self.scheduler.active)
        self.assertEqual(self.withdrawals, [0])

    def test_failed_withdrawal_blocks_build_and_publication_until_retry_succeeds(self):
        unavailable = [True]
        def withdraw():
            self.withdrawals.append(self.now)
            if unavailable[0]:
                raise OSError("transport still advertising")
        self.scheduler = self.make(withdraw=withdraw)
        self.scheduler.poll()
        self.gate.tip = "B"
        for attempt in range(2):
            with self.assertRaisesRegex(OSError, "still advertising"):
                self.scheduler.poll()
            self.assertTrue(self.scheduler.withdrawal_pending)
            self.assertIsNone(self.scheduler.active)
            self.assertEqual(self.gate.builds, 1)
            self.assertEqual(len(self.sent), 1)
            self.assertEqual(len(self.withdrawals), attempt + 1)
        unavailable[0] = False
        self.scheduler.poll()
        self.assertFalse(self.scheduler.withdrawal_pending)
        self.assertEqual(self.gate.builds, 2)
        self.assertEqual(self.scheduler.active.tip, "B")
        self.assertEqual(len(self.withdrawals), 3)

    def test_close_can_retry_failed_withdrawal_without_resuming_jobs(self):
        unavailable = [True]
        def withdraw():
            self.withdrawals.append(self.now)
            if unavailable[0]:
                raise OSError("shutdown not confirmed")
        self.scheduler = self.make(withdraw=withdraw)
        self.scheduler.poll()
        with self.assertRaisesRegex(OSError, "not confirmed"):
            self.scheduler.close()
        self.assertTrue(self.scheduler.withdrawal_pending)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.scheduler.poll()
        unavailable[0] = False
        self.scheduler.close()
        self.scheduler.close()
        self.assertFalse(self.scheduler.withdrawal_pending)
        self.assertEqual(len(self.withdrawals), 2)
        self.assertEqual(self.gate.builds, 1)

    def test_partial_publish_and_failed_withdrawal_remain_latched(self):
        def publish(auth):
            self.sent.append(auth)
            raise OSError("partial publish")
        def withdraw():
            self.withdrawals.append(self.now)
            raise OSError("cannot stop transport")
        self.scheduler = self.make(publish=publish, withdraw=withdraw)
        for attempt in range(2):
            with self.assertRaisesRegex(OSError, "cannot stop"):
                self.scheduler.poll()
            self.assertTrue(self.scheduler.withdrawal_pending)
            self.assertEqual(self.gate.builds, 1)
            self.assertEqual(len(self.sent), 1)
            self.assertEqual(len(self.withdrawals), attempt + 1)

    def test_slow_construction_exposes_time_and_does_not_replay_missed_intervals(self):
        self.scheduler.poll()
        self.now = 120
        def slow():
            self.assertIs(self.scheduler.active, self.sent[0])
            self.now += 157
        self.gate.on_build = slow
        self.scheduler.poll()
        self.assertEqual(self.gate.builds, 2)
        self.assertEqual(self.scheduler.last_prepare_seconds, 157)
        self.assertEqual(self.scheduler.last_due_lateness_seconds, 80)
        self.assertEqual(self.scheduler.next_refresh_at, 317)
        self.assertIsNone(self.scheduler.poll())

    def test_invalid_or_regressing_clock_fails_closed(self):
        for bad in (-1, float("nan"), float("inf"), True, "40", 1e308):
            with self.subTest(bad=bad):
                self.setUp()
                self.scheduler.poll()
                self.now = bad
                with self.assertRaises(ValueError):
                    self.scheduler.poll()
                self.assertIsNone(self.scheduler.active)
        self.setUp()
        self.now = 10
        self.scheduler.poll()
        self.now = 9
        with self.assertRaisesRegex(ValueError, "monotonic"):
            self.scheduler.poll()
        self.assertIsNone(self.scheduler.active)

    def test_owner_thread_process_and_callback_reentrancy(self):
        self.scheduler.poll()
        failures = []
        def foreign():
            try:
                self.scheduler.poll()
            except RuntimeError as error:
                failures.append(str(error))
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join()
        self.assertEqual(len(failures), 1)
        with patch("hash_job_scheduler.os.getpid", return_value=-1):
            with self.assertRaisesRegex(RuntimeError, "owner"):
                self.scheduler.poll()
        self.assertEqual(self.gate.builds, 1)
        self.scheduler.close()
        scheduler = self.make(publish=lambda unused: scheduler.poll())
        with self.assertRaisesRegex(RuntimeError, "reentrant"):
            scheduler.poll()
        self.assertIsNone(scheduler.active)

    def test_configuration_bounds_and_explicit_close(self):
        for value in (True, 4, 121, 40.0, "40"):
            with self.assertRaises(ValueError):
                self.make(work_update_seconds=value)
        for interval in (5, 40, 120):
            scheduler = self.make(work_update_seconds=interval)
            self.assertEqual(scheduler.work_update_seconds, interval)
            scheduler.poll()
            self.assertEqual(scheduler.next_refresh_at, interval)
            scheduler.close()
            self.assertIsNone(scheduler.active)
            with self.assertRaisesRegex(RuntimeError, "closed"):
                scheduler.poll()

    def test_transport_invalidation_requires_fresh_authorization(self):
        first = self.scheduler.poll()
        self.now = 1
        self.scheduler.invalidate()
        self.assertIsNone(self.scheduler.active)
        self.assertIsNone(self.scheduler.next_refresh_at)
        self.assertEqual(self.withdrawals, [1])
        second = self.scheduler.poll()
        self.assertIsNot(first, second)
        self.assertEqual(self.gate.builds, 2)
        self.assertEqual(self.scheduler.last_update_reason, "initial")


if __name__ == "__main__":
    unittest.main()
