#!/usr/bin/env python3
"""Causal weighted control and due-job scheduling; no native-validity claim."""
import threading
import unittest

from hash_job_scheduler import HashJobScheduler
from hash_vardiff import VardiffController
from test_hash_job_scheduler import Gate


class VardiffTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.controller = self.make()

    def make(self, **options):
        return VardiffController(**dict(dict(initial_work_bits=4, target_share_seconds=10,
            clock=lambda: self.now), **options))

    def test_requires_explicit_bounded_policy(self):
        for bits in (None, True, -1, 256, 1.0):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                self.make(initial_work_bits=bits)
        for target in (True, 0, 3601, float("nan"), float("inf")):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.make(target_share_seconds=target)
        for interval in (True, 9, 86401, float("nan"), float("inf")):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                self.make(retarget_seconds=interval)
        with self.assertRaises(ValueError):
            self.make(min_work_bits=5)

    def test_initial_assignment_waits_for_publication(self):
        self.now = 1000
        self.assertEqual(self.controller.next_assignment(), 4)
        with self.assertRaises(RuntimeError):
            self.controller.observe(4)
        self.controller.start()
        self.assertEqual(self.controller.status()["window_elapsed_seconds"], 0)

    def test_receipts_never_retarget_or_change_old_assignment(self):
        self.controller.start()
        for unused in range(100):
            self.controller.observe(4)
        self.now = 39
        self.assertEqual(self.controller.next_assignment(), 4)
        self.assertEqual(self.controller.status()["window_accepted_work"], 1600)
        self.now = 40
        self.assertEqual(self.controller.next_assignment(), 5)  # Exactly one step.
        self.assertEqual(self.controller.last_estimate["accepted_work"], 1600)
        self.assertEqual(self.controller.last_estimate["estimated_hashes_per_second"], 40)

    def test_old_and_new_job_shares_keep_original_work_after_retarget(self):
        self.controller.start()
        for unused in range(8):
            self.controller.observe(4)
        self.now = 40
        self.assertEqual(self.controller.next_assignment(), 5)
        self.controller.observe(4)
        self.controller.observe(5)
        self.now = 80
        self.assertEqual(self.controller.next_assignment(), 4)
        self.assertEqual(self.controller.last_estimate["accepted_work"], 48)
        self.assertEqual(self.controller.last_estimate["accepted_shares"], 2)
        self.assertEqual(self.controller.last_estimate["estimated_hashes_per_second"], 1.2)

    def test_actual_elapsed_time_and_late_poll_do_not_create_catchup_retargets(self):
        self.controller.start()
        for unused in range(8):
            self.controller.observe(4)
        self.now = 160
        self.assertEqual(self.controller.next_assignment(), 3)
        self.assertEqual(self.controller.last_estimate["elapsed_seconds"], 160)
        self.assertEqual(self.controller.last_estimate["estimated_hashes_per_second"], 0.8)
        self.assertEqual(self.controller.next_assignment(), 3)
        self.assertEqual(self.controller.observations, 1)

    def test_zero_observations_ease_without_physical_idle_claim(self):
        self.controller.start()
        self.now = 40
        self.assertEqual(self.controller.next_assignment(), 3)
        self.assertEqual(self.controller.last_estimate["accepted_work"], 0)
        self.assertFalse(self.controller.status()["physical_hashrate_attested"])

    def test_deadband_and_configured_bounds(self):
        self.controller.start()
        for unused in range(4):
            self.controller.observe(4)
        self.now = 40
        self.assertEqual(self.controller.next_assignment(), 4)
        bounded = self.make(min_work_bits=4, max_work_bits=4)
        bounded.start()
        self.now = 80
        self.assertEqual(bounded.next_assignment(), 4)
        self.assertEqual(bounded.adjustments, 0)

    def test_job_publication_does_not_reset_observation_window(self):
        self.controller.start()
        self.controller.observe(4)
        self.now = 20
        self.controller.start()
        self.assertEqual(self.controller.status()["window_elapsed_seconds"], 20)
        self.assertEqual(self.controller.status()["window_accepted_work"], 16)

    def test_independent_miner_controllers_do_not_share_assignment(self):
        other = self.make()
        self.controller.start()
        other.start()
        for unused in range(20):
            self.controller.observe(4)
        self.now = 40
        self.assertEqual(self.controller.next_assignment(), 5)
        self.assertEqual(other.next_assignment(), 3)

    def test_bad_clock_and_foreign_owner_cannot_update(self):
        for clock in (lambda: float("nan"), lambda: -1, lambda: 1 << 10000):
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                self.make(clock=clock).start()
        self.controller.start()
        self.now = -1
        with self.assertRaises(ValueError):
            self.controller.next_assignment()
        failures = []
        def foreign():
            try:
                self.controller.observe(4)
            except RuntimeError as error:
                failures.append(error)
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=1)
        self.assertEqual(len(failures), 1)

    def test_controller_only_runs_at_due_scheduler_build(self):
        gate, prepared, published = Gate(), [], []
        def before_build():
            prepared.append((self.now, self.controller.next_assignment()))
        def publish(authorization):
            published.append(authorization)
            self.controller.start()
            return True
        scheduler = HashJobScheduler(gate, sign_owner=lambda unused: b"signed", publish=publish,
            withdraw=lambda: None, clock=lambda: self.now, before_build=before_build)
        self.addCleanup(scheduler.close)
        old = scheduler.poll()
        for second in range(1, 40):
            self.now = second
            gate.receipts += 1
            self.controller.observe(4)
            self.assertIsNone(scheduler.poll())
        self.assertEqual(prepared, [(0, 4)])
        self.assertIs(scheduler.active, old)
        self.now = 40
        scheduler.poll()
        self.assertEqual(prepared, [(0, 4), (40, 5)])
        self.assertEqual(old.receipts, 0)
        self.assertEqual(len(published), 2)


if __name__ == "__main__":
    unittest.main()
