#!/usr/bin/env python3
"""Fake bridge plus real disposable worker processes; never contact a device."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from goldshell_test_guard import GuardError
from goldshell_test_supervisor import MiningWorker, READY, _ready, supervise_test
from test_goldshell_test_guard import FakeBridge, ORIGINAL, SETTINGS, TEST_POOL, identities


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.bridge = FakeBridge()
        self.worker = None

    def run_case(self, code, *, seconds=1, after_mutation=None):
        ready = self.directory / "ready"
        command = [sys.executable, "-c", "import os,time,signal; " +
            "fd=os.open(" + repr(str(ready)) + ",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); " +
            "os.write(fd," + repr(READY) + "); os.close(fd); " + code]

        def factory(command, log):
            self.worker = MiningWorker(command, log)
            return self.worker

        def bridge(method, path, body=None):
            if method == "DELETE":
                self.assertIsNotNone(self.worker.poll(), "worker must be reaped before restoration")
            result = self.bridge(method, path, body)
            if after_mutation is not None and method == "POST":
                after_mutation(self.worker)
            return result

        result = supervise_test(bridge, test_pool=TEST_POOL, backup_path=self.directory / "backup",
            command=command, worker_log=self.directory / "log", ready_path=ready,
            seconds=seconds, ready_seconds=2, worker_factory=factory)
        self.assertEqual(identities(self.bridge.pools), identities(ORIGINAL))
        self.assertEqual(self.bridge.settings, SETTINGS)
        self.assertIsNotNone(self.worker.poll())
        self.assertTrue(result.restored)
        self.assertEqual((self.directory / "backup").stat().st_mode & 0o777, 0o600)
        return result

    def test_successful_worker_is_reaped_before_restoration(self):
        result = self.run_case("time.sleep(0.2)")
        self.assertTrue(result.ok)

    def test_hung_worker_is_killed_then_original_configuration_restored(self):
        result = self.run_case("time.sleep(60)", seconds=0.1)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_stage, "run_test")

    def test_term_ignoring_worker_is_force_killed_and_reaped(self):
        result = self.run_case("signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)", seconds=0.1)
        self.assertFalse(result.ok)
        self.assertEqual(self.worker.poll(), -signal.SIGKILL)

    def test_worker_death_after_pool_change_still_restores(self):
        result = self.run_case("time.sleep(60)",
            after_mutation=lambda worker: os.kill(worker.process.pid, signal.SIGKILL))
        self.assertFalse(result.ok)

    def test_lost_add_response_stops_worker_before_restoration(self):
        self.bridge.fail_after[("POST", "/api/miner/pools")] = 1
        result = self.run_case("time.sleep(60)")
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_stage, "add_test_pool")

    def test_failed_readiness_never_mutates_pools(self):
        with self.assertRaises(GuardError):
            supervise_test(self.bridge, test_pool=TEST_POOL, backup_path=self.directory / "backup",
                command=[sys.executable, "-c", "raise SystemExit(1)"], worker_log=self.directory / "log",
                ready_path=self.directory / "ready", ready_seconds=1)
        self.assertFalse(self.bridge.mutations)

    def test_readiness_waits_for_exclusive_link_publication_to_finish(self):
        staging, final = self.directory / "staging", self.directory / "ready"
        descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(descriptor, READY)
        os.close(descriptor)
        os.link(staging, final)
        self.assertFalse(_ready(final))
        staging.unlink()
        self.assertTrue(_ready(final))

    def test_cleanup_failure_does_not_veto_or_mask_verified_restoration(self):
        ready = self.directory / "ready"
        class FailedCleanupWorker:
            def __init__(self, command, log):
                descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(descriptor, READY)
                os.close(descriptor)
                self.polls = self.stops = 0

            def poll(self):
                self.polls += 1
                return None if self.polls == 1 else 0

            def stop(self):
                self.stops += 1
                raise GuardError("simulated worker cleanup failure")

        result = supervise_test(self.bridge, test_pool=TEST_POOL, backup_path=self.directory / "backup",
            command=["unused-fake-worker"], worker_log=self.directory / "log", ready_path=ready,
            seconds=1, ready_seconds=1, worker_factory=FailedCleanupWorker)
        self.assertEqual(identities(self.bridge.pools), identities(ORIGINAL))
        self.assertEqual(self.bridge.settings, SETTINGS)
        self.assertTrue(result.restored)
        self.assertTrue(result.test_completed)
        self.assertEqual(result.restore_failures, ())
        self.assertEqual(result.failure_stage, "before_restore")
        self.assertTrue(result.worker_cleanup_failed)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
