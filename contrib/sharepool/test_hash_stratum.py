#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Transport freshness invariants; native Sia handoff is tested by regtest."""
import threading
import unittest

from hash_stratum import TipLatch


class Client:
    def __init__(self):
        self.closed = threading.Event()

    def shutdown(self, unused):
        self.closed.set()


class HashStratumTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.latch = TipLatch(observation_timeout=2, clock=lambda: self.now)
        self.client = Client()

    def test_unknown_and_expired_native_observation_fail_closed(self):
        self.assertFalse(self.latch.check())
        self.latch.observe("a" * 64)
        self.latch.sockets.add(self.client)
        generation = self.latch.generation
        self.now = 1.999
        self.assertTrue(self.latch.check("a" * 64, generation))
        self.now = 2
        self.assertFalse(self.latch.check("a" * 64, generation))
        self.assertTrue(self.client.closed.is_set())
        self.assertEqual(self.latch.generation, generation + 1)

    def test_tip_change_withdraws_without_owner_service(self):
        self.latch.observe("a" * 64)
        self.latch.sockets.add(self.client)
        generation = self.latch.generation
        observer = threading.Thread(target=lambda: self.latch.observe("b" * 64))
        observer.start()
        self.assertTrue(self.client.closed.wait(1))
        observer.join(timeout=1)
        self.assertFalse(self.latch.check("a" * 64, generation))
        self.assertTrue(self.latch.check("b" * 64, generation + 1))

    def test_reorg_back_to_same_parent_cannot_revive_old_handoff(self):
        self.latch.observe("a" * 64)
        generation = self.latch.generation
        self.latch.observe("b" * 64)
        self.latch.observe("a" * 64)
        self.assertTrue(self.latch.check("a" * 64))
        self.assertFalse(self.latch.check("a" * 64, generation))

    def test_observer_failure_cannot_revive_old_handoff_on_recovery(self):
        self.latch.observe("a" * 64)
        generation = self.latch.generation
        self.latch.sockets.add(self.client)
        self.latch.fail("RPC unavailable")
        self.assertTrue(self.client.closed.is_set())
        self.assertFalse(self.latch.check())
        self.latch.observe("a" * 64)
        self.assertTrue(self.latch.check())
        self.assertFalse(self.latch.check("a" * 64, generation))

    def test_bad_tip_and_clock_rollback_withdraw(self):
        self.latch.observe("a" * 64)
        self.latch.sockets.add(self.client)
        with self.assertRaises(ValueError):
            self.latch.observe("not-a-hash")
        self.assertTrue(self.client.closed.is_set())
        self.now = 5
        self.latch.observe("a" * 64)
        self.now = 4
        self.assertFalse(self.latch.check())

    def test_invalid_time_budgets(self):
        for timeout in (True, 0, -1, float("nan"), float("inf"), 31):
            with self.assertRaises(ValueError):
                TipLatch(observation_timeout=timeout)

    def test_nonfinite_and_throwing_clocks_cannot_prevent_withdrawal(self):
        for value in (float("nan"), float("inf"), -1, True, "bad", 1 << 10000):
            with self.subTest(value=value):
                latch = TipLatch(clock=lambda: 0)
                latch.observe("a" * 64)
                client = Client()
                latch.sockets.add(client)
                latch.clock = lambda: value
                self.assertFalse(latch.check())
                self.assertTrue(client.closed.is_set())
                self.assertIsNone(latch.last_withdrawal)
        latch = TipLatch(clock=lambda: 0)
        latch.observe("a" * 64)
        client = Client()
        latch.sockets.add(client)
        def broken():
            raise RuntimeError("clock failed")
        latch.clock = broken
        latch.fail("observer failed concurrently")
        self.assertTrue(client.closed.is_set())
        self.assertFalse(latch.check())

    def test_observation_clock_failure_closes_existing_connections(self):
        self.latch.observe("a" * 64)
        self.latch.sockets.add(self.client)
        self.now = float("nan")
        with self.assertRaises(ValueError):
            self.latch.observe("a" * 64)
        self.assertTrue(self.client.closed.is_set())
        self.assertFalse(self.latch.check())


if __name__ == "__main__":
    unittest.main()
