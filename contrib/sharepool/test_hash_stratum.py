#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Transport freshness invariants; native Sia handoff is tested by regtest."""
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hash_stratum import HashStratumService, TipLatch, transport_target


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

    def test_optional_transport_target_preserves_default_and_cannot_weaken_native_work(self):
        native = (1 << 256) - 1
        harder = ((1 << 224) - 1) // 4096
        self.assertEqual(transport_target(native), native)
        self.assertEqual(transport_target(native, 4096), harder)
        self.assertEqual(transport_target(harder // 2, 4096), harder // 2)
        for difficulty in (True, 0, -1, 3, 4096.0, 1 << 25, "4096"):
            with self.subTest(difficulty=difficulty), self.assertRaises(ValueError):
                transport_target(native, difficulty)
        for target in (True, 0, -1, 1 << 256, 1.0):
            with self.subTest(target=target), self.assertRaises(ValueError):
                transport_target(target, 4096)

    def test_lower_than_assigned_work_never_reaches_native_gate_or_ack(self):
        gate = SimpleNamespace(profile_version=7, mode="test", rules=1, activation_height=1,
                               receive=Mock(), rpc=Mock())
        service = HashStratumService(gate, sign_owner=lambda unused: None,
                                    observer_rpc=lambda unused: None, transport_difficulty=4096)
        work = SimpleNamespace(template=object(), target=transport_target((1 << 256) - 1, 4096),
                               authorization=Mock())
        service.jobs["test-job"] = work
        params = ["sharepool.regtest", "test-job", "00" * 8, "00" * 8, "00" * 8]
        # This is a rejection/traffic-budget test, not a claim that mocked work
        # has a valid native header or qualifies for any coinbase payment.
        with patch("hash_stratum.proof_from_sia", return_value=SimpleNamespace(hash_int=work.target + 1)):
            with self.assertRaisesRegex(ValueError, "assigned share work"):
                service._submit(bytes(4), params)
        gate.receive.assert_not_called()
        gate.rpc.assert_not_called()
        work.authorization.block_for_header.assert_not_called()
        self.assertEqual(service.stats["acknowledged"], 0)
        service.close()


if __name__ == "__main__":
    unittest.main()
