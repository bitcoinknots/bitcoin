#!/usr/bin/env python3
"""Transport/controller decisions with native doubles; regtest checks real PoW."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hash_snapshot import share_target
from hash_stratum import VardiffStratumService
from hash_vardiff import VardiffController


class VardiffStratumTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.gate = SimpleNamespace(profile_version=8, mode="test", rules=1, activation_height=1,
            share_work_bits=4, receive=Mock(return_value=True), rpc=Mock(return_value=None),
            set_share_work_bits=Mock())
        self.controller = VardiffController(initial_work_bits=4, target_share_seconds=1,
                                            clock=lambda: self.now)
        self.service = VardiffStratumService(self.gate, controller=self.controller,
            sign_owner=lambda unused: None, observer_rpc=lambda unused: None, clock=lambda: self.now)
        self.addCleanup(self.service.close)
        self.controller.start()
        self.params = ["sharepool.regtest", "old-job", "00" * 8, "00" * 8, "00" * 8]

    def work(self, *, native_bits=0x01010000, assigned_bits=4):
        envelope = SimpleNamespace(share_work_bits=assigned_bits)
        work = SimpleNamespace(template=SimpleNamespace(header=SimpleNamespace(nBits=native_bits)),
            snapshot=SimpleNamespace(envelope=envelope, owner_signature=bytes(64)),
            authorization=SimpleNamespace(block_for_header=Mock(return_value=b"block")))
        self.service.jobs["old-job"] = work
        return work

    def submit(self, hash_int):
        proof = SimpleNamespace(hash_int=hash_int, header=b"header", block=b"block")
        with patch("hash_stratum.proof_from_sia", return_value=proof):
            return self.service._submit(bytes(4), self.params)

    def test_new_ack_counts_exact_old_assignment_but_duplicate_does_not(self):
        self.work(assigned_bits=4)
        self.gate.share_work_bits = 9
        self.assertTrue(self.submit(128))
        self.assertEqual(self.controller.status()["window_accepted_work"], 16)
        self.gate.receive.return_value = False
        self.assertTrue(self.submit(128))
        self.assertEqual(self.controller.status()["window_accepted_work"], 16)
        self.assertEqual(self.service.stats["acknowledged"], 1)
        self.assertEqual(self.service.stats["duplicate"], 1)
        self.gate.rpc.assert_not_called()

    def test_rejected_target_and_failed_ack_never_influence_controller(self):
        self.work()
        with self.assertRaisesRegex(ValueError, "insufficient"):
            self.submit(1 << 255)
        self.gate.receive.assert_not_called()
        self.gate.receive.side_effect = ValueError("native admission refused")
        with self.assertRaisesRegex(ValueError, "native admission"):
            self.submit(128)
        self.assertEqual(self.controller.status()["window_accepted_work"], 0)

    def test_native_only_winner_is_submitted_without_share_ack_or_credit(self):
        self.work(native_bits=0x207fffff, assigned_bits=255)
        self.assertTrue(self.submit(128))
        self.gate.receive.assert_not_called()
        self.gate.rpc.assert_called_once_with("submitblock", b"block".hex())
        self.assertEqual(self.service.stats["accepted_candidates"], 1)
        self.assertEqual(self.service.stats["native_only_candidates"], 1)
        self.assertEqual(self.service.stats["acknowledged"], 0)
        self.assertEqual(self.controller.status()["window_accepted_work"], 0)

    def test_failed_native_only_submission_cannot_claim_acceptance(self):
        self.work(native_bits=0x207fffff, assigned_bits=255)
        self.gate.rpc.side_effect = RuntimeError("RPC lost")
        with self.assertRaisesRegex(RuntimeError, "not confirmed"):
            self.submit(128)
        self.assertEqual(self.service.stats["acknowledged"], 0)
        self.assertEqual(self.service.stats["accepted_candidates"], 0)
        self.gate.rpc.side_effect = None
        self.gate.rpc.return_value = "bad-block"
        with self.assertRaisesRegex(ValueError, "not accepted"):
            self.submit(128)

    def test_native_rpc_failure_preserves_an_already_durable_share_ack(self):
        self.work(native_bits=0x207fffff, assigned_bits=4)
        self.gate.rpc.side_effect = RuntimeError("RPC lost")
        self.assertTrue(self.submit(128))
        self.assertEqual(self.service.stats["acknowledged"], 1)
        self.assertEqual(self.controller.status()["window_accepted_work"], 16)

    def test_advertised_target_catches_both_shares_and_native_blocks(self):
        work = self.work(native_bits=0x207fffff, assigned_bits=255)
        target = self.service._mining_target(work.template.header, work.snapshot)
        self.assertGreater(target, share_target(0x207fffff, 8, 255))
        self.assertGreater(target, 128)
        work = self.work(native_bits=0x01010000, assigned_bits=4)
        self.assertEqual(self.service._mining_target(work.template.header, work.snapshot),
                         share_target(0x01010000, 8, 4))
        self.assertEqual(self.service.MAX_CLIENTS, 1)


if __name__ == "__main__":
    unittest.main()
