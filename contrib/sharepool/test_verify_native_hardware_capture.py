#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Archive integrity tests; native replay uses a separately running real node."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from native_hardware_capture import NativeCaptureStore, NativeHardwareCapture
from test_native_hardware_capture import FakeNativeRPC
from testnet_template import proof_from_sia, sia_notify
from verify_native_hardware_capture import verify_capture


def fixture(count=6):
    with tempfile.TemporaryDirectory() as directory:
        store = NativeCaptureStore(Path(directory) / "capture.sqlite")
        capture = None
        try:
            capture = NativeHardwareCapture(FakeNativeRPC(), store,
                gate_path=Path(directory) / "gate.sqlite", bind=("127.0.0.1", 0),
                miner_ip="127.0.0.1", payout_script=b"\x00\x14" + b"U" * 20)
            for unused in range(count):
                active = capture.current
                prefix, extra = bytes.fromhex("01000000"), bytes(8)
                ntime = sia_notify(active.template, prefix)[7]
                for nonce in range(1000):
                    nonce_text = nonce.to_bytes(8, "little").hex()
                    proof = proof_from_sia(active.template, prefix, extra, ntime, nonce_text)
                    if capture.share_target < proof.hash_int <= capture.native_share_target:
                        params = ["sharepool.hardware", active.template.job_id, extra.hex(), ntime, nonce_text]
                        capture._process_proof(prefix, params)
                        break
                else:
                    raise AssertionError("fixture PoW search exhausted")
            return capture.report()
        finally:
            if capture is not None:
                capture.close()
            store.close()


class ReplayRPC(FakeNativeRPC):
    def __call__(self, method, *args):
        result = super().__call__(method, *args)
        if method == "getblockchaininfo":
            result["bestblockhash"] = self.chain[-1]
        return result


class NativeHardwareVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.capture = deepcopy(self.original)

    def test_replays_every_proof_and_historical_payment(self):
        result = verify_capture(self.capture)
        self.assertEqual(result["jobs_verified"], 7)
        self.assertEqual(result["asic_proofs_replayed"], 6)
        self.assertEqual(result["accepted_blocks_verified"], 6)
        self.assertEqual(result["historically_settled_proofs"], 5)
        self.assertEqual(len(result["pending_proofs"]), 1)
        self.assertEqual(result["native_expected_work"], 12)
        self.assertEqual(result["assigned_difficulty_proofs"], 0)
        self.assertFalse(result["independent_native_replay"])

    def test_exact_asic_and_native_header_and_full_body_are_required(self):
        for field in ("header", "work_header", "block", "share_wire"):
            with self.subTest(field=field):
                data = deepcopy(self.original)
                raw = bytearray.fromhex(data["shares"][0][field])
                raw[-1] ^= 1
                data["shares"][0][field] = raw.hex()
                with self.assertRaises(ValueError):
                    verify_capture(data)

    def test_current_manifest_and_direct_payout_archive_are_exact(self):
        for field in ("manifest", "coinbase", "commitment"):
            with self.subTest(field=field):
                data = deepcopy(self.original)
                raw = bytearray.fromhex(data["jobs"][0][field])
                raw[-1] ^= 1
                data["jobs"][0][field] = raw.hex()
                with self.assertRaises(ValueError):
                    verify_capture(data)
        self.capture["jobs"][0]["payouts"][0]["satoshis"] -= 1
        with self.assertRaises(ValueError):
            verify_capture(self.capture)

    def test_candidate_only_work_cannot_claim_harder_credit(self):
        for value in (True, 0, "false"):
            data = deepcopy(self.original)
            data["shares"][0]["meets_assigned_target"] = value
            with self.assertRaisesRegex(ValueError, "credit mismatch"):
                verify_capture(data)
        self.capture["shares"][0]["native_expected_work"] = 4096 * (1 << 32)
        with self.assertRaisesRegex(ValueError, "credit mismatch"):
            verify_capture(self.capture)

    def test_missing_proof_or_candidate_never_partially_verifies(self):
        for field in ("shares", "candidates"):
            data = deepcopy(self.original)
            data[field].pop()
            with self.assertRaises(ValueError):
                verify_capture(data)
        self.capture["events"] = [e for e in self.capture["events"] if e["kind"] != "native_block_accepted"]
        with self.assertRaisesRegex(ValueError, "acceptance evidence"):
            verify_capture(self.capture)

    def test_expired_paid_nullifiers_do_not_become_pending_again(self):
        self.capture["pending_proofs"] = sorted(row["hash"] for row in self.capture["shares"])
        with self.assertRaisesRegex(ValueError, "historical settled"):
            verify_capture(self.capture)

    def test_fresh_native_replay_visits_all_origins_and_blocks(self):
        rpc = ReplayRPC()
        result = verify_capture(self.capture, native_rpc=rpc)
        self.assertTrue(result["independent_native_replay"])
        self.assertEqual(len(rpc.chain), 7)
        self.assertEqual(rpc.chain[-1], result["last_native_tip"])

    def test_native_replay_refuses_wrong_network_existing_chain_and_proposal_failure(self):
        rpc = ReplayRPC()
        rpc.network = "main"
        with self.assertRaisesRegex(ValueError, "fresh isolated"):
            verify_capture(self.capture, native_rpc=rpc)
        rpc = ReplayRPC()
        rpc.chain.append("11" * 32)
        with self.assertRaisesRegex(ValueError, "fresh isolated"):
            verify_capture(self.capture, native_rpc=rpc)
        rpc = ReplayRPC()
        def rejected(method, *args):
            if method == "getblocktemplate" and args[0].get("mode") == "proposal":
                return "bad-sharepool-payout"
            return rpc(method, *args)
        with self.assertRaisesRegex(ValueError, "full origin proposal"):
            verify_capture(self.capture, native_rpc=rejected)
        self.assertEqual(len(rpc.chain), 1)

    def test_failed_capture_and_counter_tampering_reject(self):
        self.capture["failure"] = "native_processing_failure"
        with self.assertRaisesRegex(ValueError, "failed native capture"):
            verify_capture(self.capture)
        self.capture = deepcopy(self.original)
        self.capture["stats"]["durable_acknowledgments_ready"] -= 1
        with self.assertRaisesRegex(ValueError, "counter mismatch"):
            verify_capture(self.capture)


if __name__ == "__main__":
    unittest.main()
