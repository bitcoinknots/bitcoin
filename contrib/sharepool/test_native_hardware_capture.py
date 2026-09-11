#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Hardware harness fault/ownership tests; native consensus has separate tests."""
from pathlib import Path
import queue
import tempfile
import threading
import unittest
from unittest.mock import patch

from native_enforcement import MAX_MANIFEST, MAX_SHARE_AGE, MAX_SHARES, RULES_HASH, SHARE_BITS
from native_hardware_capture import NativeCaptureStore, NativeHardwareCapture, Request
from native_mining_gate import REGTEST_GENESIS, parse_block, parse_share
from testnet_template import proof_from_sia, sia_notify


class FakeNativeRPC:
    def __init__(self):
        self.chain = [REGTEST_GENESIS]
        self.blocks = {}
        self.call_threads = []
        self.network = "regtest"
        self.transactions = []
        self.reward = 5_000_000_000

    def __call__(self, method, *args):
        self.call_threads.append(threading.get_ident())
        if method == "getblockchaininfo":
            return {"chain": self.network, "blocks": len(self.chain) - 1}
        if method == "getnetworkinfo":
            return {"networkactive": False, "connections": 0}
        if method == "getblockhash":
            return self.chain[args[0]]
        if method == "getbestblockhash":
            return self.chain[-1]
        if method == "getblock":
            return self.blocks[args[0]].serialize().hex()
        if method == "getblockheader":
            return {"hash": args[0], "height": self.chain.index(args[0])}
        if method == "submitblock":
            block = parse_block(bytes.fromhex(args[0]))
            assert f"{block.hashPrevBlock:064x}" == self.chain[-1]
            identity = f"{block.rehash():064x}"
            self.blocks[identity] = block
            self.chain.append(identity)
            return None
        if method == "validatesharepoolshare":
            share = parse_share(bytes.fromhex(args[0]))
            return {"valid": True, "proof_id": f"{share.proof_id:064x}",
                "pool": f"{share.envelope.pool:064x}", "owner": share.envelope.public_key.hex(),
                "origin_height": share.envelope.height, "payout_script": share.envelope.payout_script.hex(),
                "share_bits": f"{SHARE_BITS:08x}"}
        if method == "getblocktemplate":
            if args[0].get("mode") == "proposal":
                return None
            return {"height": len(self.chain), "previousblockhash": self.chain[-1],
                "rules": ["!sharepool", "!blake2b", "!segwit"], "version": 0xA0000000,
                "curtime": 1_800_000_000 + len(self.chain), "mintime": 1_700_000_000,
                "bits": f"{SHARE_BITS:08x}", "coinbasevalue": self.reward,
                "transactions": self.transactions, "sizelimit": 4_000_000, "weightlimit": 4_000_000,
                "sharepool": {"version": 1, "activation_height": 1, "genesis": REGTEST_GENESIS,
                    "rules_root": f"{RULES_HASH:064x}", "share_bits": f"{SHARE_BITS:08x}",
                    "max_share_age": MAX_SHARE_AGE, "max_shares": MAX_SHARES,
                    "max_manifest_bytes": MAX_MANIFEST, "requires_completion": True}}
        raise AssertionError(method)


class NativeHardwareCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = NativeCaptureStore(Path(self.directory.name) / "capture.sqlite")
        self.addCleanup(self.store.close)
        self.rpc = FakeNativeRPC()
        self.capture = NativeHardwareCapture(self.rpc, self.store,
            gate_path=Path(self.directory.name) / "gate.sqlite", bind=("127.0.0.1", 0),
            miner_ip="127.0.0.1", payout_script=b"\x00\x14" + b"U" * 20)
        self.addCleanup(self.capture.close)

    def submission(self, *, active=None, start=0):
        active = active or self.capture.current
        prefix, extra = b"\x01\x00\x00\x00", bytes(8)
        ntime = sia_notify(active.template, prefix)[7]
        for nonce in range(start, start + 1000):
            text = nonce.to_bytes(8, "little").hex()
            proof = proof_from_sia(active.template, prefix, extra, ntime, text)
            if self.capture.share_target < proof.hash_int <= self.capture.native_share_target:
                return prefix, ["sharepool.hardware", active.template.job_id, extra.hex(), ntime, text], proof
        self.fail("native fixture search exhausted")

    def test_dispatch_fence_runs_on_owner_and_can_refuse(self):
        owner = threading.get_ident()
        result = []
        started = threading.Event()
        def dispatch():
            started.set()
            result.append(self.capture.prepare_dispatch(self.capture.current))
        thread = threading.Thread(target=dispatch)
        with patch.object(self.capture.gate, "ready_for_dispatch", side_effect=lambda auth: threading.get_ident() == owner) as fence:
            thread.start()
            started.wait(1)
            request = self.capture.requests.get(timeout=1)
            self.capture._handle(request)
            thread.join(1)
            self.assertEqual(result, [True])
            fence.assert_called_once()
        request = Request("dispatch", self.capture.current)
        with patch.object(self.capture.gate, "ready_for_dispatch", return_value=False), patch.object(self.capture, "refresh") as refresh:
            self.capture._handle(request)
            self.assertFalse(request.result)
            refresh.assert_called_once()
        self.assertEqual(set(self.rpc.call_threads), {owner})

    def test_handler_ack_waits_for_both_durable_stores_and_native_acceptance(self):
        prefix, params, proof = self.submission()
        results = []
        def miner():
            results.append(self.capture.submit(prefix, params, "sharepool.hardware"))
        thread = threading.Thread(target=miner)
        thread.start()
        request = self.capture.requests.get(timeout=1)
        self.assertFalse(request.done.is_set())
        self.assertEqual(self.store.snapshot(), [])
        self.capture._handle(request)
        thread.join(1)
        self.assertEqual(results, [True])
        self.assertTrue(self.store.has_proof(proof.display_hash))
        self.assertEqual(self.rpc.chain[-1], proof.display_hash)
        self.assertEqual(self.capture.stats["assigned_difficulty_shares"], 0)
        self.assertEqual(self.capture.stats["native_blocks_accepted"], 1)
        self.assertEqual(self.capture.current.manifest.shares[0].proof_id, proof.hash_int)
        self.assertEqual(set(self.rpc.call_threads), {threading.get_ident()})

    def test_partial_archive_retry_completes_existing_gate_receipt(self):
        prefix, params, proof = self.submission()
        with patch.object(self.store, "persist_native_proof", side_effect=OSError("fixture disk error")):
            with self.assertRaises(OSError):
                self.capture._process_proof(prefix, params)
        self.assertFalse(self.store.has_proof(proof.display_hash))
        self.assertEqual(self.capture.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.assertEqual(self.capture.stats["durable_acknowledgments_ready"], 0)
        self.assertTrue(self.capture._process_proof(prefix, params))
        self.assertTrue(self.store.has_proof(proof.display_hash))
        self.assertEqual(self.capture.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.capture._process_proof(prefix, params)

    def test_historical_payments_do_not_expire_back_into_pending(self):
        proofs = []
        for unused in range(6):
            prefix, params, proof = self.submission()
            proofs.append(proof.display_hash)
            self.capture._process_proof(prefix, params)
        report = self.capture.report()
        self.assertEqual(report["pending_proofs"], proofs[-1:])
        self.assertEqual(report["stats"]["native_blocks_accepted"], 6)
        self.assertEqual(report["format"], "sharepool-native-hardware-spn1-v1")

    def test_old_parent_work_is_credited_without_submitting_side_block(self):
        old = self.capture.current
        prefix, params, proof = self.submission(active=old)
        self.capture._process_proof(prefix, params)
        old_nonce = int.from_bytes(bytes.fromhex(params[4]), "little")
        prefix, params, stale = self.submission(active=old, start=old_nonce + 1)
        self.capture._process_proof(prefix, params)
        self.assertEqual(self.rpc.chain[-1], proof.display_hash)
        self.assertEqual(self.capture.stats["old_parent_shares"], 1)
        self.assertEqual({s.proof_id for s in self.capture.current.manifest.shares}, {proof.hash_int, stale.hash_int})

    def test_shutdown_cancels_bounded_queue_and_never_acknowledges(self):
        requests = [Request("dispatch", self.capture.current) for unused in range(4)]
        for request in requests:
            self.capture.requests.put_nowait(request)
        with self.assertRaisesRegex(RuntimeError, "queue is full"):
            self.capture._enqueue("dispatch", self.capture.current)
        self.capture.close()
        self.assertTrue(all(request.done.is_set() and request.error is not None for request in requests))
        self.assertTrue(self.capture.requests.empty())

    def test_post_receipt_native_rejection_stops_and_raises_run(self):
        prefix, params, unused = self.submission()
        original = self.capture.rpc
        self.capture.rpc = lambda method, *args: "bad-native-fixture" if method == "submitblock" else original(method, *args)
        request = Request("submit", (prefix, params))
        self.capture.requests.put_nowait(request)
        with self.assertRaisesRegex(RuntimeError, "capture failed"):
            self.capture.run(0.1)
        self.assertTrue(request.done.is_set())
        self.assertIsNotNone(request.error)
        self.assertEqual(self.capture.stats["durable_acknowledgments_ready"], 0)

    def test_empty_template_and_exact_reward_are_required(self):
        self.rpc.transactions = [{"data": "00"}]
        with self.assertRaisesRegex(ValueError, "empty transaction"):
            self.capture.refresh()
        self.rpc.transactions = []
        self.rpc.reward -= 1
        with self.assertRaisesRegex(ValueError, "exact subsidy"):
            self.capture.refresh()


if __name__ == "__main__":
    unittest.main()
