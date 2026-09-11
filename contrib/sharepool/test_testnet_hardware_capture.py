#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Admission/durability regressions; physical hash math has separate tests."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from base_chain_settlement import NativeRPCError, SettlementCommitment, unavailable
from live_protocol import canonical
from precommit_demo import uint256_from_compact
from settlement_sim import merkle_root
from testnet_hardware_capture import (CaptureStore, HardwareCapture, NodeRPC,
                                      TESTNET4_GENESIS)


SCRIPT = bytes.fromhex("0014" + "44" * 20)


class FakeNode:
    def __init__(self, bits="1a00ffff"):
        self.info = {"chain": "testnet4", "initialblockdownload": False}
        self.genesis = TESTNET4_GENESIS
        self.proposal_result = None
        self.submission_error = None
        self.calls = []
        self.gbt = {"rules": ["!segwit", "!blake2b"], "version": 0xa0000000,
                    "height": 150309, "curtime": 1789158160, "mintime": 1789158000,
                    "bits": bits, "previousblockhash": "55" * 32, "coinbasevalue": 5_000_000_000,
                    "weightlimit": 800000, "sizelimit": 4000000, "sigoplimit": 80000,
                    "transactions": [], "coinbaseaux": {}}

    def check_testnet(self):
        if self.info["chain"] != "testnet4" or self.genesis != TESTNET4_GENESIS:
            raise ValueError("wrong native network")
        if self.info["initialblockdownload"]:
            raise ValueError("native node is synchronizing")
        return self.info

    def __call__(self, method, *params):
        self.calls.append((method, params))
        if method == "getblocktemplate":
            return self.proposal_result if params[0].get("mode") == "proposal" else copy.deepcopy(self.gbt)
        if method == "submitblock":
            if self.submission_error:
                raise self.submission_error
            return None
        raise AssertionError("unexpected RPC " + method)


class NodeRPCTests(unittest.TestCase):
    @patch("testnet_hardware_capture.subprocess.run")
    def test_forced_chain_and_no_spurious_empty_rpc_argument(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout='{"chain":"testnet4"}', stderr="")
        rpc = NodeRPC("/test/bitcoin-cli", "/test/data", timeout=9)
        rpc("getblockchaininfo")
        args, kwargs = run.call_args
        self.assertIn("-chain=testnet4", args[0])
        self.assertEqual(args[0][-2:], ["-stdin", "getblockchaininfo"])
        self.assertEqual(kwargs["input"], "")
        self.assertEqual(kwargs["timeout"], 9)
        rpc("getblocktemplate", {"rules": ["segwit", "blake2b"]})
        self.assertEqual(run.call_args.kwargs["input"], '{"rules":["segwit","blake2b"]}\n')
        rpc("getblockhash", 0)
        self.assertEqual(run.call_args.kwargs["input"], "0\n")

    @patch("testnet_hardware_capture.subprocess.run")
    def test_native_chain_genesis_and_ibd_guards(self, run):
        rpc = NodeRPC("/test/bitcoin-cli", "/test/data")
        def response(value):
            return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")
        cases = [({"chain": "main", "initialblockdownload": False}, TESTNET4_GENESIS),
                 ({"chain": "testnet4", "initialblockdownload": False}, "00" * 32),
                 ({"chain": "testnet4", "initialblockdownload": True}, TESTNET4_GENESIS)]
        for info, genesis in cases:
            run.side_effect = [response(info), response(genesis)]
            with self.subTest(info=info, genesis=genesis), self.assertRaises(ValueError):
                rpc.check_testnet()
        run.side_effect = [response({"chain": "testnet4", "initialblockdownload": False}), response(TESTNET4_GENESIS)]
        self.assertEqual(rpc.check_testnet()["chain"], "testnet4")

    @patch("testnet_hardware_capture.subprocess.run")
    def test_rpc_allowlist_and_observer_tip_method(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout='"' + "11" * 32 + '"', stderr="")
        rpc = NodeRPC("/test/bitcoin-cli", "/test/data")
        self.assertEqual(rpc("getbestblockhash"), "11" * 32)
        with self.assertRaisesRegex(ValueError, "outside hardware test scope"):
            rpc("sendtoaddress", "anything", 1)
        self.assertEqual(run.call_count, 1)

    @patch("testnet_hardware_capture.subprocess.run")
    def test_native_body_unavailable_is_preserved_without_arbitrary_error_text(self, run):
        rpc = NodeRPC("/test/bitcoin-cli", "/test/data")
        for description in ("Block not available (pruned data)", "Block not available (not fully downloaded)"):
            run.return_value = SimpleNamespace(returncode=1, stdout="",
                stderr="error code: -1\nerror message:\n" + description + "\n")
            with self.subTest(description=description), self.assertRaises(NativeRPCError) as error:
                rpc("getblock", "11" * 32, 2)
            self.assertTrue(unavailable(error.exception))
            self.assertEqual(str(error.exception), description)
        run.return_value = SimpleNamespace(returncode=1, stdout="",
            stderr="error code: -1\nerror message:\nUnexpected failure with secret-token-example\n")
        with self.assertRaises(NativeRPCError) as error:
            rpc("getblock", "11" * 32, 2)
        self.assertFalse(unavailable(error.exception))
        self.assertNotIn("secret-token-example", str(error.exception))


class HardwareCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "capture.sqlite3"
        self.store = CaptureStore(self.path)
        self.node = FakeNode()
        self.capture = HardwareCapture(self.node, self.store, bind=("127.0.0.1", 0),
                                       miner_ip="127.0.0.1", payout_script=SCRIPT, difficulty=4096)

    def tearDown(self):
        self.capture.close()
        if self.store is not None:
            self.store.close()
        self.directory.cleanup()

    def params(self, job=None):
        return ["sharepool.hardware", job or self.capture.current.template.job_id,
                "00" * 8, "00" * 8, "00" * 8]

    def fake_proof(self, value, identity="99" * 32):
        return SimpleNamespace(hash_int=value, display_hash=identity, header=b"mock native header",
                               work=b"mock ASIC work", block=b"mock full block")

    def submit(self, proof, params=None):
        with patch("testnet_hardware_capture.proof_from_sia", return_value=proof):
            return self.capture.submit(b"ABCD", self.params() if params is None else params, "sharepool.hardware")

    def ordinary_proof(self, identity="99" * 32):
        base_target = uint256_from_compact(self.capture.current.template.header.nBits)
        self.assertLess(base_target, self.capture.share_target)
        return self.fake_proof((base_target + self.capture.share_target) // 2, identity)

    def test_sqlite_acceptance_is_durable_duplicate_and_missing_job_reject(self):
        proof = self.ordinary_proof()
        self.assertTrue(self.submit(proof))
        # A separate native SQLite connection sees the commit before submit's ACK.
        with sqlite3.connect(str(self.path)) as disk:
            self.assertEqual(disk.execute("SELECT count(*) FROM shares").fetchone()[0], 1)
            saved = json.loads(disk.execute("SELECT data FROM shares").fetchone()[0])
        self.assertEqual(saved["hash"], proof.display_hash)
        with self.assertRaisesRegex(ValueError, "duplicate share"):
            self.submit(proof)
        with self.assertRaisesRegex(ValueError, "missing job"):
            self.store.share("different", "unknown-job", {})
        self.assertEqual(self.capture.stats["accepted"], 1)
        self.assertEqual(self.store.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.store.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_capture_cannot_overwrite_a_previous_run_and_raw_rows_survive_restart(self):
        self.submit(self.ordinary_proof())
        self.store.close()
        self.store = None
        with self.assertRaises(FileExistsError):
            CaptureStore(self.path)
        # A process restart reads the committed archive; live resume is forbidden.
        with sqlite3.connect(str(self.path)) as reader:
            jobs = reader.execute("SELECT id,data FROM jobs").fetchall()
            shares = reader.execute("SELECT job,data FROM shares").fetchall()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0][0], jobs[0][0])
        self.assertEqual(json.loads(jobs[0][1])["snapshot"], [])
        self.assertEqual(json.loads(shares[0][1])["weight"], self.capture.work)

    def test_job_snapshot_is_fixed_and_next_job_commits_previous_durable_work(self):
        first = self.capture.current
        initial = self.store.report()["jobs"][0]
        self.assertEqual(initial["snapshot"], [])
        self.submit(self.ordinary_proof())
        self.assertEqual(first.envelope.snapshot_root, merkle_root([]).hex())
        self.capture.refresh()
        second = self.capture.current
        self.assertNotEqual(first.template.job_id, second.template.job_id)
        latest = self.store.report()["jobs"][-1]
        self.assertEqual(latest["snapshot"], self.store.snapshot())
        self.assertEqual(second.envelope.snapshot_root, merkle_root([canonical(row) for row in latest["snapshot"]]).hex())
        self.assertEqual(second.template.commitment, second.envelope.root)
        self.assertFalse(second.clean)
        self.submit(self.ordinary_proof("aa" * 32))
        self.assertEqual(len(latest["snapshot"]), 1)
        self.assertEqual(len(self.store.snapshot()), 2)
        self.assertEqual(self.store.report()["jobs"][0], initial)

    def test_native_parent_change_cleans_job_and_rejects_old_ordinary_share(self):
        old = self.capture.current
        proof = self.ordinary_proof()
        self.node.gbt["previousblockhash"] = "66" * 32
        self.capture.refresh()
        self.assertTrue(self.capture.current.clean)
        with self.assertRaisesRegex(ValueError, "old native parent"):
            self.submit(proof, self.params(old.template.job_id))
        self.assertEqual(self.store.snapshot(), [])

    def test_easier_base_candidate_has_no_harder_share_credit(self):
        self.node.gbt["bits"] = "1d00ffff"
        self.capture.refresh()
        base_target = uint256_from_compact(self.capture.current.template.header.nBits)
        self.assertGreater(base_target, self.capture.share_target)
        proof = self.fake_proof((base_target + self.capture.share_target) // 2)
        self.assertTrue(self.submit(proof))
        report = self.store.report()
        self.assertEqual(report["shares"], [])
        self.assertEqual(len(report["candidates"]), 1)
        self.assertFalse(report["candidates"][0]["credited_as_share"])
        self.assertEqual(report["candidates"][0]["block"], proof.block.hex())
        self.assertEqual(self.capture.stats["accepted"], 0)
        self.assertEqual(self.capture.stats["block_candidates"], 1)
        self.capture.refresh()
        self.assertEqual(self.capture.current.envelope.snapshot_root, merkle_root([]).hex())

    def test_submission_rpc_failure_preserves_candidate_share_and_ack(self):
        self.capture.submit_blocks = True
        self.node.submission_error = NativeRPCError(-28, "warming up")
        proof = self.fake_proof(1)
        self.assertTrue(self.submit(proof))
        report = self.store.report()
        self.assertEqual(len(report["shares"]), 1)
        self.assertEqual(len(report["candidates"]), 1)
        self.assertTrue(report["candidates"][0]["credited_as_share"])
        self.assertEqual(report["events"][-1]["data"]["result"], {"rpc_failure": "NativeRPCError"})
        self.assertEqual(self.capture.stats["accepted"], 1)
        with sqlite3.connect(str(self.path)) as disk:
            self.assertEqual(disk.execute("SELECT count(*) FROM candidates").fetchone()[0], 1)
            self.assertEqual(disk.execute("SELECT count(*) FROM shares").fetchone()[0], 1)

    def test_candidate_capacity_failure_leaves_no_partial_share_or_stats(self):
        job = self.capture.current.template.job_id
        for index in range(64):
            self.store.candidate(f"{index:064x}", {"proof": {"job_id": job}, "block": "00"})
        before = self.store.report()
        with self.assertRaisesRegex(ValueError, "candidate limit"):
            self.submit(self.fake_proof(1))
        self.assertEqual(self.store.report(), before)
        self.assertEqual(self.store.snapshot(), [])
        self.assertEqual(self.capture.stats["accepted"], 0)
        self.assertEqual(self.capture.stats["block_candidates"], 0)
        self.assertFalse(self.store.db.in_transaction)

    def test_candidate_insert_abort_rolls_back_preceding_share_and_allows_retry(self):
        self.store.db.execute("""CREATE TRIGGER fail_candidate BEFORE INSERT ON candidates
            BEGIN SELECT RAISE(ABORT, 'simulated candidate insertion failure'); END""")
        self.store.db.commit()
        before = self.store.report()
        proof = self.fake_proof(1)
        with self.assertRaisesRegex(ValueError, "rejected proof insert"):
            self.submit(proof)
        self.assertEqual(self.store.report(), before)
        self.assertEqual(self.capture.stats["accepted"], 0)
        self.assertEqual(self.capture.stats["block_candidates"], 0)
        self.assertFalse(self.store.db.in_transaction)
        with sqlite3.connect(str(self.path)) as reader:
            self.assertEqual(reader.execute("SELECT count(*) FROM shares").fetchone()[0], 0)
            self.assertEqual(reader.execute("SELECT count(*) FROM candidates").fetchone()[0], 0)
        self.store.db.execute("DROP TRIGGER fail_candidate")
        self.store.db.commit()
        self.assertTrue(self.submit(proof))
        self.assertEqual(len(self.store.report()["shares"]), 1)
        self.assertEqual(len(self.store.report()["candidates"]), 1)
        self.assertEqual(self.capture.stats["accepted"], 1)

    def test_candidate_only_requires_existing_job_and_nonempty_admission(self):
        with self.assertRaisesRegex(ValueError, "missing job"):
            self.store.candidate("aa" * 32, {"proof": {"job_id": "unknown"}})
        with self.assertRaisesRegex(ValueError, "share or candidate"):
            self.store.record_proof("aa" * 32, self.capture.current.template.job_id)
        self.assertEqual(self.store.report()["candidates"], [])
        self.assertFalse(self.store.db.in_transaction)

    def test_submit_disabled_never_calls_native_submission(self):
        self.assertTrue(self.submit(self.fake_proof(1)))
        self.assertFalse(any(method == "submitblock" for method, _ in self.node.calls))
        self.assertEqual(self.store.report()["events"][-1]["data"]["result"], "submission-disabled")

    def test_unknown_unauthorized_and_expired_jobs_never_credit(self):
        unknown = self.params("unknown")
        unauthorized = self.params()
        unauthorized[0] = "other-user"
        for params in (unknown, unauthorized):
            with self.subTest(params=params), patch("testnet_hardware_capture.proof_from_sia") as proof:
                with self.assertRaises(ValueError):
                    self.capture.submit(b"ABCD", params, "sharepool.hardware")
                proof.assert_not_called()
        identity = self.capture.current.template.job_id
        self.capture.jobs[identity] = replace(self.capture.current, issued=time.monotonic() - 181)
        with patch("testnet_hardware_capture.proof_from_sia") as proof:
            with self.assertRaisesRegex(ValueError, "expired"):
                self.capture.submit(b"ABCD", self.params(), "sharepool.hardware")
            proof.assert_not_called()
        self.assertEqual(self.store.snapshot(), [])

    def test_failed_native_proposal_does_not_publish_or_persist_new_job(self):
        before = self.capture.current
        self.node.gbt["curtime"] += 1
        self.node.proposal_result = "bad-txnmrklroot"
        with self.assertRaisesRegex(ValueError, "rejected hardware template proposal"):
            self.capture.refresh()
        self.assertIs(self.capture.current, before)
        self.assertEqual(len(self.store.report()["jobs"]), 1)

    def test_network_change_prevents_refresh_and_native_candidate_submission(self):
        self.node.info["chain"] = "main"
        with self.assertRaisesRegex(ValueError, "wrong native network"):
            self.capture.refresh()
        self.capture.submit_blocks = True
        self.assertTrue(self.submit(self.fake_proof(1)))
        self.assertFalse(any(method == "submitblock" for method, _ in self.node.calls))
        self.assertEqual(self.store.report()["events"][-1]["data"]["result"], {"rpc_failure": "ValueError"})

    def test_share_below_neither_target_does_not_write(self):
        with self.assertRaisesRegex(ValueError, "insufficient hardware share work"):
            self.submit(self.fake_proof((1 << 256) - 1))
        self.assertEqual(self.store.report()["shares"], [])
        self.assertEqual(self.store.report()["candidates"], [])


if __name__ == "__main__":
    unittest.main()
