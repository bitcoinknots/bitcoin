#!/usr/bin/env python3
"""Capture durability and malformed-input gates; native replay has its fixture."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from native_mining_gate import REGTEST_GENESIS
from v7_hardware_capture import (CaptureStore, canonical, replay_capture, require_captured_winner,
                                 submission_params, write_terminal_report)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def store(self):
        store = CaptureStore(self.directory / "capture.sqlite")
        self.addCleanup(store.close)
        return store

    def test_committed_records_export_exactly_and_existing_artifacts_are_preserved(self):
        store = self.store()
        store.append("policy", {"profile": 7})
        store.append("job", {"bytes": "public fixture"})
        path = self.directory / "capture.jsonl"
        digest = store.export(path)
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(store.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(path.read_bytes(), b"".join(raw + b"\n" for raw, in store.db.execute("SELECT data FROM records ORDER BY sequence")))
        with self.assertRaises(FileExistsError):
            store.export(path)
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_exceptional_and_unfinished_terminal_reports_cannot_claim_success(self):
        path = self.directory / "failed.json"
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            try:
                raise RuntimeError("fixture failure")
            finally:
                write_terminal_report(path, {"result": "running", "mode": "software"})
        self.assertEqual(json.loads(path.read_bytes())["result"], "failed")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        stale = self.directory / "stale-success.json"
        write_terminal_report(stale, {"result": "passed"})
        self.assertEqual(json.loads(stale.read_bytes())["result"], "failed")
        with self.assertRaises(FileExistsError):
            write_terminal_report(path, {}, successful=True)
        self.assertEqual(json.loads(path.read_bytes())["result"], "failed")

    def test_explicit_completed_report_can_pass(self):
        path = self.directory / "passed.json"
        write_terminal_report(path, {"result": "failed", "proofs": 4}, successful=True)
        self.assertEqual(json.loads(path.read_bytes()), {"result": "passed", "proofs": 4})

    def test_database_failure_latches_capture_without_advancing_counters_or_export(self):
        store = self.store()
        store.append("policy", {})
        before = store.count, store.bytes
        store.db.execute("CREATE TRIGGER reject_insert BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            store.append("job", {})
        self.assertEqual((store.count, store.bytes), before)
        self.assertTrue(store.failed)
        with self.assertRaises(ValueError):
            store.export(self.directory / "refused.jsonl")
        self.assertFalse((self.directory / "refused.jsonl").exists())

    def test_budget_failure_is_latched_before_a_record_can_be_claimed(self):
        store = self.store()
        with patch("v7_hardware_capture.MAX_RECORDS", 0), self.assertRaises(ValueError):
            store.append("policy", {})
        self.assertEqual((store.count, store.bytes), (0, 0))
        with self.assertRaises(ValueError):
            store.append("policy", {})

    def test_malformed_policy_never_replays_mutating_rpc(self):
        calls = []
        def rpc(method, *args):
            calls.append(method)
            return {"getblockchaininfo": {"chain": "regtest"}, "getblockcount": 0,
                    "getblockhash": REGTEST_GENESIS, "getnetworkinfo": {"networkactive": False, "connections": 0},
                    "getsharepoolhashstatus": {"mode": "hash-only-v7-compact-tides"}}[method]
        policy = {"sequence": 1, "kind": "policy", "data": {"profile": 7, "genesis": REGTEST_GENESIS,
            "mode": "hardware", "transport_difficulty": 1}}
        path = self.directory / "bad.jsonl"
        path.write_bytes(canonical(policy) + b"\n")
        with self.assertRaises(ValueError):
            replay_capture(path, rpc)
        self.assertFalse(any(method.startswith(("submit", "validate")) for method in calls))

    def test_submission_requires_exact_authorized_five_fields_and_job_id(self):
        params = ["sharepool.regtest", "job-123", "00" * 8, "12345678", "00" * 8]
        self.assertEqual(submission_params({"job_id": "job-123", "params": params}), params)
        for malformed in (params[:-1], params + ["extra"], ["someone-else"] + params[1:],
                          params[:1] + ["other-job"] + params[2:], params[:2] + [7] + params[3:],
                          params[:2] + ["0" * 257] + params[3:], tuple(params)):
            with self.subTest(params=malformed), self.assertRaises(ValueError):
                submission_params({"job_id": "job-123", "params": malformed})

    def test_every_winner_requires_its_exact_captured_proof_including_final_block(self):
        captured = {"first": b"first-block", "final": b"final-block"}
        for block_hash, block_raw in captured.items():
            require_captured_winner(block_hash, block_raw, captured)
        for block_hash, block_raw in (("final", b"another-valid-header"),
                                      ("uncaptured-final", b"final-block"),
                                      ("first", b"altered-body")):
            with self.subTest(block_hash=block_hash), self.assertRaises(ValueError):
                require_captured_winner(block_hash, block_raw, captured)


if __name__ == "__main__":
    unittest.main()
