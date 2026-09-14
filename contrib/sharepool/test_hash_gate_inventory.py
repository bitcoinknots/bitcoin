#!/usr/bin/env python3
"""V8 inventory admission pressure and retry cursors with a native RPC double."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_mining_gate import HashMiningGate, PROOF
from hash_snapshot import solve_share
from native_mining_gate import template_id
from test_hash_gate_origin_cache import AssignedRPC
from test_hash_snapshot import SCRIPT
from test_hash_variable import variable_fixture


class PagedAssignedRPC(AssignedRPC):
    def __call__(self, method, *args):
        if method == "getsharepoolhashrecent":
            self.calls.append((method, args))
            after, count = args
            entries = [{"sequence": index + 1, "hash": identity}
                       for index, identity in enumerate(self.snapshots)]
            latest = len(entries)
            gap = after > latest
            page = [entry for entry in entries if entry["sequence"] > (0 if gap else after)][:count]
            return {"entries": page, "next": page[-1]["sequence"] if page else after,
                    "latest": latest, "gap": gap, "epoch": "11" * 32}
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            after, count = args if args else (None, 1024)
            ids = sorted(self.snapshots, key=lambda value: bytes.fromhex(value)[::-1])
            if after is not None:
                ids = [value for value in ids if bytes.fromhex(value)[::-1] > bytes.fromhex(after)[::-1]]
            page = ids[:count]
            result.update(inventory=page, inventory_next=page[-1] if len(ids) > count else None,
                          inventory_complete=len(ids) <= count, inventory_revision=len(self.snapshots))
        return result


class InventoryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="inventory-admission-")
        self.addCleanup(self.directory.cleanup)
        self.rpc = PagedAssignedRPC()
        self.origin, self.opening = variable_fixture()
        self.gate = None
        self.addCleanup(lambda: self.gate.close() if self.gate is not None else None)

    def setup_source(self, *, count=3, budget=4096):
        self.gate = HashMiningGate(Path(self.directory.name) / "gate.sqlite", rpc=self.rpc,
            pool=3, public_key=self.opening.envelope.public_key, payout_script=SCRIPT,
            profile_version=8, share_work_bits=0, snapshot_budget=budget)
        self.rpc.gate = self.gate
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        proofs, nonce = [], 0
        for _ in range(count):
            proof = solve_share(self.origin, self.opening, start_nonce=nonce)
            nonce = proof.header.nNonce + 1
            proofs.append(proof)
        _, source = variable_fixture(pool=9, ntime=1700000100,
                                     templates=(self.origin,), shares=tuple(proofs))
        self.rpc.snapshots[source.hash_hex] = source.serialize().hex()
        self.source = source
        return source.shares

    def cursor(self, share=0):
        return {"after": None, "snapshot": self.source.hash_hex, "share": share}

    def scan(self, share=0, **options):
        return self.gate.sync_native_receipts(cursor=self.cursor(share), limit=1, **options)

    def assert_absent(self, proof):
        with self.assertRaises(KeyError):
            self.gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_tight_budget_stops_at_exact_unacknowledged_proof_and_can_retry(self):
        proofs = self.setup_source(budget=1200)
        before = len(self.rpc.calls)
        result = self.scan()
        self.assertEqual(result["accepted"], [f"{proof.proof_id:064x}" for proof in proofs[:2]])
        self.assertEqual((result["capacity_refused"], result["limit_reason"], result["proofs_examined"]),
                         (1, "admission-capacity", 3))
        self.assertEqual(result["deferred"][0]["reason"], "local-admission-capacity")
        self.assertEqual(result["deferred"][0]["retry_cursor"], self.cursor(2))
        self.assertEqual(result["cursor"]["archive"], self.cursor(2))
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 2)
        self.assert_absent(proofs[2])
        # Every fresh import was natively checked, including the locally
        # refused one, without rewriting its already available dependencies.
        calls = self.rpc.calls[before:]
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in calls), 3)
        self.assertFalse(any(name == "submitsharepoolhashsnapshot" for name, _ in calls))
        head = self.gate.archive_head()
        again = self.gate.sync_native_receipts(cursor=result["deferred"][0]["retry_cursor"], limit=1)
        self.assertEqual(again["accepted"], [])
        self.assertEqual(again["deferred"][0]["retry_cursor"], self.cursor(2))
        self.assertEqual(self.gate.archive_head(), head)
        # After a canonical settlement frees this batch, retry that same proof.
        settled_block, settled = variable_fixture(ntime=1700000200,
            templates=(self.origin,), shares=proofs[:2])
        self.rpc.publish(settled_block, settled)
        retried = self.scan(2)
        self.assertEqual(retried["accepted"], [f"{proofs[2].proof_id:064x}"])
        self.assertEqual(retried["capacity_refused"], 0)
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 3)

    def test_existing_exact_receipts_advance_cursor_without_new_ack_under_pressure(self):
        proofs = self.setup_source(budget=1200)
        self.scan()
        head = self.gate.archive_head()
        result = self.scan()
        self.assertEqual(result["already_retained"], 2)
        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["deferred"][0]["retry_cursor"], self.cursor(2))
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_absent(proofs[2])

    def test_recent_lane_keeps_refused_snapshot_position(self):
        self.setup_source(budget=1200)
        result = self.gate.sync_native_receipts(cursor={
            "archive": {"after": None, "snapshot": None, "share": 0},
            "recent": {"after": 1, "epoch": "11" * 32, "snapshot": self.source.hash_hex,
                       "share": 0, "sequence": 2}, "next_lane": "recent"}, limit=1)
        self.assertEqual(result["limit_reason"], "admission-capacity")
        self.assertEqual((result["cursor"]["recent"]["snapshot"], result["cursor"]["recent"]["share"]),
                         (self.source.hash_hex, 2))
        self.assertEqual(result["cursor"]["recent"]["after"], 1)

    def test_native_missing_data_recovers_once_then_warm_imports_do_not_replay(self):
        proofs = self.setup_source(count=2)
        self.rpc.templates.pop(template_id(self.origin))
        before = len(self.rpc.calls)
        first = self.scan(max_receipts=1)
        self.assertEqual(first["accepted"], [f"{proofs[0].proof_id:064x}"])
        calls = self.rpc.calls[before:]
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in calls), 2)
        self.assertEqual(sum(name == "validatesharepoolhashtemplate" for name, _ in calls), 1)
        self.assertTrue(any(name == "submitsharepoolhashsnapshot" for name, _ in calls))
        before = len(self.rpc.calls)
        second = self.scan(1)
        self.assertEqual(second["accepted"], [f"{proofs[1].proof_id:064x}"])
        calls = self.rpc.calls[before:]
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in calls), 1)
        self.assertFalse(any(name == "submitsharepoolhashsnapshot" for name, _ in calls))

    def test_native_rejection_precedes_pressure_and_never_acknowledges(self):
        proofs = self.setup_source(count=1, budget=1024)
        self.rpc.share_error = "fresh native rejection"
        before = len(self.rpc.calls)
        head = self.gate.archive_head()
        result = self.scan()
        self.assertEqual(result["capacity_refused"], 0)
        self.assertEqual(result["deferred"][0]["reason"], "origin-or-proof-validation-unavailable")
        self.assertIn("fresh native rejection", result["deferred"][0]["detail"])
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_absent(proofs[0])
        self.assertFalse(any(name == "submitsharepoolhashsnapshot" for name, _ in self.rpc.calls[before:]))

    def test_deadline_margin_refuses_import_with_exact_retry_cursor(self):
        proofs = self.setup_source(count=1)
        parent = None
        for height in range(1, 4):
            block, parent = variable_fixture(height=height, native_parent=int(self.rpc.tip, 16),
                parent_snapshot=parent, ntime=1700000200 + height)
            self.rpc.publish(block, parent)
        head = self.gate.archive_head()
        result = self.scan()
        self.assertEqual(result["limit_reason"], "admission-capacity")
        self.assertIn("admission-deadline-margin", result["deferred"][0]["detail"])
        self.assertEqual(result["deferred"][0]["retry_cursor"], self.cursor())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_absent(proofs[0])

    def test_post_ack_metadata_failure_returns_success_and_preserves_receipt(self):
        proofs = self.setup_source(count=2)
        self.scan(max_receipts=1)
        accountant = self.gate._admission_state.accountant
        self.assertIsNotNone(accountant)
        with patch.object(accountant, "commit", side_effect=MemoryError("optional cache allocation")):
            result = self.scan(1)
        self.assertEqual(result["accepted"], [f"{proofs[1].proof_id:064x}"])
        self.assertEqual(result["deferred"], [])
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 2)
        self.assertIsNone(self.gate._admission_state)
        self.assertEqual(self.gate._read(PROOF, f"{proofs[1].proof_id:064x}"), proofs[1].serialize())


if __name__ == "__main__":
    unittest.main()
