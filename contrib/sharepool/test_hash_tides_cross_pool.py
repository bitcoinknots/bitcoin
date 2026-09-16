#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""V6 cross-pool gate policy with an RPC double; native tests are separate."""

from pathlib import Path
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import hash_gate_batch
from hash_mining_gate import HashMiningGate, PROOF
from hash_snapshot import solve_share
from native_mining_gate import JobOmission
from test_hash_gate_ledger import LedgerRPC
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT
from test_hash_tides import codec_fixture, TidesRPC


class TidesCrossPoolGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gate-cross-pool-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "gate.sqlite"
        self.rpc = TidesRPC()
        self.origin, self.opening = codec_fixture()
        self.foreign_origin, self.foreign_opening = codec_fixture(pool=4, secret=(2).to_bytes(32, "big"),
            payout_script=b"\x00\x14" + b"f" * 20)
        self.proof = solve_share(self.foreign_origin, self.foreign_opening)
        self.policy = dict(rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key,
                           payout_script=SCRIPT, profile_version=6)
        self.gate = HashMiningGate(self.path, **self.policy)
        self.rpc.gate = self.gate
        self.addCleanup(lambda: self.gate.close())

    def retain_foreign(self):
        self.gate.register_snapshot(self.foreign_opening.serialize())
        self.gate.register_template(self.foreign_origin.serialize())

    def test_cross_pool_receipt_keeps_original_destination_and_restart_evidence(self):
        self.retain_foreign()
        self.assertTrue(self.gate.receive(self.proof))
        head = self.gate.archive_head()
        self.assertEqual(self.gate.eligible_shares(), (self.proof,))
        self.assertEqual(self.gate._read(PROOF, f"{self.proof.proof_id:064x}"), self.proof.serialize())
        self.gate.close()
        self.gate = HashMiningGate(self.path, **self.policy)
        self.rpc.gate = self.gate
        self.assertEqual(self.gate.archive_head(), head)
        result = self.gate.revalidate_active()
        self.assertEqual(result["provisional_proofs"], (f"{self.proof.proof_id:064x}",))
        self.assertEqual(self.gate.eligible_shares()[0].envelope.pool, 4)
        self.assertEqual(self.gate.eligible_shares()[0].envelope.payout_script, self.foreign_opening.envelope.payout_script)

    def test_foreign_native_rejection_or_response_pool_rebinding_never_acknowledges(self):
        self.retain_foreign()
        head = self.gate.archive_head()
        self.rpc.share_error = "bad-sharepool-hash-proof"
        with self.assertRaisesRegex(ValueError, "bad-sharepool-hash-proof"):
            self.gate.receive(self.proof)
        self.assertEqual(self.gate.archive_head(), head)
        self.rpc.share_error = None

        def rebound(method, *args):
            result = self.rpc(method, *args)
            return dict(result, pool=f"{self.gate.pool:064x}") if method == "validatesharepoolhashshare" else result

        self.gate.rpc = rebound
        with self.assertRaisesRegex(ValueError, "response failed binding"):
            self.gate.receive(self.proof)
        self.assertEqual(self.gate.archive_head(), head)

    def test_foreign_origin_requires_full_native_validation(self):
        self.gate.register_snapshot(self.foreign_opening.serialize())
        head = self.gate.archive_head()
        self.rpc.template_error = "invalid foreign transaction"
        with self.assertRaisesRegex(ValueError, "invalid foreign transaction"):
            self.gate.register_template(self.foreign_origin.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        with self.assertRaisesRegex(ValueError, "durably validated full origin"):
            self.gate.receive(self.proof)

    def test_cross_pool_offer_is_admitted_atomically_with_own_job_policy(self):
        # Peer openings exist without a prior local receipt or template ACK.
        self.rpc.snapshots[self.foreign_opening.hash_hex] = self.foreign_opening.serialize().hex()
        block, snapshot = codec_fixture(ntime=1700000009, templates=(self.foreign_origin,), shares=(self.proof,))
        authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)
        self.assertEqual(self.gate.eligible_shares(), (self.proof,))
        with self.assertRaisesRegex(ValueError, "pool/key/payout policy"):
            self.gate.authorize(self.foreign_origin.serialize(), self.foreign_opening.serialize())

    def test_own_job_cannot_omit_durably_acknowledged_foreign_work(self):
        self.retain_foreign()
        self.gate.receive(self.proof)
        head = self.gate.archive_head()
        block, snapshot = codec_fixture(ntime=1700000009)
        with self.assertRaises(JobOmission) as failure:
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(failure.exception.proof_ids, (f"{self.proof.proof_id:064x}",))
        self.assertEqual(self.gate.archive_head(), head)

    def test_foreign_receipt_archive_restores_complete_bytes_and_revalidates(self):
        self.retain_foreign()
        self.gate.receive(self.proof)
        exported = Path(self.directory.name) / "gate.archive"
        head = self.gate.export_archive(exported)
        restored = HashMiningGate.restore_archive([exported], Path(self.directory.name) / "restored.sqlite",
                                                  trusted_head=head, **self.policy)
        try:
            self.assertEqual(restored.archive_head(), head)
            self.assertEqual(restored.eligible_shares(), (self.proof,))
            self.assertEqual(restored._read(PROOF, f"{self.proof.proof_id:064x}"), self.proof.serialize())
        finally:
            restored.close()

    def test_v4_v5_keep_pool_local_origin_and_receipt_policy(self):
        for version, rpc_class in ((4, FakeRPC), (5, LedgerRPC)):
            rpc = rpc_class()
            _, local = fixture(version=version)
            origin, foreign = fixture(version=version, pool=4)
            proof = solve_share(origin, foreign)
            gate = HashMiningGate(Path(self.directory.name) / f"legacy-{version}.sqlite", rpc=rpc, pool=3,
                public_key=local.envelope.public_key, payout_script=SCRIPT, profile_version=version)
            try:
                rpc.gate = gate
                gate.register_snapshot(foreign.serialize())
                head = gate.archive_head()
                with self.assertRaisesRegex(ValueError, "outside this pool"):
                    gate.register_template(origin.serialize())
                with self.assertRaisesRegex(ValueError, "outside this pool"):
                    gate.receive(proof)
                self.assertEqual(gate.archive_head(), head)
            finally:
                gate.close()

    def one_share_budget(self):
        original = hash_gate_batch.check_graph

        def check(snapshot, **kwargs):
            if len(snapshot.shares) > 1:
                raise hash_gate_batch.BatchLimit("test one-proof budget")
            return original(snapshot, **kwargs)

        return patch("hash_mining_gate.hash_gate_batch.check_graph", side_effect=check)

    def high_low(self):
        proofs = tuple(solve_share(self.foreign_origin, self.foreign_opening, start_nonce=number) for number in range(16))
        return max(proofs, key=lambda value: value.proof_id), min(proofs, key=lambda value: value.proof_id)

    def test_later_low_hash_cannot_overtake_same_origin_ack_even_after_restart(self):
        self.retain_foreign()
        high, low = self.high_low()
        self.gate.receive(high)
        self.gate.receive(low)
        with self.one_share_budget():
            selected = self.gate._batch(0, self.rpc.tip, None)
            self.assertEqual(selected["snapshot"].shares, (high,))
            self.assertEqual(selected["deferred_count"], 1)
        self.gate.close()
        self.gate = HashMiningGate(self.path, **self.policy)
        self.rpc.gate = self.gate
        with self.one_share_budget():
            self.assertEqual(self.gate._batch(0, self.rpc.tip, None)["snapshot"].shares, (high,))
            block, snapshot = codec_fixture(ntime=1700000009, templates=(self.foreign_origin,), shares=(low,))
            with self.assertRaises(JobOmission):
                self.gate.authorize(block.serialize(), snapshot.serialize())

    def test_unacknowledged_offer_cannot_overtake_same_origin_receipt(self):
        self.retain_foreign()
        high, low = self.high_low()
        self.gate.receive(high)
        with self.one_share_budget():
            selected = self.gate._batch(0, self.rpc.tip, None, offered=(low,),
                templates=(self.gate.active_templates()[0],))
        self.assertEqual(selected["snapshot"].shares, (high,))
        self.assertEqual(selected["deferred_count"], 1)

    def test_new_batch_policy_is_pinned_and_cannot_silently_reopen_old_journal(self):
        policy = json.loads(self.gate.config)
        self.assertEqual(policy["batch_policy"], "oldest-origin-receipt-v2")
        self.gate.close()
        policy["batch_policy"] = "oldest-origin-proof-v1"
        with sqlite3.connect(self.path) as database:
            database.execute("UPDATE config SET value=?", (json.dumps(policy, sort_keys=True, separators=(",", ":")).encode(),))
        with self.assertRaisesRegex(ValueError, "journal configuration|another profile"):
            HashMiningGate(self.path, **self.policy)

    def inventory_source(self, proofs=None):
        proofs = (self.proof,) if proofs is None else proofs
        _, source = codec_fixture(pool=9, ntime=1700000020, templates=(self.foreign_origin,), shares=proofs)
        self.rpc.snapshots[self.foreign_opening.hash_hex] = self.foreign_opening.serialize().hex()
        self.rpc.snapshots[source.hash_hex] = source.serialize().hex()

        def paged(method, *args):
            if method == "getsharepoolhashrecent":
                after, count = args
                entries = [{"sequence": number + 1, "hash": value} for number, value in enumerate(self.rpc.snapshots)]
                latest = len(entries)
                gap = after > latest
                if gap:
                    after = 0
                page = [entry for entry in entries if entry["sequence"] > after][:count]
                return {"entries": page, "next": page[-1]["sequence"] if page else after,
                    "latest": latest, "gap": gap, "epoch": getattr(self, "recent_epoch", "11" * 32)}
            result = self.rpc(method, *args)
            if method == "getsharepoolhashstatus":
                after, count = args if args else (None, 1024)
                ids = sorted(self.rpc.snapshots, key=lambda identity: bytes.fromhex(identity)[::-1])
                if after is not None:
                    ids = [value for value in ids if bytes.fromhex(value)[::-1] > bytes.fromhex(after)[::-1]]
                page = ids[:count]
                return dict(result, inventory=page, inventory_next=page[-1] if len(ids) > count else None,
                    inventory_complete=len(ids) <= count, inventory_revision=len(self.rpc.snapshots))
            return result

        self.gate.rpc = paged
        return source

    def pending_cursor(self, cursor):
        pending = [cursor[lane] for lane in ("archive", "recent") if cursor[lane]["snapshot"] is not None]
        self.assertTrue(pending)
        return pending[0]

    def test_paged_inventory_imports_foreign_proofs_and_resumes_inside_snapshot(self):
        second = solve_share(self.foreign_origin, self.foreign_opening, start_nonce=self.proof.header.nNonce + 1)
        source = self.inventory_source((self.proof, second))
        first = self.gate.sync_native_receipts(limit=8, max_receipts=1)
        self.assertEqual(len(first["accepted"]), 1)
        self.assertEqual(self.pending_cursor(first["cursor"])["snapshot"], source.hash_hex)
        self.assertEqual(self.pending_cursor(first["cursor"])["share"], 1)
        self.assertEqual(first["deferred"], [])
        last = self.gate.sync_native_receipts(cursor=first["cursor"], limit=8, max_receipts=8)
        self.assertEqual(len(last["accepted"]), 1)
        self.assertTrue(last["complete"])
        self.assertEqual({proof.proof_id for proof in self.gate.eligible_shares()}, {self.proof.proof_id, second.proof_id})
        repeated = self.gate.sync_native_receipts(cursor=last["cursor"], limit=8)
        self.assertEqual(repeated["accepted"], [])
        self.assertEqual(repeated["already_retained"], 2)
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 2)

    def test_inventory_missing_or_invalid_proof_has_explicit_retry_and_no_ack(self):
        source = self.inventory_source()
        before = self.gate.archive_head()
        self.rpc.share_error = "sharepool-hash-data-missing"
        failed = self.gate.sync_native_receipts(limit=8)
        self.assertEqual(failed["accepted"], [])
        self.assertEqual(failed["deferred"][0]["snapshot"], source.hash_hex)
        self.assertEqual(self.gate.archive_head(), before)
        self.rpc.share_error = None
        retried = self.gate.sync_native_receipts(cursor=failed["deferred"][0]["retry_cursor"], limit=8)
        self.assertEqual(retried["accepted"], [f"{self.proof.proof_id:064x}"])

    def test_inventory_byte_budget_preserves_unprocessed_cursor_and_no_ack(self):
        source = self.inventory_source()
        before = self.gate.archive_head()
        limited = self.gate.sync_native_receipts(limit=8, max_bytes=1024)
        self.assertEqual(limited["limit_reason"], "bytes")
        self.assertEqual(limited["accepted"], [])
        self.assertEqual(self.gate.archive_head(), before)
        completed = self.gate.sync_native_receipts(cursor=limited["cursor"], limit=8)
        self.assertEqual(completed["accepted"], [f"{self.proof.proof_id:064x}"])

    def test_inventory_dependency_bytes_are_metered_before_native_validation(self):
        source = self.inventory_source()
        before = self.gate.archive_head()
        # Read the source and expanded origin, then run out immediately before
        # reading the origin's opening. No native proof validation or ACK occurs.
        budget = (len(source.serialize()) + len(self.proof.serialize()) + len(self.foreign_origin.serialize()) +
                  len(self.foreign_opening.serialize()) - 1)
        cursor = {"after": None, "snapshot": source.hash_hex, "share": 0}
        limited = self.gate.sync_native_receipts(cursor=cursor, limit=8, max_bytes=budget)
        self.assertEqual(limited["limit_reason"], "bytes")
        self.assertEqual(limited["cursor"]["archive"], cursor)
        self.assertLessEqual(limited["bytes_charged"], budget)
        self.assertFalse(any(method == "validatesharepoolhashshare" for method, _ in self.rpc.calls))
        self.assertEqual(self.gate.archive_head(), before)
        self.assertIsNone(self.gate._snapshot_observer)

    def test_inventory_cycle_catches_insertions_below_old_hash_cursor(self):
        source = self.inventory_source()
        first = self.gate.sync_native_receipts(limit=8)
        self.assertTrue(first["complete"])
        second = solve_share(self.foreign_origin, self.foreign_opening, start_nonce=self.proof.header.nNonce + 1)
        for number in range(64):
            _, candidate = codec_fixture(pool=9, ntime=1700000040 + number,
                templates=(self.foreign_origin,), shares=(second,))
            if bytes.fromhex(candidate.hash_hex)[::-1] < bytes.fromhex(source.hash_hex)[::-1]:
                break
        else:
            self.fail("deterministic fixture did not produce a lower inventory key")
        self.rpc.snapshots[candidate.hash_hex] = candidate.serialize().hex()
        next_cycle = self.gate.sync_native_receipts(cursor=first["cursor"], limit=8)
        self.assertIn(f"{second.proof_id:064x}", next_cycle["accepted"])

    def test_inventory_invalid_bounds_and_pagination_response_fail_closed(self):
        for options in ({"limit": 0}, {"max_receipts": 257}, {"max_bytes": 0},
                        {"cursor": {"after": None, "snapshot": None, "share": 1}}):
            with self.assertRaises(ValueError):
                self.gate.sync_native_receipts(**options)
        # The older unpaged RPC double must never be mistaken for a complete
        # bounded scan, even when it happens to have a short inventory.
        self.gate.rpc = lambda method, *args: {} if method == "getsharepoolhashrecent" else self.rpc(method, *args)
        with self.assertRaisesRegex(ValueError, "pagination response failed"):
            self.gate.sync_native_receipts()

    def test_recent_lane_discovers_lower_hash_work_without_waiting_for_archive_cycle(self):
        source = self.inventory_source()
        completed = self.gate.sync_native_receipts(limit=16)
        self.assertTrue(completed["complete"])
        second = solve_share(self.foreign_origin, self.foreign_opening, start_nonce=self.proof.header.nNonce + 1)
        _, fresh = codec_fixture(pool=9, ntime=1700000050, templates=(self.foreign_origin,), shares=(second,))
        self.rpc.snapshots[fresh.hash_hex] = fresh.serialize().hex()
        cursor = completed["cursor"]
        cursor["archive"]["after"] = "ff" * 32
        cursor["next_lane"] = "recent"
        one = self.gate.sync_native_receipts(cursor=cursor, limit=1)
        self.assertEqual(one["accepted"], [f"{second.proof_id:064x}"])
        self.assertEqual(one["recent_pages"], 1)
        self.assertEqual(one["archive_pages"], 0)
        self.assertEqual(one["cursor"]["archive"]["after"], "ff" * 32)
        # Even another new live event cannot take the next archive turn.
        third = solve_share(self.foreign_origin, self.foreign_opening, start_nonce=second.header.nNonce + 1)
        _, later = codec_fixture(pool=9, ntime=1700000052, templates=(self.foreign_origin,), shares=(third,))
        self.rpc.snapshots[later.hash_hex] = later.serialize().hex()
        following = self.gate.sync_native_receipts(cursor=one["cursor"], limit=1)
        self.assertEqual(following["archive_pages"], 1)

    def test_recent_epoch_change_restarts_even_when_new_counter_exceeds_old_cursor(self):
        source = self.inventory_source()
        before = self.gate.sync_native_receipts(limit=16)
        self.assertTrue(before["complete"])
        old_after = before["cursor"]["recent"]["after"]
        second = solve_share(self.foreign_origin, self.foreign_opening, start_nonce=self.proof.header.nNonce + 1)
        _, fresh = codec_fixture(pool=9, ntime=1700000051, templates=(self.foreign_origin,), shares=(second,))
        self.rpc.snapshots = {fresh.hash_hex: fresh.serialize().hex(),
            self.foreign_opening.hash_hex: self.foreign_opening.serialize().hex(), source.hash_hex: source.serialize().hex()}
        self.assertGreater(len(self.rpc.snapshots), old_after)
        self.recent_epoch = "22" * 32
        before["cursor"]["next_lane"] = "recent"
        reset = self.gate.sync_native_receipts(cursor=before["cursor"], limit=1)
        self.assertTrue(reset["recent_epoch_changed"])
        self.assertEqual(reset["cursor"]["recent"]["after"], 0)
        after = self.gate.sync_native_receipts(cursor=reset["cursor"], limit=8)
        self.assertIn(f"{second.proof_id:064x}", after["accepted"])

    def test_recent_gap_is_visible_and_archive_lane_still_runs(self):
        self.inventory_source()
        cursor = {"archive": {"after": None, "snapshot": None, "share": 0},
            "recent": {"after": 99, "epoch": "11" * 32, "snapshot": None, "share": 0, "sequence": 0},
            "next_lane": "recent"}
        result = self.gate.sync_native_receipts(cursor=cursor, limit=8)
        self.assertTrue(result["recent_gap"])
        self.assertGreater(result["archive_pages"], 0)

    def test_context_requests_only_one_inventory_record(self):
        self.gate._context()
        requests = [args for method, args in self.rpc.calls if method == "getsharepoolhashstatus"]
        self.assertTrue(requests)
        self.assertTrue(all(args == (None, 1) for args in requests))


if __name__ == "__main__":
    unittest.main()
