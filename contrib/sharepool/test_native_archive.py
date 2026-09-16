#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable archive/recovery failures; native consensus has functional coverage."""
from copy import deepcopy
from pathlib import Path
import sqlite3
import os
import tempfile
import unittest
from unittest.mock import patch

import native_archive as archive
from native_enforcement import candidate, solve_share
from native_mining_gate import NativeMiningGate, RecoveryRequired, JobOmission, parse_block
from test_native_mining_gate import FakeRPC, fixture, SECRET, SCRIPT, GENESIS


class NativeArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "gate.sqlite"
        self.rpc = FakeRPC()
        self.block, self.manifest = fixture()
        self.options = dict(rpc=self.rpc, pool=3, public_key=self.manifest.envelope.public_key,
                            payout_script=SCRIPT)
        self.gate = NativeMiningGate(self.path, **self.options)
        self.addCleanup(lambda: self.gate.close() if self.gate else None)
        self.gate.register_template(self.block.serialize())
        self.share = solve_share(self.block, self.manifest)

    def acknowledge(self):
        self.assertTrue(self.gate.receive(self.share.serialize()))

    def deep_rollback(self):
        self.rpc.advance(162)
        self.gate.maintenance()
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
        self.gate.close()
        self.gate = None
        self.rpc.advance(0)
        with self.assertRaises(RecoveryRequired):
            NativeMiningGate(self.path, **self.options)

    def test_complete_export_is_contiguous_and_matches_protected_checkpoint(self):
        self.acknowledge()
        exported = self.root / "full.spna"
        head = self.gate.export_archive(exported)
        self.assertEqual(head, self.gate.archive_head())
        self.assertEqual(head["receipt_revision"], 1)
        self.assertEqual(head["events"], 2)
        records = list(archive.export_records(exported, trusted_head=head,
                       binding=head["binding"], quota=archive.DEFAULT_QUOTA))
        self.assertEqual([row[0] for row in records], [1, 2])
        self.assertEqual([row[1] for row in records], [0, 1])
        self.assertEqual(records[0][5], self.block.serialize())
        self.assertEqual(records[1][5], self.share.serialize())
        self.assertEqual(records[-1][7], head["root"])
        with self.assertRaises(FileExistsError):
            self.gate.export_archive(exported)

    def test_pruning_preserves_full_archive_and_deep_recovery_restores_known_work(self):
        self.acknowledge()
        head = self.gate.archive_head()
        self.deep_rollback()
        self.gate = NativeMiningGate.recover_archive(self.path, **self.options)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.gate.receipt_bytes(f"{self.share.proof_id:064x}"), self.share.serialize())
        with self.assertRaises(JobOmission):
            self.gate.authorize(self.block.serialize())
        full, unused = fixture((self.share,))
        authorization = self.gate.authorize(full.serialize())
        self.assertEqual(authorization.receipt_sequence, 1)
        self.gate.close()
        self.gate = NativeMiningGate(self.path, **self.options)
        self.assertFalse(self.gate.receive(self.share.serialize()))

    def test_future_height_acknowledged_work_rehydrates_as_chain_advances(self):
        self.acknowledge()
        self.rpc.advance(5)
        later, manifest = candidate(genesis=GENESIS, native_parent=int(self.rpc.tip, 16), height=6,
                                    ntime=1700000006, pool=3, secret=SECRET, payout_script=SCRIPT)
        later_share = solve_share(later, manifest)
        self.gate.register_template(later.serialize())
        self.gate.receive(later_share.serialize())
        self.deep_rollback()
        self.gate = NativeMiningGate.recover_archive(self.path, **self.options)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.rpc.advance(5)
        self.gate.maintenance()
        self.assertEqual(self.gate.receipt_bytes(f"{later_share.proof_id:064x}"), later_share.serialize())
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 2)
        with self.assertRaises(JobOmission):
            self.gate.authorize(later.serialize())

    def test_restore_requires_final_trusted_head_and_publishes_only_complete_store(self):
        stale = self.root / "stale.spna"
        self.gate.export_archive(stale)
        self.acknowledge()
        exported, head = self.root / "full.spna", self.gate.archive_head()
        self.gate.export_archive(exported)
        destination = self.root / "restored.sqlite"
        with self.assertRaises(archive.ArchiveError):
            NativeMiningGate.restore_archive(stale, destination, trusted_head=head, **self.options)
        self.assertFalse(destination.exists())
        for bad in (self.root / "missing.spna", self.root / "truncated.spna"):
            if bad.name == "truncated.spna":
                bad.write_bytes(exported.read_bytes()[:-1])
            with self.assertRaises(archive.ArchiveError):
                NativeMiningGate.restore_archive(bad, destination, trusted_head=head, **self.options)
            self.assertFalse(destination.exists())
        wrong = deepcopy(head)
        wrong["root"] = "ff" * 32
        with self.assertRaises(archive.ArchiveError):
            NativeMiningGate.restore_archive(exported, destination, trusted_head=wrong, **self.options)
        self.assertFalse(destination.exists())
        with NativeMiningGate.restore_archive(exported, destination, trusted_head=head, **self.options) as restored:
            self.assertEqual(restored.archive_head(), head)
            with self.assertRaises(JobOmission):
                restored.authorize(self.block.serialize())
        with NativeMiningGate(destination, **self.options) as reopened:
            self.assertEqual(reopened.archive_head(), head)

    def test_native_revalidation_failure_never_publishes_fresh_destination(self):
        self.acknowledge()
        exported = self.root / "full.spna"
        head = self.gate.export_archive(exported)
        self.rpc.proposal_error = "injected native rejection"
        destination = self.root / "restored.sqlite"
        with self.assertRaisesRegex(ValueError, "injected native"):
            NativeMiningGate.restore_archive(exported, destination, trusted_head=head, **self.options)
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_name(destination.name + ".archive-head.json").exists())
        self.assertEqual(list(self.root.glob(".sharepool-restore-*")), [])

    def test_inplace_partial_validation_failure_preserves_hot_state_and_latch(self):
        self.acknowledge()
        other, manifest = candidate(genesis=GENESIS, native_parent=GENESIS, height=1,
            ntime=1700000001, pool=3, secret=(2).to_bytes(32, "big"), payout_script=SCRIPT)
        self.gate.register_template(other.serialize())
        self.gate.receive(solve_share(other, manifest).serialize())
        self.deep_rollback()
        def logical():
            with sqlite3.connect(self.path) as db:
                return tuple(tuple(db.execute("SELECT * FROM " + table).fetchall()) for table in ("receipts", "templates", "state"))
        before = logical()
        calls = []
        original = self.rpc
        def rejecting(method, *args):
            if method == "validatesharepooltemplate":
                calls.append(args[0])
                if len(calls) == 2:
                    raise ValueError("second origin unavailable")
            return original(method, *args)
        with self.assertRaisesRegex(ValueError, "second origin"):
            NativeMiningGate.recover_archive(self.path, **dict(self.options, rpc=rejecting))
        self.assertEqual(len(calls), 2)
        self.assertEqual(logical(), before)
        with self.assertRaises(RecoveryRequired):
            NativeMiningGate(self.path, **self.options)

    def test_archive_gap_and_payload_corruption_fail_before_export_or_recovery(self):
        self.acknowledge()
        with self.gate.db:
            self.gate.db.execute("DELETE FROM archive_events WHERE sequence=1")
        with self.assertRaises(archive.ArchiveError):
            self.gate.export_archive(self.root / "corrupt.spna")
        self.assertFalse((self.root / "corrupt.spna").exists())
        self.gate.close()
        self.gate = None
        with self.assertRaises(archive.ArchiveError):
            NativeMiningGate.recover_archive(self.path, **self.options)

    def test_payload_bitflip_invalidates_archive_chain(self):
        self.acknowledge()
        raw = bytearray(self.share.serialize())
        raw[-1] ^= 1
        with self.gate.db:
            self.gate.db.execute("UPDATE archive_events SET data=? WHERE kind=1", (bytes(raw),))
        with self.assertRaises(archive.ArchiveError):
            self.gate.export_archive(self.root / "corrupt.spna")

    def test_pruning_does_not_discard_last_intact_copy_when_archive_is_corrupt(self):
        self.acknowledge()
        corrupted = bytearray(self.share.serialize())
        corrupted[-1] ^= 1
        with self.gate.db:
            self.gate.db.execute("UPDATE archive_events SET data=? WHERE kind=1", (bytes(corrupted),))
        self.rpc.advance(162)
        with self.assertRaisesRegex(archive.ArchiveError, "corrupt archived copy"):
            self.gate.maintenance()
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM templates").fetchone()[0], 1)
        self.assertEqual(self.gate.db.execute("SELECT anchor_height FROM state").fetchone()[0], 0)

    def test_pruning_does_not_delete_acknowledged_work_missing_from_archive(self):
        self.acknowledge()
        with self.gate.db:
            self.gate.db.execute("DELETE FROM archive_events WHERE kind=1")
        self.rpc.advance(162)
        with self.assertRaisesRegex(archive.ArchiveError, "complete archived copy"):
            self.gate.maintenance()
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)

    def test_postcommit_seal_failure_never_acknowledges_and_restart_preserves_work(self):
        old = archive.read_head(self.gate.head_path)
        with patch("native_archive.write_head", side_effect=OSError("seal fsync failed")):
            with self.assertRaisesRegex(OSError, "seal fsync"):
                self.gate.receive(self.share.serialize())
        self.assertEqual(archive.read_head(self.gate.head_path), old)
        self.gate.close()
        self.gate = NativeMiningGate(self.path, **self.options)
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)
        self.assertFalse(self.gate.receive(self.share.serialize()))
        with self.assertRaises(JobOmission):
            self.gate.authorize(self.block.serialize())

    def test_database_rollback_below_protected_high_water_is_detected(self):
        backup = self.root / "old.sqlite"
        with sqlite3.connect(backup) as db:
            self.gate.db.backup(db)
        self.acknowledge()
        head_path = self.gate.head_path
        expected = archive.read_head(head_path)
        self.gate.close()
        self.gate = None
        with self.assertRaises(archive.ArchiveError):
            NativeMiningGate(backup, trusted_head_path=head_path, **self.options)
        self.assertEqual(archive.read_head(head_path), expected)

    def test_two_stores_cannot_overwrite_the_same_protected_checkpoint(self):
        other = self.root / "other.sqlite"
        with self.assertRaisesRegex(ValueError, "owning process"):
            NativeMiningGate(other, trusted_head_path=self.gate.head_path, **self.options)
        self.assertEqual(self.gate.archive_head()["events"], 1)

    def test_missing_initialized_seal_cannot_be_recreated_implicitly(self):
        self.acknowledge()
        self.gate.head_path.unlink()
        self.gate.close()
        self.gate = None
        with self.assertRaisesRegex(archive.ArchiveError, "high-water is missing"):
            NativeMiningGate.recover_archive(self.path, **self.options)

    def test_quota_exhaustion_rolls_back_receipt_and_archive_before_ack(self):
        self.gate.close()
        self.gate = NativeMiningGate(self.path, archive_quota=4096, **self.options)
        nonce = 0
        for unused in range(20):
            share = solve_share(self.block, self.manifest, start_nonce=nonce)
            nonce = share.header.nNonce + 1
            before = self.gate.archive_head()
            try:
                self.gate.receive(share.serialize())
            except archive.ArchiveError as error:
                self.assertIn("quota exhausted", str(error))
                self.assertEqual(self.gate.archive_head(), before)
                self.assertIsNone(self.gate.db.execute("SELECT 1 FROM receipts WHERE proof_id=?", (f"{share.proof_id:064x}",)).fetchone())
                break
        else:
            self.fail("bounded archive never rejected admission")

    def test_protected_head_refuses_writable_other_owner_symlink_and_hardlink(self):
        path = self.gate.head_path
        original = path.read_bytes()
        path.chmod(0o622)
        with self.assertRaises(archive.ArchiveError):
            archive.read_head(path)
        with self.assertRaises(archive.ArchiveError):
            archive.write_head(path, self.gate._sealed_head)
        self.assertEqual(path.read_bytes(), original)
        path.chmod(0o600)
        uid = os.geteuid()
        with patch("native_archive.os.geteuid", return_value=uid + 1):
            with self.assertRaises(archive.ArchiveError):
                archive.read_head(path)
        symbolic = self.root / "head-symlink"
        symbolic.symlink_to(path)
        with self.assertRaises(archive.ArchiveError):
            archive.read_head(symbolic)
        linked = self.root / "head-hardlink"
        os.link(path, linked)
        with self.assertRaises(archive.ArchiveError):
            archive.read_head(path)
        linked.unlink()
        self.assertEqual(archive.read_head(path), self.gate._sealed_head)

    def test_changed_or_missing_live_checkpoint_prevents_new_acknowledgment(self):
        path = self.gate.head_path
        original = self.gate.archive_head()
        wrong = deepcopy(original)
        wrong["root"] = "ff" * 32
        archive.write_head(path, wrong)
        with self.assertRaisesRegex(archive.ArchiveError, "changed outside"):
            self.gate.receive(self.share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
        archive.write_head(path, original)
        path.unlink()
        with self.assertRaisesRegex(archive.ArchiveError, "high-water is missing"):
            self.gate.receive(self.share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)

    def test_prepruned_v2_cannot_claim_complete_archive_migration(self):
        self.acknowledge()
        self.rpc.advance(162)
        self.gate.maintenance()
        config = self.gate._config(2)
        seal = self.gate.head_path
        self.gate.close()
        self.gate = None
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE archive_events")
            db.execute("DROP TABLE archive_state")
            db.execute("UPDATE config SET value=?", (config,))
            db.execute("PRAGMA user_version=2")
        seal.unlink()
        with self.assertRaisesRegex(RecoveryRequired, "pre-pruned v2"):
            NativeMiningGate.recover_archive(self.path, **self.options)
        with sqlite3.connect(self.path) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='archive_events'").fetchone())

    def test_recovery_only_opening_cannot_admit_without_verified_rebuild(self):
        self.gate.close()
        self.gate = NativeMiningGate(self.path, _recovery_only=True, **self.options)
        for action in (lambda: self.gate.receive(self.share.serialize()),
                       lambda: self.gate.register_template(self.block.serialize()),
                       lambda: self.gate.authorize(self.block.serialize())):
            with self.assertRaises(RecoveryRequired):
                action()
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 0)


if __name__ == "__main__":
    unittest.main()
