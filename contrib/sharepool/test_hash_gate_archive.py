#!/usr/bin/env python3
"""Bounded backup/restore and branch reconciliation of acknowledged gate work."""
from pathlib import Path
import struct
import tempfile
import unittest

from hash_mining_gate import HashMiningGate
import hash_gate_archive
import native_archive
from hash_snapshot import solve_share
from native_mining_gate import REGTEST_GENESIS
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


class HashGateArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hash-gate-archive-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rpc = FakeRPC()
        self.origin, self.opening = fixture()
        self.options = dict(rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key, payout_script=SCRIPT)
        self.gate = HashMiningGate(self.directory / "source.sqlite", **self.options)
        self.addCleanup(self.gate.close)
        self.rpc.gate = self.gate
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())

    def proof(self, nonce=0):
        return solve_share(self.origin, self.opening, start_nonce=nonce)

    def restore(self, exports, head, *, name="restored.sqlite", **extra):
        gate = HashMiningGate.restore_archive(exports, self.directory / name, trusted_head=head,
                                             **dict(self.options, **extra))
        self.addCleanup(gate.close)
        return gate

    def assert_destination_absent(self, name="restored.sqlite"):
        self.assertFalse((self.directory / name).exists())
        self.assertFalse((self.directory / (name + ".archive-head.json")).exists())
        self.assertFalse(list(self.directory.glob(".hash-gate-restore-*")))

    def test_full_archive_restores_exact_receipts_and_complete_origins(self):
        proofs, nonce = [], 0
        for unused in range(100):
            proof = self.proof(nonce)
            nonce = proof.header.nNonce + 1
            self.gate.receive(proof)
            proofs.append(proof)
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        self.assertEqual(head, self.gate.archive_head())
        restored = self.restore(target, head)
        self.assertEqual(restored.archive_head(), head)
        self.assertEqual([share.proof_id for share in restored.eligible_shares()], sorted(share.proof_id for share in proofs))
        self.assertEqual(restored.snapshot_bytes(self.opening.hash_hex), self.opening.serialize())
        for proof in proofs:
            self.assertFalse(restored.receive(proof))
        self.assertEqual(restored.archive_head(), head)
        newer = self.proof(nonce)
        self.assertTrue(restored.receive(newer))
        self.assertEqual(restored.archive_head()["receipt_revision"], 101)

    def test_incremental_segments_rotate_without_removing_acknowledgments(self):
        first = self.directory / "segment-001.spharc"
        prefix = self.gate.export_archive(first)
        proof = self.proof()
        self.gate.receive(proof)
        second = self.directory / "segment-002.spharc"
        head = self.gate.export_archive(second, since=prefix)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertLess(second.stat().st_size, first.stat().st_size + len(proof.serialize()))
        restored = self.restore([first, second], head)
        self.assertEqual(restored.archive_head(), head)
        self.assertFalse(restored.receive(proof))
        for paths in ([second], [second, first], [first], [first, first, second]):
            with self.subTest(paths=[path.name for path in paths]), self.assertRaises(ValueError):
                self.restore(paths, head, name="refused.sqlite")
            self.assert_destination_absent("refused.sqlite")

    def test_paid_and_orphaned_work_is_retained_for_native_branch_reconciliation(self):
        proof = self.proof()
        self.gate.receive(proof)
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        block, snapshot = fixture(ntime=1700000002, templates=[self.origin], shares=[proof])
        self.rpc.publish(block, snapshot)
        restored = self.restore(target, head)
        self.assertEqual(restored.archive_head(), head)
        self.assertEqual(restored.revalidate_active()["unsettled_proofs"], ())
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        reconciled = restored.revalidate_active()
        self.assertEqual(reconciled["retained_receipts"], 1)
        self.assertEqual(reconciled["unsettled_proofs"], (f"{proof.proof_id:064x}",))
        self.assertEqual(restored.archive_head(), head)
        self.assertEqual([share.proof_id for share in restored.eligible_shares()], [proof.proof_id])

    def test_incomplete_or_changed_export_never_publishes_partial_restore(self):
        self.gate.receive(self.proof())
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        raw = target.read_bytes()
        for suffix, changed in (("truncated", raw[:-1]), ("changed", raw[:-1] + bytes([raw[-1] ^ 1])),
                                ("trailing", raw + b"\0")):
            bad = self.directory / (suffix + ".spharc")
            bad.write_bytes(changed)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.restore(bad, head)
            self.assert_destination_absent()

    def test_archive_header_bounds_and_untrusted_checkpoint_are_refused(self):
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        raw = target.read_bytes()
        bad = self.directory / "oversized-header.spharc"
        bad.write_bytes(raw[:8] + struct.pack("<I", 100_000) + raw[12:])
        with self.assertRaisesRegex(ValueError, "header exceeds"):
            self.restore(bad, head)
        self.assert_destination_absent()
        wrong = dict(head, root="01" * 32)
        with self.assertRaises(ValueError):
            self.restore(target, wrong)
        self.assert_destination_absent()
        with self.assertRaises(ValueError):
            self.gate.export_archive(self.directory / "wrong-prefix.spharc", since=wrong)
        self.assertFalse((self.directory / "wrong-prefix.spharc").exists())

    def test_native_revalidation_failure_keeps_restore_unpublished(self):
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        self.rpc.template_error = "native chain validation refused"
        with self.assertRaisesRegex(ValueError, "native chain validation refused"):
            self.restore(target, head)
        self.assert_destination_absent()
        self.rpc.template_error = None
        self.assertEqual(self.restore(target, head).archive_head(), head)

    def test_export_and_restore_never_overwrite_existing_destinations(self):
        target = self.directory / "complete.spharc"
        head = self.gate.export_archive(target)
        original = target.read_bytes()
        with self.assertRaises(FileExistsError):
            self.gate.export_archive(target)
        self.assertEqual(target.read_bytes(), original)
        restored = self.restore(target, head)
        with self.assertRaises(ValueError):
            self.restore(target, head)
        self.assertEqual(restored.archive_head(), head)

    def reopen_source(self, **extra):
        path = self.gate.path
        self.gate.close()
        self.gate = HashMiningGate(path, **dict(self.options, **extra))
        self.rpc.gate = self.gate
        self.addCleanup(self.gate.close)

    def test_cold_rotation_preserves_frozen_job_receipts_and_restart(self):
        proof = self.proof()
        self.gate.receive(proof)
        block, snapshot = fixture(ntime=1700000002, templates=[self.origin], shares=[proof])
        authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
        head = self.gate.archive_head()
        cold = self.directory / "cold-001.spharc"
        self.assertEqual(self.gate.rotate_archive(cold), head)
        self.assertEqual(self.gate.resident_bytes(), 0)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        self.assertEqual(self.gate.snapshot_bytes(self.opening.hash_hex), self.opening.serialize())
        self.reopen_source()
        self.assertFalse(self.gate.receive(proof))
        self.assertFalse(self.gate.ready_for_dispatch(authorization))
        renewed = self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(self.gate.ready_for_dispatch(renewed))
        self.assertEqual(self.gate.archive_head(), head)

    def test_automatic_rollover_applies_quota_only_to_resident_evidence(self):
        cold_directory = self.directory / "cold"
        self.reopen_source(quota=4096, archive_directory=cold_directory)
        proofs, nonce = [], 0
        for unused in range(100):
            proof = self.proof(nonce)
            nonce = proof.header.nNonce + 1
            self.assertTrue(self.gate.receive(proof))
            self.assertLessEqual(self.gate.resident_bytes(), 4096)
            proofs.append(proof)
        head = self.gate.archive_head()
        self.assertGreater(head["bytes"], 4096)
        self.assertEqual(head["receipt_revision"], 100)
        self.assertGreater(len(list(cold_directory.glob("*.spharc"))), 1)
        self.reopen_source(quota=4096, archive_directory=cold_directory)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertFalse(self.gate.receive(proofs[0]))
        self.assertEqual(len(self.gate.eligible_shares()), 100)
        # Full export reads older bodies from cold storage one record at a time.
        complete = self.directory / "complete-cold.spharc"
        self.gate.export_archive(complete)
        restored = self.restore(complete, head, quota=4096, archive_directory=self.directory / "restored-cold")
        self.assertEqual(restored.archive_head(), head)
        self.assertLessEqual(restored.resident_bytes(), 4096)
        self.assertEqual(len(restored.eligible_shares()), 100)

    def test_failed_cold_segment_verification_preserves_resident_copy(self):
        self.gate.receive(self.proof())
        head = self.gate.archive_head()
        resident = self.gate.resident_bytes()
        cold = self.directory / "incomplete-cold.spharc"
        self.gate.export_archive(cold)
        raw = cold.read_bytes()
        cold.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(ValueError):
            self.gate.rotate_archive(cold)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.gate.resident_bytes(), resident)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM segments").fetchone()[0], 0)
        self.assertEqual(len(self.gate.eligible_shares()), 1)

    def test_missing_or_changed_cold_body_fails_closed(self):
        proof = self.proof()
        self.gate.receive(proof)
        cold = self.directory / "cold-001.spharc"
        head = self.gate.rotate_archive(cold)
        raw = cold.read_bytes()
        cold.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(ValueError):
            self.gate.receive(proof)
        self.assertEqual(self.gate.archive_head(), head)
        cold.write_bytes(raw)
        self.assertFalse(self.gate.receive(proof))
        cold.unlink()
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "cold archive data is unavailable"):
            HashMiningGate(self.directory / "source.sqlite", **self.options)
        self.assertEqual(hash_gate_archive.read_head(self.gate.head_path), head)

    def test_cold_receipt_becomes_unpaid_again_after_native_reorganization(self):
        proof = self.proof()
        self.gate.receive(proof)
        head = self.gate.rotate_archive(self.directory / "cold-001.spharc")
        block, snapshot = fixture(ntime=1700000002, templates=[self.origin], shares=[proof])
        self.rpc.publish(block, snapshot)
        self.assertEqual(self.gate.revalidate_active()["unsettled_proofs"], ())
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.assertEqual(self.gate.revalidate_active()["unsettled_proofs"], (f"{proof.proof_id:064x}",))
        self.assertEqual(self.gate.archive_head(), head)

    def test_lifetime_counters_are_not_the_resident_quota(self):
        proof = self.proof()
        head = dict(native_archive.initial_head(self.gate.binding), events=1_000_001,
                    receipt_revision=1_000_000, bytes=4 * 1024 * 1024 * 1024 + 1)
        hash_gate_archive.check_head(head)
        next_head, unused = self.gate._next(head, 2, f"{proof.proof_id:064x}", proof.serialize())
        self.assertEqual(next_head["receipt_revision"], 1_000_001)
        self.assertGreater(next_head["bytes"], head["bytes"])
        with self.assertRaisesRegex(ValueError, "counter exhausted"):
            self.gate._next(dict(head, events=hash_gate_archive.MAX_COUNTER), 2,
                            f"{proof.proof_id:064x}", proof.serialize())


if __name__ == "__main__":
    unittest.main()
