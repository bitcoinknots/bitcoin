#!/usr/bin/env python3
"""v5 local ACK/ledger semantics with a strict RPC adapter double.

Native UTXO/script and confirmed-ledger validity are covered separately by the
native ledger and gate-ledger functional tests; this file checks local policy,
canonical history interpretation, recovery, and certificate graph collection.
"""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_gate_batch import check_graph
from hash_mining_gate import HashMiningGate
from hash_snapshot import (Snapshot, LEDGER_VERSION, LEDGER_RULES_HASH, TemplateRecord,
                           origin_certificate, solve_share)
from native_mining_gate import REGTEST_GENESIS
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


class LedgerRPC(FakeRPC):
    def __call__(self, method, *args):
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            result.update(mode="hash-only-v5-confirmed-ledger", rules=f"{LEDGER_RULES_HASH:064x}",
                          activation_height=getattr(self, "activation_height", 1))
        return result


class HashGateLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gate-ledger-")
        self.addCleanup(self.directory.cleanup)
        self.rpc = LedgerRPC()
        self.origin, self.opening = fixture(version=LEDGER_VERSION)
        self.options = dict(rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key,
                            payout_script=SCRIPT, profile_version=LEDGER_VERSION)
        self.gate = HashMiningGate(Path(self.directory.name) / "gate.sqlite", **self.options)
        self.addCleanup(lambda: self.gate.close())
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        self.proof = solve_share(self.origin, self.opening)
        self.assertTrue(self.gate.receive(self.proof))

    def status(self):
        return self.gate.receipt_status()["receipts"][0]

    def mine(self, *, pool=9, shares=(), templates=()):
        parent = self.gate._parent_snapshot(self.rpc.height, self.rpc.tip, {})
        block, opening = fixture(version=5, native_parent=int(self.rpc.tip, 16), height=self.rpc.height + 1,
                                 pool=pool, parent_snapshot=parent, shares=shares, templates=templates,
                                 ntime=1700000010 + self.rpc.height)
        self.rpc.publish(block, opening)
        return block, opening

    def test_provisional_anchor_cutoff_late_settlement_and_reorg(self):
        self.assertEqual(self.status()["status"], "provisional")
        self.assertTrue(self.status()["selected_for_admission"])
        anchor, snapshot = self.mine(shares=[self.proof], templates=[self.origin])
        self.assertEqual(snapshot.settled, ())
        self.assertEqual(self.status()["status"], "confirmed_pending")
        self.assertIsNone(self.status()["settled_in"])
        self.assertEqual(self.gate.batch_status()["selected_proofs"], ())
        for _ in range(5):
            self.mine()
        self.assertEqual(self.status()["status"], "confirmed_pending")
        before_payment = self.rpc.tip
        paid, _ = self.mine(pool=3)
        self.assertEqual(self.status()["status"], "settled")
        self.assertEqual(self.status()["settled_in"], paid.hash)
        for _ in range(3):
            self.mine()
        self.assertEqual(self.status()["settled_in"], paid.hash)
        # The canonical branch loses the payment but retains the earlier anchor.
        self.rpc.height, self.rpc.tip = 6, before_payment
        self.assertEqual(self.status()["status"], "confirmed_pending")
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.assertEqual(self.status()["status"], "provisional")

    def test_unknown_history_is_never_reported_as_payment(self):
        anchor, admitted = self.mine(shares=[self.proof], templates=[self.origin])
        self.mine(pool=3)
        self.mine()
        del self.rpc.snapshots[admitted.hash_hex]
        result = self.status()
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["settled_in"])

    def test_ledger_capacity_defers_provisional_ack_without_losing_it(self):
        second = solve_share(self.origin, self.opening, start_nonce=self.proof.header.nNonce + 1)
        self.assertTrue(self.gate.receive(second))
        head = self.gate.archive_head()
        unused, full = fixture(version=5, templates=[self.origin], shares=[self.proof, second])
        one_credit = 1 + len(full.pending[0].serialize())
        with patch("hash_snapshot.MAX_LEDGER_BYTES", one_credit):
            result = self.gate.batch_status()
            self.assertEqual(len(result["selected_proofs"]), 1)
            self.assertEqual(result["deferred_count"], 1)
        with patch("hash_snapshot.MAX_LEDGER_BYTES", 1):
            self.assertEqual(self.gate.batch_status()["selected_proofs"], ())
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(len(self.gate.eligible_shares()), 2)

    def test_status_history_is_bounded_and_pending_credit_needs_no_proof_rewalk(self):
        anchor, admitted = self.mine(shares=[self.proof], templates=[self.origin])
        # The chain's confirmed pending credit is sufficient for status. Losing
        # unrelated historical origin data cannot turn it into a provisional ACK.
        saved = self.rpc.snapshots.pop(self.opening.hash_hex)
        self.assertEqual(self.status()["status"], "confirmed_pending")
        self.rpc.snapshots[self.opening.hash_hex] = saved
        for _ in range(5):
            self.mine()
        reconciled = self.gate.revalidate_active()
        self.assertEqual(reconciled["active_receipts"], 0)
        self.assertEqual(reconciled["confirmed_pending_proofs"], (f"{self.proof.proof_id:064x}",))
        self.assertEqual(reconciled["provisional_proofs"], ())
        self.mine(pool=3)
        unused, tip = self.mine()
        with patch("hash_mining_gate.RECEIPT_HISTORY_SNAPSHOTS", 1):
            result = self.gate.receipt_status()
            self.assertEqual(result["receipts"][0]["status"], "unknown")
            self.assertTrue(result["history_limited"])
        # The current parent is part of the byte budget, even though already
        # loaded for its ledger. This permits each next opening alone, not both.
        budget = max(len(tip.serialize()), len(admitted.serialize()))
        with patch("hash_mining_gate.RECEIPT_HISTORY_BYTES", budget):
            result = self.gate.receipt_status()
            self.assertEqual(result["receipts"][0]["status"], "unknown")
            self.assertTrue(result["history_limited"])

    def test_archive_preserves_profile_and_provisional_ack(self):
        path = Path(self.directory.name)
        archive, restored = path / "export.bin", path / "restored.sqlite"
        self.gate.export_archive(archive)
        head = self.gate.archive_head()
        with HashMiningGate.restore_archive([archive], restored, trusted_head=head, **self.options) as recovered:
            self.assertEqual(recovered.receipt_status()["receipts"][0]["status"], "provisional")
            self.assertFalse(recovered.receive(self.proof))
        with self.assertRaisesRegex(ValueError, "v4 profile"):
            HashMiningGate(path / "wrong.sqlite", **dict(self.options, profile_version=4))

    def test_delayed_activation_has_no_preactivation_snapshot_dependency(self):
        rpc = LedgerRPC()
        rpc.activation_height = 102
        rpc.height, rpc.tip = 101, "12" * 32
        rpc.hashes[101] = rpc.tip
        origin, opening = fixture(version=5, height=102, native_parent=int(rpc.tip, 16))
        options = dict(self.options, rpc=rpc, activation_height=102)
        path = Path(self.directory.name) / "delayed.sqlite"
        # No preactivation header/snapshot is supplied by the RPC double.
        with HashMiningGate(path, **options) as gate:
            self.assertIsNone(gate._parent_snapshot(101, rpc.tip, {}))
            self.assertIn(b'"activation_height":102', gate.config)
            gate.register_snapshot(opening.serialize())
            gate.register_template(origin.serialize())
            proof = solve_share(origin, opening)
            self.assertTrue(gate.receive(proof))
            self.assertEqual(gate.batch_status()["selected_proofs"], (f"{proof.proof_id:064x}",))
            self.assertFalse(gate._eligible(101, rpc.tip, 101))
            head = gate.archive_head()
        with HashMiningGate(path, **options) as gate:
            self.assertEqual(gate.archive_head(), head)
        with self.assertRaisesRegex(ValueError, "activation height 1 required"):
            HashMiningGate(Path(self.directory.name) / "wrong-height.sqlite", **dict(options, activation_height=1))
        def forbidden_parent(*unused):
            raise AssertionError("preactivation has no settlement opening")
        self.assertEqual(check_graph(opening, lookup=lambda unused: None,
            parent_snapshot=forbidden_parent, activation_height=102)["origins"], 0)
        for invalid in (0, -1, True, 1.5, 0x80000000):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                HashMiningGate(Path(self.directory.name) / "invalid.sqlite", **dict(options, activation_height=invalid))

    def test_top_parent_certificate_skips_only_its_authenticated_origin_graph(self):
        # Child opening is deliberately unavailable. Only the exact certificate
        # from the actual top parent may eliminate that transitive dependency.
        child, child_opening = fixture(version=5, ntime=1700000020)
        descendant = solve_share(child, child_opening)
        origin, opening = fixture(version=5, ntime=1700000021, templates=[child], shares=[descendant])
        receipt = solve_share(origin, opening)
        anchor, parent = fixture(version=5, pool=9, templates=[origin], shares=[receipt])
        anchor.solve()
        _, current = fixture(version=5, height=2, native_parent=anchor.sha256, parent_snapshot=parent,
                             templates=[origin], shares=[solve_share(origin, opening, start_nonce=receipt.header.nNonce + 1)])
        loaded = []
        def lookup(identity):
            loaded.append(identity)
            if identity != opening.hash:
                raise ValueError("unavailable historical dependency")
            return opening
        parents = lambda *unused: parent
        result = check_graph(current, lookup=lookup, parent_snapshot=parents)
        self.assertEqual(loaded, [opening.hash])
        self.assertEqual(result["origins"], 1)
        self.assertEqual(check_graph(opening, lookup=lookup, parent_snapshot=parents,
            trusted_parent=parent, root_origin=TemplateRecord.from_block(origin), root_depth=1)["origins"], 1)
        # Proposed current certificates are not usable as trust anchors.
        with self.assertRaisesRegex(ValueError, "unavailable"):
            check_graph(current, lookup=lookup, parent_snapshot=lambda *unused: replace(parent, certificates=()))
        # A different exact body cannot borrow the other origin's certificate.
        changed = replace(parent, certificates=(replace(origin_certificate(TemplateRecord.from_block(origin)), identity=123),))
        with self.assertRaisesRegex(ValueError, "unavailable"):
            check_graph(current, lookup=lookup, parent_snapshot=lambda *unused: changed)
        with self.assertRaisesRegex(ValueError, "missing"):
            check_graph(current, lookup=lambda unused: None, parent_snapshot=parents)


if __name__ == "__main__":
    unittest.main()
