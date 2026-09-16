#!/usr/bin/env python3
"""Atomic provenance admission and recovery using a dependency-strict RPC double.

The double checks required snapshot openings, not native scripts or UTXOs.
feature_sharepool_hash_gate_provenance.py covers real native RPC recovery.
"""
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_gate_batch import check_graph
from hash_mining_gate import HashMiningGate, SNAPSHOT, TEMPLATE, PROOF
from hash_snapshot import Snapshot, solve_share, normalize_template
from native_mining_gate import parse_block, template_id
from test_framework.messages import CBlockHeader
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


class GraphRPC(FakeRPC):
    def __call__(self, method, *args):
        result = super().__call__(method, *args)
        if method == "validatesharepoolhashtemplate":
            block = parse_block(bytes.fromhex(args[0]))
            opening = Snapshot.deserialize(bytes.fromhex(args[1] if len(args) > 1 and args[1] is not None else
                                                          self.snapshots[f"{block.m_mm_rhs:064x}"]))

            def lookup(identity):
                key = f"{identity:064x}"
                if key not in self.snapshots:
                    raise ValueError("required native snapshot is unavailable")
                return Snapshot.deserialize(bytes.fromhex(self.snapshots[key]))

            def parent(identity, height):
                header = CBlockHeader()
                header.deserialize(BytesIO(bytes.fromhex(self.headers[f"{identity:064x}"])))
                return lookup(header.m_mm_rhs)

            check_graph(opening, lookup=lookup, parent_snapshot=parent)
        return result


class HashGateProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hash-gate-provenance-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rpc = GraphRPC()
        unused, opening = fixture()
        self.options = dict(rpc=self.rpc, pool=3, public_key=opening.envelope.public_key, payout_script=SCRIPT)

    def gate(self, name="source.sqlite", **extra):
        gate = HashMiningGate(self.directory / name, **dict(self.options, **extra))
        self.addCleanup(gate.close)
        return gate

    def chain(self, count=3):
        pairs, proof = [], None
        for index in range(count):
            block, opening = fixture(ntime=1700000001 + index,
                templates=[pairs[-1][0]] if pairs else (), shares=[proof] if pairs else ())
            pairs.append((block, opening))
            proof = solve_share(block, opening)
            self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        return pairs

    def assert_closure(self, gate, pairs):
        for unused, opening in pairs:
            self.assertEqual(gate.snapshot_bytes(opening.hash_hex), opening.serialize())

    def cold_restore(self, gate):
        archive = self.directory / "complete.spharc"
        head = gate.export_archive(archive)
        gate.close()
        self.rpc.snapshots.clear()
        restored = HashMiningGate.restore_archive(archive, self.directory / "restored.sqlite",
                                                  trusted_head=head, **self.options)
        self.addCleanup(restored.close)
        self.assertEqual(restored.archive_head(), head)
        self.assertEqual(restored.revalidate_active()["retained_receipts"], head["receipt_revision"])
        return restored

    def test_authorization_atomically_retains_transitive_openings_for_cold_restore(self):
        pairs = self.chain()
        block, opening = pairs[-1]
        gate = self.gate()
        with patch.object(gate, "_persist", wraps=gate._persist) as persist:
            authorization = gate.authorize(block.serialize(), opening.serialize())
        self.assertEqual(persist.call_count, 1)
        self.assertEqual(authorization.receipt_sequence, 1)
        self.assert_closure(gate, pairs)
        restored = self.cold_restore(gate)
        self.assert_closure(restored, pairs)
        self.assertEqual(len(restored.eligible_shares()), 1)

    def test_older_origin_parent_paid_state_is_retained_separately_from_current_parent(self):
        first, first_opening = fixture()
        self.rpc.publish(first, first_opening)
        second, second_opening = fixture(height=2, native_parent=int(self.rpc.tip, 16),
            ntime=1700000002, parent_snapshot=first_opening)
        origin, opening = fixture(height=2, native_parent=int(self.rpc.tip, 16),
            ntime=1700000003, parent_snapshot=first_opening)
        self.rpc.publish(second, second_opening)
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proposal, snapshot = fixture(height=3, native_parent=int(self.rpc.tip, 16),
            ntime=1700000004, parent_snapshot=second_opening,
            templates=[origin], shares=[solve_share(origin, opening)])
        gate = self.gate()
        gate.authorize(proposal.serialize(), snapshot.serialize())
        pairs = [(first, first_opening), (second, second_opening), (origin, opening), (proposal, snapshot)]
        self.assert_closure(gate, pairs)
        self.assert_closure(self.cold_restore(gate), pairs)

    def test_registration_retains_complete_graph_and_duplicate_receive_rehydrates_it(self):
        pairs = self.chain()
        block, opening = pairs[-1]
        gate = self.gate()
        gate.register_template(block.serialize())
        self.assert_closure(gate, pairs)
        proof = solve_share(block, opening)
        self.assertTrue(gate.receive(proof))
        head = gate.archive_head()
        self.rpc.snapshots.clear()
        self.assertFalse(gate.receive(proof))
        self.assertEqual(gate.archive_head(), head)
        self.assert_closure(self.cold_restore(gate), pairs)

    def test_receive_repairs_preexisting_incomplete_provenance_in_the_proof_commit(self):
        pairs = self.chain()
        block, opening = pairs[-1]
        gate = self.gate()
        # Simulate a pre-fix journal retaining only the immediate origin. No
        # receipt has been acknowledged yet; the new receipt must close it.
        gate.register_snapshot(opening.serialize())
        gate._persist([(TEMPLATE, normalize_template(block))])
        proof = solve_share(block, opening)
        with patch.object(gate, "_persist", wraps=gate._persist) as persist:
            self.assertTrue(gate.receive(proof))
        self.assertEqual(persist.call_count, 1)
        self.assert_closure(gate, pairs)
        self.assertEqual(gate.archive_head()["receipt_revision"], 1)

    def test_warm_native_receive_atomically_retains_fetched_graph_without_republishing(self):
        pairs = self.chain()
        block, opening = pairs[-1]
        proof = solve_share(block, opening)
        self.rpc.templates[template_id(block)] = block.serialize()
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds):
                gate = self.gate(f"warm-native-{succeeds}.sqlite")
                gate.register_snapshot(opening.serialize())
                gate._persist([(TEMPLATE, normalize_template(block))])
                head = gate.archive_head()
                self.rpc.calls.clear()
                self.rpc.share_error = None if succeeds else "native proof refused"
                with patch.object(gate, "_persist", wraps=gate._persist) as persist, \
                        patch.object(gate, "_rehydrate_retained", side_effect=AssertionError("unnecessary replay")):
                    if succeeds:
                        self.assertTrue(gate.receive(proof))
                        self.assertEqual(persist.call_count, 1)
                        self.assert_closure(gate, pairs)
                        self.assertEqual(gate.archive_head()["receipt_revision"], 1)
                    else:
                        with self.assertRaisesRegex(ValueError, "native proof refused"):
                            gate.receive(proof)
                        persist.assert_not_called()
                        self.assertEqual(gate.archive_head(), head)
                        with self.assertRaises(KeyError):
                            gate.snapshot_bytes(pairs[0][1].hash_hex)
                        with self.assertRaises(KeyError):
                            gate._read(PROOF, f"{proof.proof_id:064x}")
                methods = [name for name, _ in self.rpc.calls]
                self.assertEqual(methods.count("validatesharepoolhashshare"), 1)
                self.assertNotIn("submitsharepoolhashsnapshot", methods)
                self.assertNotIn("validatesharepoolhashtemplate", methods)

    def test_warm_cache_still_rejects_corrupt_retained_dependency_before_native_write(self):
        pairs = self.chain()
        block, opening = pairs[-1]
        gate = self.gate()
        gate.register_template(block.serialize())
        proof = solve_share(block, opening)
        self.assertTrue(gate.receive(proof))
        next_proof = solve_share(block, opening, start_nonce=proof.header.nNonce + 1)
        head = gate.archive_head()
        identity = pairs[0][1].hash_hex
        with gate.db:
            gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=? AND identity=?",
                            (SNAPSHOT, identity))
        self.rpc.calls.clear()
        with self.assertRaisesRegex(ValueError, "read-time integrity"):
            gate.receive(next_proof)
        self.assertEqual(gate.archive_head(), head)
        with self.assertRaises(KeyError):
            gate._read(PROOF, f"{next_proof.proof_id:064x}")
        methods = [name for name, _ in self.rpc.calls]
        self.assertNotIn("submitsharepoolhashsnapshot", methods)
        self.assertNotIn("validatesharepoolhashshare", methods)

    def test_rejected_registration_never_admits_foreign_or_native_invalid_openings(self):
        gate = self.gate()
        for pool, failure in ((4, None), (3, "native template refused")):
            block, opening = fixture(pool=pool, ntime=1700000030 + pool)
            self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
            self.rpc.template_error = failure
            head, inventory = gate.archive_head(), dict(self.rpc.snapshots)
            with self.subTest(pool=pool), self.assertRaises(ValueError):
                gate.register_template(block.serialize())
            self.assertEqual(gate.archive_head(), head)
            self.assertEqual(self.rpc.snapshots, inventory)
            for kind, identity in ((SNAPSHOT, opening.hash_hex), (TEMPLATE, template_id(block))):
                with self.assertRaises(KeyError):
                    gate._read(kind, identity)

    def test_dependency_quota_failure_rolls_back_authorization_registration_and_receipt(self):
        pairs = self.chain(5)
        block, opening = pairs[-1]
        proof = solve_share(block, opening)
        for mode in ("authorize", "register", "receive"):
            gate = self.gate(mode + ".sqlite", quota=4096)
            if mode == "receive":
                gate.register_snapshot(opening.serialize())
                gate._persist([(TEMPLATE, normalize_template(block))])
            head, resident = gate.archive_head(), gate.resident_bytes()
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "quota"):
                if mode == "authorize":
                    gate.authorize(block.serialize(), opening.serialize())
                elif mode == "register":
                    gate.register_template(block.serialize())
                else:
                    gate.receive(proof)
            self.assertEqual(gate.archive_head(), head)
            self.assertEqual(gate.resident_bytes(), resident)
            with self.assertRaises(KeyError):
                gate.snapshot_bytes(pairs[0][1].hash_hex)
            with self.assertRaises(KeyError):
                gate._read(PROOF, f"{proof.proof_id:064x}")


if __name__ == "__main__":
    unittest.main()
