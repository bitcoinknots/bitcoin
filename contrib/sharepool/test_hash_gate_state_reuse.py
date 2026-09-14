#!/usr/bin/env python3
"""Reused accounting state never substitutes for native ancestry or evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hash_snapshot
from hash_mining_gate import HashMiningGate, PROOF
from hash_snapshot import solve_share
from test_hash_compact import CompactRPC, compact_fixture
from test_hash_snapshot import SCRIPT


class GateStateReuseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="gate-state-reuse-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "gate.sqlite"
        self.rpc = CompactRPC()
        origin, opening = compact_fixture()
        proof = solve_share(origin, opening)
        self.block, self.parent = compact_fixture(templates=(origin,), shares=(proof,))
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        self.rpc.publish(self.block, self.parent)
        self.tip = self.rpc.tip
        self.gate = HashMiningGate(self.path, rpc=self.rpc, pool=3,
            public_key=self.parent.envelope.public_key, payout_script=SCRIPT, profile_version=7)
        self.addCleanup(self.gate.close)
        self.rpc.gate = self.gate

    def load_parent(self):
        return self.gate._parent_snapshot(1, self.tip, {})

    def test_warm_parent_reuses_arithmetic_but_rereads_native_header_and_opening(self):
        with patch("hash_snapshot.apply_tides_state", wraps=hash_snapshot.apply_tides_state) as apply:
            first = self.load_parent()
            self.assertGreater(apply.call_count, 0)
            apply.reset_mock()
            self.rpc.calls.clear()
            observed = []
            self.gate._snapshot_observer = observed.append
            try:
                second = self.load_parent()
            finally:
                self.gate._snapshot_observer = None
            self.assertEqual(first.post_state, second.post_state)
            self.assertEqual(first.history_head, second.history_head)
            self.assertEqual(apply.call_count, 0)
            names = [name for name, _ in self.rpc.calls]
            self.assertIn("getblockheader", names)
            self.assertIn("getsharepoolhashsnapshot", names)
            self.assertIn("getbestblockhash", names)
            self.assertEqual(observed, [self.parent.serialize()])

    def test_warm_state_does_not_supply_missing_opening(self):
        self.load_parent()
        del self.rpc.snapshots[self.parent.hash_hex]
        with self.assertRaises(KeyError):
            self.load_parent()

    def test_changed_opening_or_observer_refusal_cannot_use_warm_state(self):
        self.load_parent()
        raw = self.parent.serialize()
        self.rpc.snapshots[self.parent.hash_hex] = (raw + b"\0").hex()
        with self.assertRaises(ValueError):
            self.load_parent()
        self.rpc.snapshots[self.parent.hash_hex] = raw.hex()
        with patch.object(self.gate, "_snapshot_observer", side_effect=ValueError("inventory budget")):
            with self.assertRaisesRegex(ValueError, "inventory budget"):
                self.load_parent()

    def test_changed_tip_still_rejects_an_old_parent_after_cache_hit(self):
        self.load_parent()
        self.rpc.tip = "ab" * 32
        with self.assertRaises(ValueError):
            self.load_parent()

    def test_alternative_branch_recomputes_and_old_branch_remains_exact(self):
        first = self.load_parent()
        other, other_opening = compact_fixture(pool=9, ntime=1700000100)
        self.rpc.publish(other, other_opening)
        with patch("hash_snapshot.apply_tides_state", wraps=hash_snapshot.apply_tides_state) as apply:
            second = self.gate._parent_snapshot(1, self.rpc.tip, {})
            self.assertGreater(apply.call_count, 0)
        self.assertNotEqual(first.history_head, second.history_head)
        self.rpc.tip = self.tip
        self.assertEqual(self.load_parent().history_head, first.history_head)

    def test_native_rejection_still_prevents_acknowledgment_with_warm_history(self):
        parent = self.load_parent()
        origin, opening = compact_fixture(height=2, native_parent=int(self.tip, 16),
            parent_snapshot=parent, ntime=1700000120)
        self.gate.register_snapshot(opening.serialize())
        self.gate.register_template(origin.serialize())
        proof = solve_share(origin, opening)
        before = self.gate.archive_head()
        hits = self.gate._compact_state_cache.stats()["hits"]
        self.rpc.share_error = "native proof rejection with warm history"
        with self.assertRaisesRegex(ValueError, "native proof rejection"):
            self.gate.receive(proof)
        self.assertGreater(self.gate._compact_state_cache.stats()["hits"], hits)
        self.assertEqual(self.gate.archive_head(), before)
        with self.assertRaises(KeyError):
            self.gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_close_discards_state_without_persisting_it_as_evidence(self):
        self.load_parent()
        self.assertGreater(self.gate._compact_state_cache.stats()["entries"], 0)
        self.assertGreater(self.gate._signature_cache.stats()["entries"], 0)
        self.gate.close()
        self.assertEqual(self.gate._compact_state_cache.stats()["entries"], 0)
        self.assertEqual(self.gate._signature_cache.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
