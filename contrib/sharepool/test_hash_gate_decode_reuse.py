#!/usr/bin/env python3
"""Gate decode reuse never substitutes for evidence reads or native checks."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from hash_mining_gate import HashMiningGate, SNAPSHOT, PROOF
from hash_snapshot import Snapshot, solve_share
from test_framework.script import CScript
from test_hash_compact import CompactRPC, compact_fixture
from test_hash_snapshot import SCRIPT
from test_hash_tides import codec_fixture


class HashGateDecodeReuseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="gate-decode-reuse-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "gate.sqlite"
        self.rpc = CompactRPC()
        self.origin, self.opening = compact_fixture()
        self.raw, self.identity = self.opening.serialize(), self.opening.hash_hex
        self.gate = HashMiningGate(self.path, rpc=self.rpc, pool=3,
            public_key=self.opening.envelope.public_key, payout_script=SCRIPT, profile_version=7)
        self.addCleanup(self.gate.close)
        self.rpc.gate = self.gate
        self.gate.register_snapshot(self.raw)
        self.gate.register_template(self.origin.serialize())
        self.gate._snapshot(self.identity)
        self.rpc.calls.clear()

    def assert_unacknowledged(self, proof, head):
        self.assertEqual(self.gate.archive_head(), head)
        with self.assertRaises(KeyError):
            self.gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_repeated_local_access_reads_evidence_but_reuses_decode(self):
        self.gate._snapshot_decode_cache.clear()
        with patch.object(self.gate, "_read", wraps=self.gate._read) as read, \
                patch.object(Snapshot, "deserialize", wraps=Snapshot.deserialize) as decode:
            for _ in range(2):
                self.assertEqual(self.gate._snapshot(self.identity).serialize(), self.raw)
            self.assertEqual(read.call_args_list, [call(SNAPSHOT, self.identity), call(SNAPSHOT, self.identity)])
            self.assertEqual(decode.call_count, 1)
        self.assertEqual(self.gate._snapshot_decode_cache.stats()["hits"], 1)

    def test_warm_decode_does_not_hide_changed_local_bytes_or_metadata(self):
        with self.gate.db:
            self.gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=? AND identity=?",
                                 (SNAPSHOT, self.identity))
        with self.assertRaisesRegex(ValueError, "read-time integrity"):
            self.gate._snapshot(self.identity)
        with self.gate.db:
            self.gate.db.execute("UPDATE journal SET data=?,parent=? WHERE kind=? AND identity=?",
                                 (self.raw, "aa" * 32, SNAPSHOT, self.identity))
        with self.assertRaisesRegex(ValueError, "read-time integrity"):
            self.gate._snapshot(self.identity)

    def test_returned_payout_mutation_cannot_change_next_read_or_origin_check(self):
        first = self.gate._snapshot(self.identity)
        first.payouts[0].nValue += 1
        first.payouts[0].scriptPubKey = CScript(b"\x51")
        second = self.gate._snapshot(self.identity)
        self.assertEqual(second.serialize(), self.raw)
        self.assertIsNot(first.payouts[0], second.payouts[0])
        proof = solve_share(self.origin, self.opening)
        self.gate._require_origin(proof)
        self.assertEqual(self.gate.snapshot_bytes(self.identity), self.raw)

    def test_staged_lookup_and_observer_repeat_even_when_decode_is_warm(self):
        staged, seen = {(SNAPSHOT, self.identity): self.raw}, []
        self.gate._snapshot_observer = seen.append
        try:
            with patch.object(self.gate, "_read", side_effect=AssertionError("staged evidence reread locally")):
                self.assertEqual(self.gate._snapshot(self.identity, staged).serialize(), self.raw)
                self.assertEqual(self.gate._snapshot(self.identity, staged).serialize(), self.raw)
            self.assertEqual(seen, [self.raw, self.raw])
            staged[SNAPSHOT, self.identity] = self.raw + b"\0"
            with self.assertRaises(ValueError):
                self.gate._snapshot(self.identity, staged)
            self.assertEqual(seen[-1], self.raw + b"\0")
        finally:
            self.gate._snapshot_observer = None

    def test_warm_decode_does_not_bypass_observer_budget(self):
        with patch.object(self.gate, "_snapshot_observer", side_effect=ValueError("inventory byte budget")) as observe:
            with self.assertRaisesRegex(ValueError, "inventory byte budget"):
                self.gate._snapshot(self.identity)
            observe.assert_called_once_with(self.raw)

    def test_rpc_fetch_stages_exact_bytes_without_admitting_or_satisfying_availability(self):
        _, alternate = compact_fixture(pool=9, ntime=1700000040)
        raw, identity = alternate.serialize(), alternate.hash_hex
        self.rpc.snapshots[identity] = raw.hex()
        self.gate._snapshot_decode_cache.decode(raw, 7)
        before, staged, observed = self.gate.archive_head(), {}, []
        self.gate._snapshot_observer = observed.append
        try:
            self.assertEqual(self.gate._snapshot(identity, staged).serialize(), raw)
            self.assertEqual(staged, {(SNAPSHOT, identity): raw})
            self.assertEqual(observed, [raw])
            self.assertEqual(self.gate.archive_head(), before)
            with self.assertRaises(KeyError):
                self.gate._read(SNAPSHOT, identity)
            self.assertTrue(any(method == "getsharepoolhashsnapshot" for method, _ in self.rpc.calls))
            self.assertFalse(any(method == "submitsharepoolhashsnapshot" for method, _ in self.rpc.calls))
            del self.rpc.snapshots[identity]
            with self.assertRaises(KeyError):
                self.gate._snapshot(identity, {})
        finally:
            self.gate._snapshot_observer = None

    def test_wrong_profile_and_rpc_commitment_substitution_are_rejected(self):
        _, old = codec_fixture()
        old_raw = old.serialize()
        self.gate._snapshot_decode_cache.decode(old_raw, 6)
        self.rpc.snapshots[old.hash_hex] = old_raw.hex()
        with self.assertRaisesRegex(ValueError, "profile differs"):
            self.gate._snapshot(old.hash_hex, {})
        _, other = compact_fixture(pool=11, ntime=1700000050)
        self.gate._snapshot_decode_cache.decode(other.serialize(), 7)
        requested = "aa" * 32
        self.rpc.snapshots[requested] = other.serialize().hex()
        staged = {}
        with self.assertRaisesRegex(ValueError, "bytes do not match commitment"):
            self.gate._snapshot(requested, staged)
        self.assertEqual(staged, {})

    def test_native_storage_template_and_proof_checks_run_after_decode_hits(self):
        self.gate._snapshot(self.identity)
        self.rpc.calls.clear()
        before_hits = self.gate._snapshot_decode_cache.stats()["hits"]
        proof = solve_share(self.origin, self.opening)
        self.assertTrue(self.gate.receive(proof))
        names = [name for name, _ in self.rpc.calls]
        for method in ("submitsharepoolhashsnapshot", "validatesharepoolhashtemplate", "validatesharepoolhashshare"):
            self.assertIn(method, names)
        self.assertGreater(self.gate._snapshot_decode_cache.stats()["hits"], before_hits)
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)

    def test_same_tip_daemon_loss_rehydrates_before_native_proof_check(self):
        tip = self.rpc.tip
        self.rpc.snapshots.clear()
        proof = solve_share(self.origin, self.opening)
        self.assertTrue(self.gate.receive(proof))
        names = [name for name, _ in self.rpc.calls]
        self.assertLess(names.index("submitsharepoolhashsnapshot"), names.index("validatesharepoolhashtemplate"))
        self.assertLess(names.index("validatesharepoolhashtemplate"), names.index("validatesharepoolhashshare"))
        self.assertEqual(self.rpc.tip, tip)
        self.assertEqual(self.rpc.snapshots[self.identity], self.raw.hex())

    def test_cached_decode_cannot_override_native_rejection_or_bind_wrong_proof(self):
        proof = solve_share(self.origin, self.opening)
        head = self.gate.archive_head()
        self.rpc.template_error = "native template rejected after restart"
        with self.assertRaisesRegex(ValueError, "template rejected"):
            self.gate.receive(proof)
        self.assert_unacknowledged(proof, head)
        self.rpc.template_error, self.rpc.share_error = None, "native proof rejected"
        with self.assertRaisesRegex(ValueError, "proof rejected"):
            self.gate.receive(proof)
        self.assert_unacknowledged(proof, head)
        self.rpc.share_error, self.rpc.bad_response = None, True
        with self.assertRaisesRegex(ValueError, "response failed binding"):
            self.gate.receive(proof)
        self.assert_unacknowledged(proof, head)

    def test_storage_refusal_after_cache_hit_cannot_acknowledge(self):
        proof = solve_share(self.origin, self.opening)
        before = self.gate.archive_head()
        rpc = self.rpc
        def refusing(method, *args):
            if method == "submitsharepoolhashsnapshot":
                raise ValueError("native snapshot storage unavailable")
            return rpc(method, *args)
        self.gate.rpc = refusing
        with self.assertRaisesRegex(ValueError, "storage unavailable"):
            self.gate.receive(proof)
        self.assert_unacknowledged(proof, before)

    def test_close_and_reopen_discard_decode_entries(self):
        self.assertGreater(self.gate._snapshot_decode_cache.stats()["entries"], 0)
        self.gate.close()
        self.assertEqual(self.gate._snapshot_decode_cache.stats()["entries"], 0)
        gate = HashMiningGate(self.path, rpc=self.rpc, pool=3,
            public_key=self.opening.envelope.public_key, payout_script=SCRIPT, profile_version=7)
        try:
            self.assertEqual(gate._snapshot_decode_cache.stats()["entries"], 0)
            self.assertEqual(gate._snapshot(self.identity).serialize(), self.raw)
        finally:
            gate.close()


if __name__ == "__main__":
    unittest.main()
