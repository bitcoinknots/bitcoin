#!/usr/bin/env python3
"""Successful batch captures feed accounting without caching graph validity."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import weakref

import hash_gate_batch
from hash_admission_accounting import MetadataCapacity
from hash_gate_admission import _accountant
from hash_mining_gate import HashMiningGate, SNAPSHOT
from hash_snapshot import SnapshotEncoding, solve_share
from native_mining_gate import REGTEST_GENESIS
from test_hash_gate_origin_cache import AssignedRPC
from test_hash_snapshot import SCRIPT
from test_hash_variable import variable_fixture


class BatchCaptureReuseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="batch-capture-reuse-")
        self.addCleanup(temporary.cleanup)
        self.rpc = AssignedRPC()
        self.origin, self.opening = variable_fixture()
        self.gate = HashMiningGate(Path(temporary.name) / "gate.sqlite", rpc=self.rpc, pool=3,
            public_key=self.opening.envelope.public_key, payout_script=SCRIPT,
            profile_version=8, share_work_bits=0, snapshot_budget=4096)
        self.addCleanup(self.gate.close)
        self.rpc.gate = self.gate
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        self.nonce = 0

    def proof(self):
        proof = solve_share(self.origin, self.opening, start_nonce=self.nonce)
        self.nonce = proof.header.nNonce + 1
        return proof

    def batch(self, **options):
        staged = {}
        parent = self.gate._parent_snapshot(self.rpc.height, self.rpc.tip, staged)
        return self.gate._batch(self.rpc.height, self.rpc.tip, parent, staged=staged,
                               capture_dependencies=True, **options)

    def test_accountant_refresh_uses_only_empty_and_successful_prefix_walks(self):
        for _ in range(2):
            self.gate.receive(self.proof())
        expected = self.gate._admission_state.accountant.resources
        self.gate._admission_state = None
        counts = []
        check_graph = hash_gate_batch.check_graph

        def inspect(snapshot, **options):
            counts.append(len(snapshot.shares))
            return check_graph(snapshot, **options)

        with patch.object(hash_gate_batch, "check_graph", new=inspect), \
                patch.object(self.gate, "_provenance", side_effect=AssertionError("duplicate graph walk")):
            status = self.gate.admission_status()
        self.assertEqual(counts, [0, 2])
        self.assertEqual(status.eligible_count, 2)
        self.assertEqual(self.gate._admission_state.accountant.resources, expected)
        self.assertNotIn("_dependency_captures", self.gate.batch_status())

    def test_exact_fallback_keeps_one_fresh_proof_walk_and_reuses_batch_capture(self):
        rpc = self.rpc

        def tight(method, *args):
            value = rpc(method, *args)
            if method == "getsharepoolhashtidesbudget":
                value["max_output_bytes"] = 62  # Conservative estimate70; exact62.
            return value

        self.gate.rpc = tight
        self.gate.admission_status()
        counts = []
        check_graph = hash_gate_batch.check_graph

        def inspect(snapshot, **options):
            counts.append((bool(options.get("mining_job")), len(snapshot.shares)))
            return check_graph(snapshot, **options)

        with patch.object(hash_gate_batch, "check_graph", new=inspect), \
                patch.object(self.gate, "_provenance", wraps=self.gate._provenance) as provenance:
            self.assertTrue(self.gate.receive(self.proof()))
        self.assertEqual(provenance.call_count, 1)
        self.assertEqual(counts, [(False, 0), (True, 0), (True, 1)])
        state = self.gate._admission_state
        self.assertEqual(state.quote.resources.recipient_bytes, 62)
        self.assertEqual(state.accountant.resources.recipient_bytes, 70)

    def test_captures_are_bounded_immutable_consumed_and_staged_for_durability(self):
        self.gate.receive(self.proof())
        batch = self.batch()
        captured = batch["_dependency_captures"]
        self.assertIs(type(captured), tuple)
        self.assertTrue(all(type(value) is SnapshotEncoding for value in captured))
        self.assertEqual(captured[0].raw, batch["snapshot"].serialize())
        self.assertEqual(sum(len(value.raw) for value in captured), batch["resources"]["dependency_bytes"])
        self.assertEqual(len({value.hash for value in captured}), len(captured))
        with self.assertRaises(AttributeError):
            captured[0].raw = b"changed"
        with self.assertRaises(AttributeError):
            captured[0].snapshot.payouts[0].nValue = 1
        staged = {}
        accountant = _accountant(batch, staged)
        self.assertNotIn("_dependency_captures", batch)
        self.assertEqual(staged, {(SNAPSHOT, f"{value.hash:064x}"): value.raw for value in captured})
        self.assertEqual(accountant.proof_count, 1)
        # The only retained accounting collections contain scalar/hash facts.
        self.assertFalse(any(type(value) is SnapshotEncoding for value in vars(accountant).values()))

    def test_next_operation_rejects_missing_or_changed_evidence_after_a_success(self):
        self.gate.receive(self.proof())
        self.batch()
        head = self.gate.archive_head()
        read = self.gate._read
        changed = replace(self.opening, owner_signature=b"x" * 64).serialize()
        for body in (None, changed):
            def unavailable(kind, identity):
                if kind == SNAPSHOT and identity == self.opening.hash_hex:
                    if body is None:
                        raise ValueError("snapshot unavailable after prior successful batch")
                    return body
                return read(kind, identity)

            self.gate._admission_state = None
            with self.subTest(body="missing" if body is None else "changed"), \
                    patch.object(self.gate, "_read", new=unavailable), self.assertRaises(ValueError):
                self.gate.admission_status()
            self.assertIsNone(self.gate._admission_state)
            self.assertEqual(self.gate.archive_head(), head)

    def test_optional_accountant_capacity_does_not_drop_captured_evidence(self):
        self.gate.receive(self.proof())
        batch = self.batch()
        captured = batch["_dependency_captures"]
        staged = {}
        with patch("hash_gate_admission.CompactAdmissionAccountant", side_effect=MetadataCapacity), \
                self.assertRaises(MetadataCapacity):
            _accountant(batch, staged)
        self.assertNotIn("_dependency_captures", batch)
        self.assertEqual(staged, {(SNAPSHOT, f"{value.hash:064x}"): value.raw for value in captured})

    def test_capture_collection_preserves_all_graph_resource_limits(self):
        for _ in range(2):
            self.gate.receive(self.proof())
        head = self.gate.archive_head()
        for bound in ("MAX_ORIGIN_CHECKS", "MAX_DEPENDENCY_DEPTH", "MAX_DEPENDENCY_BYTES"):
            value = 500 if bound == "MAX_DEPENDENCY_BYTES" else 1
            with self.subTest(bound=bound), patch.object(hash_gate_batch, bound, value):
                batch = self.batch()
            self.assertEqual(batch["snapshot"].shares, ())
            self.assertEqual(batch["deferred_count"], 2)
            self.assertEqual(len(batch["_dependency_captures"]), 1)
            self.assertEqual(len(batch["_dependency_captures"][0].raw),
                             batch["resources"]["dependency_bytes"])
        self.assertEqual(self.gate.archive_head(), head)

    def test_new_parent_and_reorg_each_rebuild_from_their_own_captures(self):
        self.gate.receive(self.proof())
        original = self.gate._admission_state
        block, opening = variable_fixture(height=1, native_parent=int(self.rpc.tip, 16), ntime=1700000200)
        self.rpc.publish(block, opening)
        with patch.object(self.gate, "_provenance", side_effect=AssertionError("duplicate graph walk")):
            self.gate.admission_status()
        advanced = self.gate._admission_state
        self.assertIsNot(advanced, original)
        self.assertEqual(advanced.key[0], self.rpc.tip)
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.gate.admission_status()
        self.assertIsNot(self.gate._admission_state, advanced)
        self.assertEqual(self.gate._admission_state.accountant.resources, original.accountant.resources)

    def test_tip_change_after_capture_cannot_install_accounting_state(self):
        self.gate.receive(self.proof())
        self.gate._admission_state = None
        batch = self.gate._batch
        head = self.gate.archive_head()

        def changed(*args, **options):
            result = batch(*args, **options)
            self.rpc.tip = "11" * 32
            return result

        with patch.object(self.gate, "_batch", new=changed), \
                self.assertRaisesRegex(ValueError, "native tip changed"):
            self.gate.admission_status()
        self.assertIsNone(self.gate._admission_state)
        self.assertEqual(self.gate.archive_head(), head)

    def test_failed_full_trial_drops_captures_and_rechecks_smaller_prefix(self):
        for _ in range(2):
            self.gate.receive(self.proof())
        check_graph = hash_gate_batch.check_graph
        failed = []
        counts = []

        def inspect(snapshot, **options):
            counts.append(len(snapshot.shares))
            callback = options["on_capture"]
            if len(snapshot.shares) == 2:
                def capture(value):
                    failed.append(weakref.ref(value.snapshot))
                    callback(value)
                options["on_capture"] = capture
            elif len(snapshot.shares) == 1:
                self.assertTrue(failed)
                self.assertTrue(all(reference() is None for reference in failed))
            resources = check_graph(snapshot, **options)
            if len(snapshot.shares) == 2:
                raise hash_gate_batch.BatchLimit("trial-only resource budget")
            return resources

        head = self.gate.archive_head()
        with patch.object(hash_gate_batch, "check_graph", new=inspect):
            batch = self.batch()
        self.assertEqual(counts, [0, 2, 1])
        self.assertEqual(batch["deferred_count"], 1)
        self.assertEqual(len(batch["snapshot"].shares), 1)
        self.assertEqual(sum(len(value.raw) for value in batch["_dependency_captures"]),
                         batch["resources"]["dependency_bytes"])
        self.assertEqual(self.gate.archive_head(), head)


if __name__ == "__main__":
    unittest.main()
