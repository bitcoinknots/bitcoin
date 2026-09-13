#!/usr/bin/env python3
"""Dispatch capability isolation; native validity is tested by functional gates."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hash_mining_gate import HashMiningAuthorization, HashMiningGate
from hash_snapshot import MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, solve_share
from native_mining_gate import MiningAuthorization, parse_block
from test_hash_gate_ledger import LedgerRPC
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


class HashGateDispatchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="gate-dispatch-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.gates = []
        self.addCleanup(lambda: [gate.close() for gate in self.gates])

    def gate(self, name="gate", *, version=4, **extra):
        block, snapshot = fixture(version=version)
        rpc = FakeRPC() if version == 4 else LedgerRPC()
        options = dict(rpc=rpc, pool=3, public_key=snapshot.envelope.public_key,
                       payout_script=SCRIPT, profile_version=version)
        options.update(extra)
        gate = HashMiningGate(self.directory / (name + ".sqlite"), **options)
        rpc.gate = gate
        self.gates.append(gate)
        return gate, rpc, block, snapshot

    def test_authorized_bytes_are_frozen_and_native_preflight_is_required(self):
        for version in (4, 5):
            with self.subTest(version=version):
                gate, rpc, block, snapshot = self.gate(str(version), version=version)
                rpc.template_error = "native validation refused"
                with self.assertRaisesRegex(ValueError, "native validation refused"):
                    gate.authorize(block.serialize(), snapshot.serialize())
                rpc.template_error = None
                authorization = gate.authorize(block.serialize(), snapshot.serialize())
                self.assertTrue(any(method == "validatesharepoolhashtemplate" for method, unused in rpc.calls))
                self.assertTrue(gate.ready_for_dispatch(authorization))
                self.assertEqual(authorization.block_bytes, block.serialize())
                self.assertEqual(authorization.snapshot_bytes, snapshot.serialize())
                with self.assertRaises(FrozenInstanceError):
                    authorization.block_bytes = b"changed"
                solved = solve_share(block, snapshot)
                self.assertEqual(parse_block(authorization.block_for_header(solved.header_bytes)).m_mm_rhs, snapshot.hash)

    def test_fabricated_exact_class_subclass_and_duck_objects_are_refused(self):
        gate, rpc, block, snapshot = self.gate()
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        class PretendAuthorization(HashMiningAuthorization):
            pass
        unsigned = HashMiningAuthorization(authorization.block_bytes, authorization.native_parent,
            authorization.commitment, authorization.receipt_sequence, authorization.snapshot_bytes,
            authorization.evidence_sequence)
        objects = [None, object(), unsigned, object.__new__(HashMiningAuthorization),
            SimpleNamespace(**authorization.__dict__),
            MiningAuthorization(authorization.block_bytes, authorization.native_parent,
                authorization.commitment, authorization.receipt_sequence),
            PretendAuthorization(**authorization.__dict__)]
        for value in objects:
            with self.subTest(kind=type(value)):
                rpc.calls.clear()
                self.assertFalse(gate.ready_for_dispatch(value))
                self.assertTrue(gate.needs_refresh(value))
                self.assertEqual(rpc.calls, [])

    def test_every_capability_field_is_authenticated_even_after_forced_mutation(self):
        gate, unused, block, snapshot = self.gate()
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        changed_block, changed_snapshot = fixture(ntime=block.nTime + 1)
        changes = {
            "block_bytes": changed_block.serialize(), "snapshot_bytes": changed_snapshot.serialize(),
            "native_parent": "12" * 32, "commitment": changed_snapshot.hash_hex,
            "receipt_sequence": authorization.receipt_sequence + 1,
            "evidence_sequence": authorization.evidence_sequence + 1,
            "native_height": authorization.native_height + 1, "policy_binding": "34" * 32,
            "dispatch_seal": b"x" * 32,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertFalse(gate.ready_for_dispatch(replace(authorization, **{field: value})))
                forced = replace(authorization)
                object.__setattr__(forced, field, value)
                self.assertFalse(gate.ready_for_dispatch(forced))
                deleted = replace(authorization)
                object.__delattr__(deleted, field)
                self.assertFalse(gate.ready_for_dispatch(deleted))
        # Coordinated replacement of all public identifiers cannot bless a
        # different otherwise valid signed job without native authorization.
        changed = replace(authorization, block_bytes=changed_block.serialize(),
            snapshot_bytes=changed_snapshot.serialize(), commitment=changed_snapshot.hash_hex)
        self.assertFalse(gate.ready_for_dispatch(changed))
        self.assertTrue(gate.ready_for_dispatch(authorization))

    def test_wrong_field_types_and_bounds_are_refused_without_native_calls(self):
        gate, rpc, block, snapshot = self.gate()
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        changes = {
            "block_bytes": (bytearray(authorization.block_bytes), b"", b"x" * (MAX_TEMPLATE_BYTES + 1)),
            "snapshot_bytes": (memoryview(authorization.snapshot_bytes), b"", b"x" * (MAX_SNAPSHOT_BYTES + 1)),
            "native_parent": (None, 0, "XX" * 32), "commitment": (None, "12"),
            "receipt_sequence": (True, -1, 1 << 64), "evidence_sequence": (True, -1, 1 << 64),
            "native_height": (True, -1, 0x7fffffff), "policy_binding": (None, "XX" * 32),
            "dispatch_seal": (None, bytearray(authorization.dispatch_seal), b""),
        }
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, kind=type(value)):
                    rpc.calls.clear()
                    self.assertFalse(gate.ready_for_dispatch(replace(authorization, **{field: value})))
                    self.assertEqual(rpc.calls, [])

    def test_distinct_gates_with_identical_policy_tip_and_revisions_cannot_cross_dispatch(self):
        first, unused, block, snapshot = self.gate("first")
        second, unused, _, _ = self.gate("second")
        a = first.authorize(block.serialize(), snapshot.serialize())
        b = second.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(a.policy_binding, b.policy_binding)
        self.assertEqual(first.archive_head(), second.archive_head())
        self.assertTrue(first.ready_for_dispatch(a))
        self.assertTrue(second.ready_for_dispatch(b))
        self.assertFalse(first.ready_for_dispatch(b))
        self.assertFalse(second.ready_for_dispatch(a))
        # Copying a foreign seal onto a different local job fails as well.
        self.assertFalse(first.ready_for_dispatch(replace(a, dispatch_seal=b.dispatch_seal)))

    def test_restart_close_and_inherited_process_revoke_dispatch_without_changing_journal(self):
        gate, unused, block, snapshot = self.gate()
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        head = gate.archive_head()
        with patch("hash_mining_gate.os.getpid", return_value=gate._dispatch_pid + 1):
            self.assertFalse(gate.ready_for_dispatch(authorization))
        gate.close()
        self.assertFalse(gate.ready_for_dispatch(authorization))
        restored, rpc, _, _ = self.gate()
        self.assertEqual(restored.archive_head(), head)
        self.assertFalse(restored.ready_for_dispatch(authorization))
        rpc.template_error = "fresh native validation required"
        with self.assertRaisesRegex(ValueError, "fresh native validation required"):
            restored.authorize(block.serialize(), snapshot.serialize())
        rpc.template_error = None
        renewed = restored.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(restored.ready_for_dispatch(renewed))
        self.assertFalse(restored.ready_for_dispatch(authorization))
        self.assertEqual(restored.archive_head(), head)
        # Revocation stops new dispatch; previously returned work remains an
        # immutable block candidate and can still be submitted if solved.
        solved = solve_share(block, snapshot)
        self.assertEqual(parse_block(authorization.block_for_header(solved.header_bytes)).m_mm_rhs, snapshot.hash)

    def test_current_policy_profile_tip_and_receipts_still_fence_dispatch(self):
        gate, rpc, block, snapshot = self.gate()
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        changes = {"pool": 4, "public_key": b"x" * 32, "payout_script": b"\x00\x14" + b"b" * 20,
                   "snapshot_budget": gate.snapshot_budget - 1, "quota": gate.quota - 1,
                   "profile_version": 5, "rules": gate.rules ^ 1, "mode": "other",
                   "activation_height": 2, "config": gate.config + b" ", "binding": "12" * 32}
        for field, value in changes.items():
            with self.subTest(field=field), patch.object(gate, field, value):
                self.assertFalse(gate.ready_for_dispatch(authorization))
        with patch.object(rpc, "chain", "main"):
            with self.assertRaisesRegex(ValueError, "regtest"):
                gate.ready_for_dispatch(authorization)
        other, unused, _, _ = self.gate("v5", version=5)
        self.assertFalse(other.ready_for_dispatch(authorization))
        rpc.publish(block, snapshot)
        self.assertFalse(gate.ready_for_dispatch(authorization))
        rpc.height, rpc.tip = 0, rpc.hashes[0]
        self.assertTrue(gate.ready_for_dispatch(authorization))
        gate.receive(solve_share(block, snapshot))
        self.assertFalse(gate.ready_for_dispatch(authorization))


if __name__ == "__main__":
    unittest.main()
