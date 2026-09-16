#!/usr/bin/env python3
"""Proof-first admission: fresh native verdicts and bounded missing recovery."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from base_chain_settlement import NativeRPCError
from hash_gate_rpc import missing_snapshot_data
from hash_mining_gate import HashMiningGate, SNAPSHOT, PROOF, TEMPLATE
from hash_snapshot import rules_hash, solve_share
from native_mining_gate import parse_block, template_id
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CTxInWitness
from test_hash_mining_gate import FakeRPC
from test_hash_gate_ledger import LedgerRPC
from test_hash_tides import TidesRPC, codec_fixture
from test_hash_compact import CompactRPC, compact_fixture
from test_hash_snapshot import fixture, SCRIPT
from test_hash_variable import variable_fixture


MISSING = {"code": -25, "message": "sharepool-hash-data-missing"}


class AssignedRPC(CompactRPC):
    """Model control-flow only; native tests exercise real v8 validation."""
    def __call__(self, method, *args):
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            result.update(mode="hash-only-v8-vardiff-tides", rules=f"{rules_hash(8):064x}")
        return result


class HashGateProofFirstTests(unittest.TestCase):
    @contextmanager
    def setup_gate(self, version=7, *, warm=True, register=True):
        rpc = {4: FakeRPC, 5: LedgerRPC, 6: TidesRPC, 7: CompactRPC, 8: AssignedRPC}[version]()
        builder = {4: fixture, 5: lambda: fixture(version=5), 6: codec_fixture,
                   7: compact_fixture, 8: lambda: variable_fixture(share_work_bits=2)}[version]
        origin, opening = builder()
        with tempfile.TemporaryDirectory(prefix="gate-proof-first-") as directory:
            gate = HashMiningGate(Path(directory) / "gate.sqlite", rpc=rpc, pool=3,
                public_key=opening.envelope.public_key, payout_script=SCRIPT, profile_version=version,
                **({"share_work_bits": 2} if version == 8 else {}))
            try:
                rpc.gate = gate
                gate.register_snapshot(opening.serialize())
                if register:
                    gate.register_template(origin.serialize())
                if not warm:
                    rpc.templates.clear()  # Explicitly simulate native origin loss.
                rpc.calls.clear()
                yield gate, rpc, origin, opening, solve_share(origin, opening)
            finally:
                gate.close()

    def assert_no_ack(self, gate, proof, head):
        self.assertEqual(gate.archive_head(), head)
        with self.assertRaises(KeyError):
            gate._read(PROOF, f"{proof.proof_id:064x}")

    @staticmethod
    def names(rpc):
        return [name for name, _ in rpc.calls]

    def test_error_classifier_requires_exact_structured_code_and_message(self):
        self.assertTrue(missing_snapshot_data(JSONRPCException(MISSING)))
        self.assertTrue(missing_snapshot_data(NativeRPCError(-25, MISSING["message"])))
        for error in (
                ValueError(MISSING["message"]), RuntimeError(str(MISSING)),
                NativeRPCError(-26, MISSING["message"]), NativeRPCError(-25.0, MISSING["message"]),
                NativeRPCError(-25, MISSING["message"] + " (-25)"),
                JSONRPCException({"code": -25, "message": "Native tip changed during validation"}),
                JSONRPCException({"code": "-25", "message": MISSING["message"]}),
                JSONRPCException({"code": -25}), JSONRPCException({"message": MISSING["message"]}),
                TimeoutError("timeout")):
            with self.subTest(error=repr(error)):
                self.assertFalse(missing_snapshot_data(error))
        conflicting = NativeRPCError(-25, MISSING["message"])
        conflicting.error = {"code": -26, "message": "rejected"}
        self.assertFalse(missing_snapshot_data(conflicting))
        conflicting.error = "malformed"
        self.assertFalse(missing_snapshot_data(conflicting))

    def test_each_profile_explicit_registration_needs_no_first_proof_recovery(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version) as (gate, rpc, origin, opening, proof):
                self.assertTrue(gate.receive(proof))
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 1)
                self.assertNotIn("validatesharepoolhashtemplate", self.names(rpc))
                self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))
                rpc.calls.clear()
                later = solve_share(origin, opening, start_nonce=proof.header.nNonce + 1)
                self.assertTrue(gate.receive(later))
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 1)
                self.assertNotIn("validatesharepoolhashtemplate", self.names(rpc))
                self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))
                self.assertEqual(gate.archive_head()["receipt_revision"], 2)

    def test_each_profile_registration_republishes_durable_opening_after_native_loss(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version, register=False) as (gate, rpc, origin, opening, proof):
                rpc.snapshots.clear()
                gate.register_template(origin.serialize())
                self.assertEqual(rpc.snapshots[opening.hash_hex], opening.serialize().hex())
                registrations = [args for name, args in rpc.calls if name == "validatesharepoolhashtemplate"]
                self.assertEqual(registrations, [(origin.serialize().hex(),)] * 2)
                methods = self.names(rpc)
                first = methods.index("validatesharepoolhashtemplate")
                self.assertNotIn("submitsharepoolhashsnapshot", methods[:first])
                self.assertIn(template_id(origin), rpc.templates)
                rpc.calls.clear()
                self.assertTrue(gate.receive(proof))
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 1)
                self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))

    def test_registration_native_rejection_or_opening_eviction_never_retains_origin(self):
        for failure in ("invalid", "eviction"):
            with self.subTest(failure=failure), self.setup_gate(register=False) as (gate, rpc, origin, _, proof):
                head = gate.archive_head()
                if failure == "invalid":
                    rpc.template_error = "native origin rejected"
                    expected = ValueError
                else:
                    def evict(method, *args):
                        if method == "validatesharepoolhashtemplate":
                            rpc.snapshots.clear()
                        return rpc(method, *args)
                    gate.rpc = evict
                    expected = JSONRPCException
                with self.assertRaises(expected):
                    gate.register_template(origin.serialize())
                self.assertNotIn(template_id(origin), rpc.templates)
                with self.assertRaises(KeyError):
                    gate._read(TEMPLATE, template_id(origin))
                self.assert_no_ack(gate, proof, head)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashtemplate"), 1 if failure == "invalid" else 2)

    def test_native_retention_does_not_override_later_registration_failure(self):
        for failure in ("tip", "persist"):
            with self.subTest(failure=failure), self.setup_gate(register=False) as (gate, rpc, origin, _, proof):
                head = gate.archive_head()
                if failure == "tip":
                    rpc.race = True
                    with self.assertRaisesRegex(ValueError, "tip changed"):
                        gate.register_template(origin.serialize())
                    rpc.race = False
                    rpc.tip = rpc.hashes[0]
                else:
                    with patch.object(gate, "_persist", side_effect=ValueError("resident quota exhausted")):
                        with self.assertRaisesRegex(ValueError, "quota exhausted"):
                            gate.register_template(origin.serialize())
                self.assertIn(template_id(origin), rpc.templates)
                with self.assertRaises(KeyError):
                    gate._read(TEMPLATE, template_id(origin))
                self.assert_no_ack(gate, proof, head)
                with self.assertRaisesRegex(ValueError, "durably validated full origin"):
                    gate.receive(proof)
                self.assert_no_ack(gate, proof, head)
                # A clean retry can durably register the already-native-valid
                # origin; evidence alone did not grant that local registration.
                gate.register_template(origin.serialize())
                self.assertTrue(gate.receive(proof))

    def test_each_profile_missing_template_recovers_once_without_overlay(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version, warm=False) as (gate, rpc, _, _, proof):
                self.assertTrue(gate.receive(proof))
                methods = self.names(rpc)
                self.assertEqual(methods.count("validatesharepoolhashshare"), 2)
                self.assertEqual(methods.count("validatesharepoolhashtemplate"), 1)
                template_at = methods.index("validatesharepoolhashtemplate")
                proof_at = [i for i, name in enumerate(methods) if name == "validatesharepoolhashshare"]
                self.assertLess(proof_at[0], template_at)
                self.assertLess(template_at, proof_at[1])
                writes = [i for i, name in enumerate(methods) if name == "submitsharepoolhashsnapshot"]
                self.assertTrue(writes)
                self.assertTrue(all(proof_at[0] < i < template_at for i in writes))
                self.assertEqual(rpc.calls[template_at][1][1:], (None, False))

    def test_exact_staged_witness_body_and_opening_are_bound_before_native_success(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version) as (gate, rpc, origin, opening, proof):
                changed = parse_block(origin.serialize())
                changed.vtx[0].wit.vtxinwit = [CTxInWitness()]
                changed.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"x" * 32]
                identity = template_id(origin)
                self.assertEqual(template_id(changed), identity)
                staged = {(TEMPLATE, identity): changed.serialize(),
                          (SNAPSHOT, opening.hash_hex): opening.serialize()}
                gate._require_origin(proof, staged)  # Header/envelope alone cannot detect this substitution.
                with self.assertRaisesRegex(ValueError, "exact committed job"):
                    gate._native_share(proof, rpc.tip, staged)
                self.assertNotIn("validatesharepoolhashshare", self.names(rpc))
                staged[TEMPLATE, identity] = origin.serialize()
                staged[SNAPSHOT, opening.hash_hex] = replace(opening, job_commitment=opening.job_commitment ^ 1).serialize()
                with self.assertRaisesRegex(ValueError, "exact committed job"):
                    gate._native_share(proof, rpc.tip, staged)
                self.assertNotIn("validatesharepoolhashshare", self.names(rpc))

    def test_each_profile_same_tip_restart_rehydrates_without_cache_authority(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version) as (gate, rpc, _, opening, proof):
                tip = rpc.tip
                gate._snapshot(opening.hash_hex)
                rpc.templates.clear()
                rpc.snapshots.clear()
                self.assertTrue(gate.receive(proof))
                self.assertEqual(rpc.tip, tip)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 2)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashtemplate"), 1)
                self.assertEqual(rpc.snapshots[opening.hash_hex], opening.serialize().hex())

    def test_other_failures_do_not_trigger_recovery_or_ack(self):
        errors = [JSONRPCException({"code": code, "message": MISSING["message"]})
                  for code in (-26, -22, -8, -28, -1, -20, -32603)]
        errors += [JSONRPCException({"code": -25, "message": "Native tip changed during validation"}),
                   ValueError(MISSING["message"]), TimeoutError("RPC timeout")]
        for error in errors:
            with self.subTest(error=repr(error)), self.setup_gate() as (gate, rpc, _, _, proof):
                head = gate.archive_head()
                def fail(method, *args):
                    if method == "validatesharepoolhashshare":
                        rpc.calls.append((method, args))
                        raise error
                    return rpc(method, *args)
                gate.rpc = fail
                with self.assertRaises(type(error)):
                    gate.receive(proof)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 1)
                self.assertNotIn("validatesharepoolhashtemplate", self.names(rpc))
                self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))
                self.assert_no_ack(gate, proof, head)

    def test_second_missing_and_eviction_after_recovery_do_not_loop(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version, warm=False) as (gate, rpc, _, _, proof):
                head = gate.archive_head()
                def evict(method, *args):
                    result = rpc(method, *args)
                    if method == "validatesharepoolhashtemplate":
                        rpc.templates.clear()
                    return result
                gate.rpc = evict
                with self.assertRaises(JSONRPCException) as failure:
                    gate.receive(proof)
                self.assertEqual(failure.exception.error, MISSING)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 2)
                self.assertEqual(self.names(rpc).count("validatesharepoolhashtemplate"), 1)
                self.assert_no_ack(gate, proof, head)

    def test_tip_and_profile_change_before_recovery_cannot_publish_or_ack(self):
        for change in ("tip", "profile"):
            with self.subTest(change=change), self.setup_gate() as (gate, rpc, _, _, proof):
                head = gate.archive_head()
                calls_after_missing = []
                failed = False
                def changing(method, *args):
                    nonlocal failed
                    if method == "validatesharepoolhashshare":
                        rpc.calls.append((method, args))
                        failed = True
                        if change == "tip":
                            rpc.tip = rpc.hashes[0] = "11" * 32
                        raise JSONRPCException(MISSING)
                    if failed:
                        calls_after_missing.append(method)
                    result = rpc(method, *args)
                    if failed and change == "profile" and method == "getsharepoolhashstatus":
                        result["mode"] = "hash-only-v4"
                    return result
                gate.rpc = changing
                with self.assertRaises(ValueError):
                    gate.receive(proof)
                self.assertNotIn("submitsharepoolhashsnapshot", calls_after_missing)
                self.assertNotIn("validatesharepoolhashtemplate", calls_after_missing)
                self.assert_no_ack(gate, proof, head)

    def test_tip_change_during_recovery_stops_before_second_proof(self):
        with self.setup_gate(warm=False) as (gate, rpc, _, _, proof):
            head = gate.archive_head()
            rpc.race = True
            with self.assertRaisesRegex(ValueError, "tip changed"):
                gate.receive(proof)
            self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 1)
            self.assertEqual(self.names(rpc).count("validatesharepoolhashtemplate"), 1)
            self.assert_no_ack(gate, proof, head)

    def test_corrupt_local_evidence_after_missing_is_rechecked_before_recovery(self):
        with self.setup_gate() as (gate, rpc, _, opening, proof):
            head = gate.archive_head()
            def corrupt(method, *args):
                if method == "validatesharepoolhashshare":
                    rpc.calls.append((method, args))
                    with gate.db:
                        gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=? AND identity=?",
                                        (SNAPSHOT, opening.hash_hex))
                    raise JSONRPCException(MISSING)
                return rpc(method, *args)
            gate.rpc = corrupt
            with self.assertRaisesRegex(ValueError, "read-time integrity"):
                gate.receive(proof)
            self.assertNotIn("validatesharepoolhashtemplate", self.names(rpc))
            self.assert_no_ack(gate, proof, head)

    def test_recovery_rechecks_seal_and_dependency_budget_before_storage(self):
        with self.setup_gate(warm=False) as (gate, rpc, _, opening, proof):
            head = gate.archive_head()
            with patch.object(gate, "_check_seal", side_effect=ValueError("protected head changed")):
                with self.assertRaisesRegex(ValueError, "protected head changed"):
                    gate._native_share(proof, rpc.tip)
            self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))
            self.assert_no_ack(gate, proof, head)
            rpc.calls.clear()
            staged = {(SNAPSHOT, opening.hash_hex): opening.serialize()}
            with patch("hash_mining_gate.MAX_DEPENDENCY_BYTES", len(opening.serialize()) - 1):
                with self.assertRaisesRegex(ValueError, "dependency byte budget"):
                    gate._native_share(proof, rpc.tip, staged)
            self.assertNotIn("submitsharepoolhashsnapshot", self.names(rpc))
            self.assert_no_ack(gate, proof, head)

    def test_native_origin_rejection_and_response_mismatch_cannot_be_overridden(self):
        for version in (4, 5, 6, 7, 8):
            with self.subTest(version=version), self.setup_gate(version) as (gate, rpc, _, _, proof):
                head = gate.archive_head()
                rpc.template_error = "native origin body rejected"
                with self.assertRaisesRegex(ValueError, "origin body rejected"):
                    gate.receive(proof)
                self.assertNotIn("validatesharepoolhashtemplate", self.names(rpc))
                self.assert_no_ack(gate, proof, head)
                rpc.template_error, rpc.bad_response = None, True
                with self.assertRaisesRegex(ValueError, "response failed binding"):
                    gate.receive(proof)
                self.assert_no_ack(gate, proof, head)

    def test_successful_native_recovery_still_requires_durable_ack(self):
        with self.setup_gate(warm=False) as (gate, rpc, _, _, proof):
            head = gate.archive_head()
            with patch.object(gate, "_persist", side_effect=ValueError("resident quota exhausted")):
                with self.assertRaisesRegex(ValueError, "quota exhausted"):
                    gate.receive(proof)
            self.assertEqual(self.names(rpc).count("validatesharepoolhashshare"), 2)
            self.assert_no_ack(gate, proof, head)


if __name__ == "__main__":
    unittest.main()
