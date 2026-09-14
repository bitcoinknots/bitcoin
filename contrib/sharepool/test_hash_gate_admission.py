#!/usr/bin/env python3
"""V8 admission control flow, with real canonical bytes and a native RPC double.

These tests cover local pressure/durability, not native consensus correctness.
"""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hash_admission_budget import AdmissionRefused
from hash_gate_batch import EmptyBatchCapacity
from hash_mining_gate import HashMiningGate, PROOF, TEMPLATE, SNAPSHOT
from hash_snapshot import compact_size, solve_share
from native_enforcement import sign_schnorr
from native_mining_gate import REGTEST_GENESIS, template_id
from test_hash_gate_origin_cache import AssignedRPC
from test_hash_snapshot import SCRIPT, SECRET
from test_hash_variable import variable_fixture


class GateAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="v8-admission-")
        self.addCleanup(self.directory.cleanup)
        self.rpc = AssignedRPC()
        self.origin, self.opening = variable_fixture()
        self.path = Path(self.directory.name) / "gate.sqlite"
        self.gate = None
        self.addCleanup(lambda: self.gate.close() if self.gate is not None else None)
        self.nonce = 0
        self.parent = None

    def open_gate(self, budget=4096):
        self.gate = HashMiningGate(self.path, rpc=self.rpc, pool=3,
            public_key=self.opening.envelope.public_key, payout_script=SCRIPT,
            profile_version=8, share_work_bits=0, snapshot_budget=budget)
        self.rpc.gate = self.gate
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        return self.gate

    def proof(self):
        result = solve_share(self.origin, self.opening, start_nonce=self.nonce)
        self.nonce = result.header.nNonce + 1
        return result

    def advance_empty(self):
        block, snapshot = variable_fixture(height=self.rpc.height + 1,
            native_parent=int(self.rpc.tip, 16), parent_snapshot=self.parent,
            ntime=1700000100 + self.rpc.height)
        self.rpc.publish(block, snapshot)
        self.parent = snapshot

    def external_job(self, proofs):
        return variable_fixture(height=self.rpc.height + 1,
            native_parent=int(self.rpc.tip, 16), parent_snapshot=self.parent,
            ntime=1700000300 + self.rpc.height,
            templates=(self.origin,), shares=tuple(proofs))

    def assert_no_receipt(self, proof):
        with self.assertRaises(KeyError):
            self.gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_tight_budget_refuses_without_ack_and_preserves_exact_fitting_prefix(self):
        gate = self.open_gate(1200)
        first, second, third = self.proof(), self.proof(), self.proof()
        self.assertTrue(gate.receive(first))
        self.assertTrue(gate.receive(second))
        head = gate.archive_head()
        calls = len(self.rpc.calls)
        with self.assertRaises(AdmissionRefused) as failure:
            gate.receive(third)
        self.assertIn("pending-prefix-does-not-fit", failure.exception.decision.reasons)
        self.assertFalse(failure.exception.consensus_invalid)
        self.assertEqual(gate.archive_head(), head)
        self.assertEqual(head["receipt_revision"], 2)
        self.assert_no_receipt(third)
        # A pressure refusal follows a fresh native verdict; it cannot be
        # treated as proof invalidity by transport or job dispatch.
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in self.rpc.calls[calls:]), 1)
        batch = gate.batch_status()
        self.assertEqual(set(batch["selected_proofs"]), {f"{p.proof_id:064x}" for p in (first, second)})
        self.assertEqual(batch["resources"]["reserved_snapshot_bytes"], 1179)
        self.assertTrue(gate.admission_status().dispatch_allowed)
        # Refused arrivals did not consume a receipt revision across startup.
        gate.close()
        self.open_gate(1200)
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_no_receipt(third)

    def test_duplicate_under_pressure_is_exact_and_freshly_native_checked(self):
        gate = self.open_gate(1200)
        first, second, refused = self.proof(), self.proof(), self.proof()
        gate.receive(first)
        gate.receive(second)
        with self.assertRaises(AdmissionRefused):
            gate.receive(refused)
        head = gate.archive_head()
        calls = len(self.rpc.calls)
        self.assertFalse(gate.receive(first))
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in self.rpc.calls[calls:]), 1)
        self.rpc.share_error = "fresh native rejection"
        with self.assertRaisesRegex(ValueError, "fresh native rejection"):
            gate.receive(first)
        self.rpc.share_error = None
        with self.assertRaisesRegex(ValueError, "full origin snapshot"):
            gate.receive(replace(first, owner_signature=b"x" * 64))
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(refused)

    def test_new_tip_rebuilds_deadline_and_never_erases_expired_ack(self):
        gate = self.open_gate()
        old = self.proof()
        gate.receive(old)
        original_state = gate._admission_state
        self.advance_empty()
        self.advance_empty()
        self.assertEqual(gate.admission_status().additional_inclusion_heights, 1)
        self.assertIsNot(gate._admission_state, original_state)
        self.advance_empty()
        decision = gate.admission_status()
        self.assertEqual((decision.mode, decision.additional_inclusion_heights, decision.dispatch_allowed),
                         ("DRAIN", 0, True))
        offered = self.proof()
        head = gate.archive_head()
        with self.assertRaises(AdmissionRefused) as failure:
            gate.receive(offered)
        self.assertEqual(failure.exception.decision.reasons, ("admission-deadline-margin",))
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(offered)
        self.assertFalse(gate.receive(old))  # Last-chance ACK is still native eligible.
        self.advance_empty()
        self.assertEqual(gate.admission_status().mode, "OPEN")
        self.assertEqual(gate.batch_status()["selected_proofs"], ())
        retained = gate.receipt_status()["receipts"][0]
        self.assertEqual(retained["status"], "expired_unanchored")
        self.assertIsNone(retained["admitted_in"])
        self.assertEqual(gate._read(PROOF, f"{old.proof_id:064x}"), old.serialize())
        self.assertEqual(gate.archive_head()["receipt_revision"], 1)
        # Returning to the original branch makes the exact retained receipt
        # eligible again and rebuilds metadata from that branch, not old OPEN.
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.assertEqual(gate.admission_status().additional_inclusion_heights, 3)
        self.assertEqual(gate._admission_state.quote.eligible_count, 1)

    def test_external_atomic_offers_cannot_bypass_deadline_pressure(self):
        gate = self.open_gate()
        old = self.proof()
        gate.receive(old)
        for _ in range(3):
            self.advance_empty()
        fresh = (self.proof(), self.proof())
        block, snapshot = self.external_job((old,) + fresh)
        head = gate.archive_head()
        native_templates = dict(self.rpc.templates)
        with self.assertRaises(AdmissionRefused) as failure:
            gate.authorize(block.serialize(), snapshot.serialize())
        self.assertIn("admission-deadline-margin", failure.exception.decision.reasons)
        self.assertEqual(gate.archive_head(), head)
        self.assertEqual(self.rpc.templates, native_templates)  # Overlay did not admit the rejected job.
        for proof in fresh:
            self.assert_no_receipt(proof)
        for kind, identity in ((TEMPLATE, template_id(block)), (SNAPSHOT, snapshot.hash_hex)):
            with self.assertRaises(KeyError):
                gate._read(kind, identity)

    def test_external_fitting_batch_acknowledges_every_offer_atomically(self):
        gate = self.open_gate()
        initial_state = gate.admission_status()
        proofs = (self.proof(), self.proof())
        block, snapshot = self.external_job(proofs)
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(gate.ready_for_dispatch(authorization))
        self.assertEqual(gate.archive_head()["receipt_revision"], 2)
        for proof in proofs:
            self.assertEqual(gate._read(PROOF, f"{proof.proof_id:064x}"), proof.serialize())
        current = gate.admission_status()
        self.assertEqual((current.receipt_revision, current.eligible_count), (2, 2))
        self.assertNotEqual(current.receipt_revision, initial_state.receipt_revision)

    def test_empty_jobs_cannot_bypass_a_retained_prefix_that_cannot_fit(self):
        gate = self.open_gate()
        proof = self.proof()
        gate.receive(proof)
        empty_block, empty_snapshot = variable_fixture(ntime=1700000400)
        head = gate.archive_head()
        # Inject resource pressure: the empty job's future origin fits, while
        # the retained proof's origin plus that reservation cannot fit. This
        # models a backlog already present when capacity becomes unavailable.
        with patch("hash_gate_batch.MAX_ORIGIN_CHECKS", 1):
            before = len(self.rpc.calls)
            signer = Mock()
            with self.assertRaises(AdmissionRefused):
                gate.make_native(sign_owner=signer)
            signer.assert_not_called()
            self.assertFalse(any(name == "preparesharepoolhashjob" for name, _ in self.rpc.calls[before:]))
            with self.assertRaises(AdmissionRefused):
                gate.authorize(empty_block.serialize(), empty_snapshot.serialize())
        self.assertEqual(gate.archive_head(), head)
        self.assertEqual(gate._read(PROOF, f"{proof.proof_id:064x}"), proof.serialize())
        with self.assertRaises(KeyError):
            gate._read(TEMPLATE, template_id(empty_block))

    def test_last_chance_nonempty_prefix_can_still_be_authorized_and_mined(self):
        gate = self.open_gate()
        proof = self.proof()
        gate.receive(proof)
        for _ in range(3):
            self.advance_empty()
        self.assertEqual(gate.admission_status().mode, "DRAIN")
        block, snapshot = self.external_job((proof,))
        external = gate.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(gate.ready_for_dispatch(external))
        local = gate.prepare_native_authorization(
            sign_owner=lambda value: sign_schnorr(SECRET, value.owner_message))
        self.assertTrue(gate.ready_for_dispatch(local))
        self.assertEqual(gate.archive_head()["receipt_revision"], 1)

    def test_derived_parent_certificates_are_reserved_without_wire_evidence(self):
        gate = self.open_gate()
        proof = self.proof()
        gate.receive(proof)
        block, snapshot = self.external_job((proof,))
        gate.authorize(block.serialize(), snapshot.serialize())
        self.rpc.publish(block, snapshot)
        self.parent = snapshot
        status = gate.admission_status()
        self.assertEqual(status.eligible_count, 0)
        batch = gate._batch(self.rpc.height, self.rpc.tip,
                           gate._parent_snapshot(self.rpc.height, self.rpc.tip, {}), staged={})
        certificates = batch["snapshot"].certificates
        actual = len(compact_size(len(certificates))) + sum(len(cert.serialize()) for cert in certificates)
        self.assertEqual(len(certificates), 1)
        self.assertEqual(batch["resources"]["historical_certificate_bytes"], 100)
        self.assertEqual(batch["resources"]["certificate_bytes"], actual)
        accountant = gate._admission_state.accountant
        self.assertEqual(accountant.resources.certificate_bytes, 109)
        self.assertGreaterEqual(accountant.resources.certificate_bytes, actual)

    def test_post_ack_optional_cache_failure_cannot_revoke_durable_receipt(self):
        gate = self.open_gate()
        first, second = self.proof(), self.proof()
        gate.receive(first)
        accountant = gate._admission_state.accountant
        self.assertIsNotNone(accountant)
        with patch.object(accountant, "commit", side_effect=MemoryError("optional metadata fault")):
            self.assertTrue(gate.receive(second))
        self.assertIsNone(gate._admission_state)
        self.assertEqual(gate.archive_head()["receipt_revision"], 2)
        self.assertEqual(gate._read(PROOF, f"{second.proof_id:064x}"), second.serialize())
        self.assertFalse(gate.receive(second))
        self.assertEqual(gate.admission_status().eligible_count, 2)

    def test_fast_preview_tip_race_cannot_commit_a_receipt(self):
        gate = self.open_gate()
        first, second = self.proof(), self.proof()
        gate.receive(first)
        accountant = gate._admission_state.accountant
        preview = accountant.preview_delta
        def race(*args, **kwargs):
            result = preview(*args, **kwargs)
            self.rpc.tip = "11" * 32
            return result
        head = gate.archive_head()
        with patch.object(accountant, "preview_delta", side_effect=race):
            with self.assertRaisesRegex(ValueError, "tip changed"):
                gate.receive(second)
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(second)

    def test_warm_resource_accounting_never_hides_missing_origin_data(self):
        gate = self.open_gate()
        gate.receive(self.proof())
        offered = self.proof()
        read = gate._read
        def unavailable(kind, identity):
            if kind == TEMPLATE and identity == template_id(self.origin):
                raise ValueError("cold archive data is unavailable")
            return read(kind, identity)
        head = gate.archive_head()
        with patch.object(gate, "_read", side_effect=unavailable):
            with self.assertRaisesRegex(ValueError, "cold archive data is unavailable"):
                gate.receive(offered)
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(offered)

    def test_warm_receipts_and_evidence_only_registrations_reuse_only_resource_metadata(self):
        gate = self.open_gate()
        proofs = tuple(self.proof() for _ in range(5))
        before = len(self.rpc.calls)
        with patch.object(gate, "_batch", wraps=gate._batch) as batches:
            for proof in proofs:
                self.assertTrue(gate.receive(proof))
            self.assertEqual(batches.call_count, 1)
            accountant = gate._admission_state.accountant
            other, opening = variable_fixture(ntime=1700000500)
            revision = gate.archive_head()["receipt_revision"]
            gate.register_snapshot(opening.serialize())
            gate.register_template(other.serialize())
            # New immutable evidence cannot change the already accounted
            # receipts. The new proof still brings its own fresh provenance.
            self.assertEqual(gate.archive_head()["receipt_revision"], revision)
            self.assertIs(gate._admission_state.accountant, accountant)
            self.assertTrue(gate.receive(solve_share(other, opening)))
            self.assertEqual(batches.call_count, 1)
        self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in self.rpc.calls[before:]), 6)
        usage = gate.batch_status()["resources"]
        self.assertGreaterEqual(accountant.resources.snapshot_bytes, usage["reserved_snapshot_bytes"])
        self.assertGreaterEqual(accountant.resources.dependency_bytes, usage["reserved_dependency_bytes"])
        self.assertEqual((accountant.proof_count, accountant.stats()["templates"]), (6, 2))

    def payout_capacity(self, value):
        rpc = self.rpc
        def bounded(method, *args):
            result = rpc(method, *args)
            if method == "getsharepoolhashtidesbudget":
                result["max_output_bytes"] = value() if callable(value) else value
            return result
        self.gate.rpc = bounded

    def test_native_output_capacity_refuses_before_ack_while_snapshot_fits(self):
        gate = self.open_gate()
        self.payout_capacity(61)  # Historical31 + current31 no longer fits.
        proof = self.proof()
        head = gate.archive_head()
        with self.assertRaises(AdmissionRefused):
            gate.receive(proof)
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(proof)
        batch = gate._batch(0, self.rpc.tip, None, staged={}, offered=(proof,))
        self.assertEqual(batch["limit_reason"], "native coinbase payout reservation budget")
        self.assertEqual(batch["resources"]["native_payout_capacity_bytes"], 61)
        self.assertLess(batch["resources"]["reserved_snapshot_bytes"], gate.snapshot_budget)
        self.assertEqual(batch["snapshot"].shares, ())

    def test_native_output_capacity_conservative_overflow_uses_exact_fallback(self):
        gate = self.open_gate()
        self.payout_capacity(62)
        gate.admission_status()
        with patch.object(gate, "_batch", wraps=gate._batch) as batches:
            self.assertTrue(gate.receive(self.proof()))
            self.assertEqual(batches.call_count, 1)  # Warm estimate70; exact62.
        state = gate._admission_state
        self.assertEqual(state.quote.native_payout_capacity_bytes, 62)
        self.assertEqual(state.quote.resources.recipient_bytes, 62)
        self.assertEqual(state.accountant.resources.recipient_bytes, 70)

    def test_native_output_capacity_is_carried_incrementally_and_refreshed_on_tip(self):
        gate = self.open_gate()
        self.payout_capacity(lambda: 100 if self.rpc.height == 0 else 61)
        gate.receive(self.proof())
        with patch.object(gate, "_batch", wraps=gate._batch) as batches:
            gate.receive(self.proof())
            self.assertEqual(batches.call_count, 0)
        self.assertEqual(gate._admission_state.quote.native_payout_capacity_bytes, 100)
        self.advance_empty()
        offered = self.proof()
        head = gate.archive_head()
        with self.assertRaises(AdmissionRefused):
            gate.receive(offered)
        self.assertEqual(gate._admission_state.quote.native_payout_capacity_bytes, 61)
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(offered)

    def test_missing_or_malformed_native_output_ceiling_fails_closed_in_v8(self):
        gate = self.open_gate()
        proof = self.proof()
        rpc = self.rpc
        head = gate.archive_head()
        for value in (None, True, 0, -1, 999613, "999612"):
            def broken(method, *args):
                result = rpc(method, *args)
                if method == "getsharepoolhashtidesbudget":
                    if value is None:
                        result.pop("max_output_bytes")
                    else:
                        result["max_output_bytes"] = value
                return result
            gate.rpc = broken
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "payout reservation failed"):
                gate.receive(proof)
            self.assertEqual(gate.archive_head(), head)
            self.assert_no_receipt(proof)

    def oversized_history(self):
        rpc = self.rpc
        def historical(method, *args):
            result = rpc(method, *args)
            if method == "getsharepoolhashtidesbudget":
                result.update(output_count=2, output_bytes=62, max_output_bytes=61)
            return result
        self.gate.rpc = historical

    def test_empty_history_capacity_is_local_pressure_without_ack_or_invalid_count(self):
        from hash_stratum import VardiffStratumService

        gate = self.open_gate()
        self.oversized_history()
        proof = self.proof()
        head = gate.archive_head()
        with self.assertRaises(AdmissionRefused) as failure:
            gate.receive(proof)
        error = failure.exception
        self.assertIsInstance(error.__cause__, EmptyBatchCapacity)
        self.assertEqual((error.decision.mode, error.decision.ack_allowed, error.decision.dispatch_allowed),
                         ("DRAIN", False, False))
        self.assertEqual(error.decision.reasons, ("resource-budget",))
        self.assertEqual(error.capacity_reason, "native coinbase payout reservation budget")
        self.assertEqual(error.resources["recipient_bytes"], 62)
        self.assertLess(error.resources["reserved_snapshot_bytes"], gate.snapshot_budget)
        self.assertEqual(gate.archive_head(), head)
        self.assert_no_receipt(proof)
        # Exercise the transport's actual receipt classifier without sockets.
        service = VardiffStratumService.__new__(VardiffStratumService)
        service.gate = gate
        service.stats = {"capacity_refused": 0, "rejected": 0, "acknowledged": 0, "duplicate": 0}
        accepted, refused = service._receive_share(proof)
        self.assertFalse(accepted)
        self.assertIsInstance(refused, AdmissionRefused)
        self.assertEqual((service.stats["capacity_refused"], service.stats["rejected"]), (1, 0))
        self.assertEqual(gate.archive_head(), head)

    def test_empty_history_capacity_blocks_status_preparation_and_external_job(self):
        gate = self.open_gate()
        self.oversized_history()
        head = gate.archive_head()
        with self.assertRaises(AdmissionRefused) as error:
            gate.admission_status()
        self.assertFalse(error.exception.decision.dispatch_allowed)
        signer = Mock()
        before = len(self.rpc.calls)
        with self.assertRaises(AdmissionRefused):
            gate.prepare_native_authorization(sign_owner=signer)
        signer.assert_not_called()
        self.assertFalse(any(name == "preparesharepoolhashjob" for name, _ in self.rpc.calls[before:]))
        block, snapshot = variable_fixture(ntime=1700000700)
        with self.assertRaises(AdmissionRefused):
            gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(gate.archive_head(), head)
        with self.assertRaises(KeyError):
            gate._read(TEMPLATE, template_id(block))

    def test_empty_capacity_preserves_exact_pending_count_and_oldest_height(self):
        gate = self.open_gate()
        proof = self.proof()
        gate.receive(proof)
        self.advance_empty()
        self.oversized_history()
        with self.assertRaises(AdmissionRefused) as failure:
            gate.admission_status()
        error = failure.exception
        self.assertEqual((error.decision.eligible_count, error.decision.selected_count), (1, 0))
        self.assertEqual(error.decision.additional_inclusion_heights, 2)
        self.assertEqual(error.__cause__.oldest_origin_height, 1)
        self.assertEqual(gate._read(PROOF, f"{proof.proof_id:064x}"), proof.serialize())
        self.assertEqual(gate.archive_head()["receipt_revision"], 1)

    def test_empty_capacity_translation_does_not_relabel_invalid_or_missing_data(self):
        gate = self.open_gate()
        for error in (ValueError("invalid owner authorization"), KeyError("missing native history")):
            with patch.object(gate, "_batch", side_effect=error):
                with self.assertRaises(type(error)) as failure:
                    gate.admission_status()
                self.assertIs(failure.exception, error)


if __name__ == "__main__":
    unittest.main()
