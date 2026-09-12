#!/usr/bin/env python3
"""Deterministic carry batches and exact native job construction boundaries."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_mining_gate import HashMiningGate, PROOF
from hash_gate_batch import check_graph
from hash_snapshot import Snapshot, solve_share, job_hash
from native_enforcement import sign_schnorr
from native_mining_gate import REGTEST_GENESIS, parse_block
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT, SECRET


def sign(snapshot):
    return sign_schnorr(SECRET, snapshot.owner_message)


class BuilderRPC(FakeRPC):
    """Only adapter tests: actual mempool/fee validation is native functional coverage."""
    prepare_change = None
    finalize_change = None

    def result(self, block, snapshot):
        return {"template": block.serialize().hex(), "snapshot": snapshot.serialize().hex(),
                "commitment": snapshot.hash_hex, "job_commitment": f"{job_hash(block):064x}",
                "native_parent": f"{block.hashPrevBlock:064x}", "height": block.m_height,
                "reward": sum(output.nValue for output in snapshot.payouts)}

    def __call__(self, method, *args):
        if method == "preparesharepoolhashjob":
            self.calls.append((method, args))
            proposal = Snapshot.deserialize(bytes.fromhex(args[0]))
            selected = {share.proof_id for share in proposal.shares}
            block, signed = fixture(native_parent=int(self.tip, 16), height=self.height + 1,
                templates=proposal.templates, shares=proposal.shares,
                parent_state=tuple(entry for entry in proposal.post_state if entry.proof_id not in selected),
                fees=1234)
            unsigned = replace(signed, owner_signature=bytes(64))
            block.m_mm_rhs = unsigned.hash
            result = self.result(block, unsigned)
            result.update(signing_payload=unsigned.signing_payload.hex(), signing_hash=unsigned.owner_message[::-1].hex())
            return self.prepare_change(result) if self.prepare_change else result
        if method == "finalizesharepoolhashjob":
            self.calls.append((method, args))
            block, snapshot = parse_block(bytes.fromhex(args[0])), Snapshot.deserialize(bytes.fromhex(args[1]))
            block.m_mm_rhs = snapshot.hash
            result = self.result(block, snapshot)
            return self.finalize_change(result) if self.finalize_change else result
        return super().__call__(method, *args)


class HashGateBatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-batches-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rpc = BuilderRPC()
        self.origin, self.opening = fixture()
        self.options = dict(rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key,
                            payout_script=SCRIPT, snapshot_budget=2000)
        self.gate = self.open_gate("gate.sqlite")
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())

    def open_gate(self, name):
        gate = HashMiningGate(self.directory / name, **self.options)
        self.addCleanup(gate.close)
        return gate

    def proofs(self, count):
        result, nonce = [], 0
        for _ in range(count):
            share = solve_share(self.origin, self.opening, start_nonce=nonce)
            nonce = share.header.nNonce + 1
            result.append(share)
        return result

    def admit(self, proofs):
        for proof in proofs:
            self.assertTrue(self.gate.receive(proof))

    def test_prefix_is_independent_of_arrival_order_and_survives_restart(self):
        proofs = self.proofs(10)
        self.admit(proofs)
        first = self.gate.batch_status()
        expected = tuple(f"{proof.proof_id:064x}" for proof in sorted(proofs, key=lambda proof: proof.proof_id)[:2])
        self.assertEqual(first["selected_proofs"], expected)
        self.assertEqual(first["deferred_count"], 8)
        self.assertLessEqual(first["resources"]["snapshot_bytes"], 2000)
        other = self.open_gate("other.sqlite")
        other.register_snapshot(self.opening.serialize())
        other.register_template(self.origin.serialize())
        for proof in reversed(proofs):
            other.receive(proof)
        self.assertEqual(other.batch_status()["selected_proofs"], expected)
        head = self.gate.archive_head()
        self.gate.close()
        self.gate = self.open_gate("gate.sqlite")
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.gate.batch_status(), first)
        self.assertEqual([entry["status"] for entry in self.gate.receipt_status()["receipts"]].count("deferred"), 8)

    def test_only_canonical_payment_advances_carry_and_reorg_reactivates_it(self):
        self.admit(self.proofs(6))
        first = self.gate.batch_status()["selected_proofs"]
        block, snapshot = self.gate.make(ntime=1700000002, sign_owner=sign)
        self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.batch_status()["selected_proofs"], first)
        self.rpc.publish(block, snapshot)
        second = self.gate.batch_status()["selected_proofs"]
        self.assertEqual(len(second), 2)
        self.assertFalse(set(first) & set(second))
        entries = self.gate.receipt_status()["receipts"]
        self.assertEqual({entry["proof_id"] for entry in entries if entry["status"] == "paid"}, set(first))
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.assertEqual(self.gate.batch_status()["selected_proofs"], first)
        self.assertNotIn("paid", {entry["status"] for entry in self.gate.receipt_status()["receipts"]})
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 6)

    def test_expired_unpaid_and_missing_historical_data_are_never_reported_paid(self):
        self.admit(self.proofs(1))
        previous = None
        for height in range(1, 5):
            block, previous = fixture(native_parent=int(self.rpc.tip, 16), height=height,
                ntime=1700000001 + height, parent_snapshot=previous)
            self.rpc.publish(block, previous)
        status = self.gate.receipt_status()["receipts"][0]
        self.assertEqual(status["status"], "expired_unpaid")
        self.assertFalse(status["consensus_eligible"])
        self.assertIsNone(status["settled_in"])
        self.assertEqual(self.gate.batch_status()["selected_proofs"], ())
        self.rpc.headers.pop(self.rpc.hashes[2])
        status = self.gate.receipt_status()["receipts"][0]
        self.assertEqual(status["status"], "unknown")
        self.assertIsNone(status["settled_in"])
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)

    def test_receipt_status_is_paginated_without_losing_revision_identity(self):
        self.admit(self.proofs(5))
        revisions, cursor = [], 0
        while True:
            page = self.gate.receipt_status(after_revision=cursor, limit=2)
            revisions.extend(entry["receipt_revision"] for entry in page["receipts"])
            if page["next_revision"] is None:
                break
            cursor = page["next_revision"]
        self.assertEqual(revisions, [1, 2, 3, 4, 5])
        for limit in (0, 257, True):
            with self.assertRaises(ValueError):
                self.gate.receipt_status(limit=limit)

    def test_resource_budgets_defer_acknowledged_work_without_discarding_it(self):
        self.admit(self.proofs(3))
        head = self.gate.archive_head()
        for bound in ("MAX_ORIGIN_CHECKS", "MAX_DEPENDENCY_DEPTH", "MAX_DEPENDENCY_BYTES"):
            # One origin must exceed zero origins/depth, while the empty
            # current snapshot fits a 500-byte dependency budget.
            value = 500 if bound == "MAX_DEPENDENCY_BYTES" else 0
            with self.subTest(bound=bound), patch("hash_gate_batch." + bound, value):
                batch = self.gate.batch_status()
                self.assertEqual(batch["selected_proofs"], ())
                self.assertEqual(batch["deferred_count"], 3)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(len(self.gate.eligible_shares()), 3)

    def test_many_unworked_refreshes_do_not_add_a_dependency_chain(self):
        frozen = None
        for index in range(70):
            block, snapshot = self.gate.make(ntime=1700000010 + index, sign_owner=sign)
            self.assertEqual(snapshot.templates, ())
            self.assertEqual(snapshot.shares, ())
            self.gate.authorize(block.serialize(), snapshot.serialize())
            if frozen is None:
                frozen = self.gate.authorize(block.serialize(), snapshot.serialize())
            self.assertTrue(self.gate.ready_for_dispatch(frozen))
        self.assertEqual(self.gate.batch_status()["deferred_count"], 0)

    def test_current_settlement_reserves_one_depth_above_its_acknowledged_origin(self):
        block, snapshot = self.origin, self.opening
        for depth in range(1, 65):
            proof = solve_share(block, snapshot)
            block, snapshot = fixture(ntime=1700000100 + depth, templates=[block], shares=[proof])
            self.rpc.snapshots[snapshot.hash_hex] = snapshot.serialize().hex()
        # This origin itself fits the native depth=64 graph limit. Settling its
        # work would add a 65th edge, so its valid ACK must remain deferred.
        resources = check_graph(snapshot,
            lookup=lambda identity: Snapshot.deserialize(bytes.fromhex(self.rpc.snapshots[f"{identity:064x}"])),
            parent_snapshot=lambda *unused: None)
        self.assertEqual(resources["origins"], 64)
        self.gate.register_snapshot(snapshot.serialize())
        self.gate.register_template(block.serialize())
        receipt = solve_share(block, snapshot)
        self.assertTrue(self.gate.receive(receipt))
        batch = self.gate.batch_status()
        self.assertEqual(batch["selected_proofs"], ())
        self.assertEqual(batch["deferred_count"], 1)
        self.assertEqual(batch["limit_reason"], "dependency depth")
        self.assertEqual(self.gate._read(PROOF, f"{receipt.proof_id:064x}"), receipt.serialize())

    def test_native_builder_binds_attestation_and_requires_separate_authorization(self):
        self.admit(self.proofs(4))
        head, native_inventory = self.gate.archive_head(), dict(self.rpc.snapshots)
        block, snapshot = self.gate.make_native(sign_owner=sign)
        self.assertEqual(sum(output.nValue for output in snapshot.payouts), 50 * 100_000_000 + 1234)
        self.assertEqual(len(snapshot.shares), 2)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.rpc.snapshots, native_inventory)
        authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertTrue(self.gate.ready_for_dispatch(authorization))

    def test_native_builder_rejects_changed_signing_payload_before_calling_signer(self):
        calls = []
        self.rpc.prepare_change = lambda value: dict(value, signing_payload="00")
        head = self.gate.archive_head()
        with self.assertRaisesRegex(ValueError, "signing payload"):
            self.gate.make_native(sign_owner=lambda value: calls.append(value))
        self.assertEqual(calls, [])
        self.assertEqual(self.gate.archive_head(), head)

    def test_native_builder_rejects_tip_race_and_changed_final_snapshot(self):
        head = self.gate.archive_head()
        def race(value):
            self.rpc.tip = "11" * 32
            return value
        self.rpc.prepare_change = race
        with self.assertRaisesRegex(ValueError, "tip changed"):
            self.gate.make_native(sign_owner=sign)
        self.rpc.tip, self.rpc.prepare_change = REGTEST_GENESIS, None
        def changed(value):
            snapshot = Snapshot.deserialize(bytes.fromhex(value["snapshot"]))
            snapshot = replace(snapshot, owner_signature=b"x" * 64)
            block = parse_block(bytes.fromhex(value["template"]))
            block.m_mm_rhs = snapshot.hash
            return self.rpc.result(block, snapshot)
        self.rpc.finalize_change = changed
        with self.assertRaisesRegex(ValueError, "changed the signed job"):
            self.gate.make_native(sign_owner=sign)
        self.assertEqual(self.gate.archive_head(), head)


if __name__ == "__main__":
    unittest.main()
