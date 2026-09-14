#!/usr/bin/env python3
"""Deterministic carry batches and exact native job construction boundaries."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_mining_gate import HashMiningGate, PROOF
from hash_gate_batch import check_graph, BatchLimit
from hash_snapshot import Snapshot, solve_share, job_hash
from native_enforcement import sign_schnorr
from native_mining_gate import REGTEST_GENESIS, parse_block, template_id
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

    def test_fitting_full_prefix_avoids_intermediate_trials(self):
        self.admit(self.proofs(2))
        counts = []
        def inspect(snapshot, **options):
            counts.append(len(snapshot.shares))
            return check_graph(snapshot, **options)
        with patch("hash_gate_batch.check_graph", side_effect=inspect):
            batch = self.gate.batch_status()
        self.assertEqual(len(batch["selected_proofs"]), 2)
        self.assertEqual(batch["deferred_count"], 0)
        self.assertEqual(counts, [0, 2])

    def test_full_trial_invalidity_is_not_hidden_by_a_smaller_prefix(self):
        self.admit(self.proofs(2))
        head = self.gate.archive_head()
        def inspect(snapshot, **options):
            if len(snapshot.shares) == 2:
                raise ValueError("corrupt origin evidence")
            return check_graph(snapshot, **options)
        with patch("hash_gate_batch.check_graph", side_effect=inspect):
            with self.assertRaisesRegex(ValueError, "corrupt origin"):
                self.gate.batch_status()
        self.assertEqual(self.gate.archive_head(), head)

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
            # The empty current job reserves one future origin/depth, while
            # the first receipt would require another. An empty snapshot fits
            # the independent 500-byte dependency budget.
            value = 500 if bound == "MAX_DEPENDENCY_BYTES" else 1
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
        for depth in range(1, 64):
            proof = solve_share(block, snapshot)
            block, snapshot = fixture(ntime=1700000100 + depth, templates=[block], shares=[proof])
            self.rpc.snapshots[snapshot.hash_hex] = snapshot.serialize().hex()
        # The standalone proof starts at depth one, so this 63-edge origin
        # fits. A new mining job reserves another edge and must defer it.
        resources = check_graph(snapshot,
            lookup=lambda identity: Snapshot.deserialize(bytes.fromhex(self.rpc.snapshots[f"{identity:064x}"])),
            parent_snapshot=lambda *unused: None)
        self.assertEqual(resources["origins"], 63)
        self.gate.register_snapshot(snapshot.serialize())
        self.gate.register_template(block.serialize())
        receipt = solve_share(block, snapshot)
        self.assertTrue(self.gate.receive(receipt))
        batch = self.gate.batch_status()
        self.assertEqual(batch["selected_proofs"], ())
        self.assertEqual(batch["deferred_count"], 1)
        self.assertEqual(batch["limit_reason"], "dependency depth")
        self.assertEqual(self.gate._read(PROOF, f"{receipt.proof_id:064x}"), receipt.serialize())

    def test_dense_dag_loads_each_snapshot_once_and_preserves_intrinsic_depth(self):
        blocks, proofs, snapshots = [], [], {}
        for index in range(50):
            block, snapshot = fixture(ntime=1700000001 + index, templates=blocks, shares=proofs)
            snapshots[snapshot.hash] = snapshot
            blocks.append(block)
            proofs.append(solve_share(block, snapshot))
        lookups, captured = [], []

        def lookup(identity):
            lookups.append(identity)
            return snapshots[identity]

        result = check_graph(snapshot, lookup=lookup, parent_snapshot=lambda *unused: None,
                             on_snapshot=lambda identity, raw: captured.append((identity, raw)))
        self.assertEqual(result["origins"], 49)
        self.assertEqual(len(lookups), 49)
        self.assertEqual(len(set(lookups)), 49)
        self.assertEqual(len(captured), 50)
        # A smaller configured depth catches a reused subtree even if it was
        # first visited through a short path. Merely caching 'visited' is wrong.
        with patch("hash_gate_batch.MAX_DEPENDENCY_DEPTH", 48), self.assertRaises(BatchLimit):
            check_graph(snapshot, lookup=lookup, parent_snapshot=lambda *unused: None)
        with patch("hash_gate_batch.MAX_DEPENDENCY_DEPTH", 49):
            self.assertEqual(check_graph(snapshot, lookup=lookup,
                parent_snapshot=lambda *unused: None)["origins"], 49)

    def test_cached_subtree_still_rejects_a_later_longer_path_and_reserves_new_jobs(self):
        snapshots = {}
        shared, opening = fixture()
        snapshots[opening.hash] = opening
        for index in range(2):
            shared, opening = fixture(ntime=1700000100 + index, templates=[shared],
                                      shares=[solve_share(shared, opening)])
            snapshots[opening.hash] = opening
        shared_proof = solve_share(shared, opening)
        shared_order = int(template_id(shared), 16).to_bytes(32, "little")
        for offset in range(100):
            wrapper, wrapper_snapshot = fixture(ntime=1700000200 + offset,
                templates=[shared], shares=[shared_proof])
            if shared_order < int(template_id(wrapper), 16).to_bytes(32, "little"):
                break
        else:
            self.fail("could not construct the deterministic short-path-first fixture")
        snapshots[wrapper_snapshot.hash] = wrapper_snapshot
        unused, root = fixture(ntime=1700000400, templates=[shared, wrapper],
            shares=[shared_proof, solve_share(wrapper, wrapper_snapshot)])
        self.assertEqual(root.templates[0].template_id, int(template_id(shared), 16))
        options = dict(lookup=lambda identity: snapshots[identity], parent_snapshot=lambda *unused: None)
        with patch("hash_gate_batch.MAX_DEPENDENCY_DEPTH", 3), self.assertRaises(BatchLimit):
            check_graph(root, **options)
        with patch("hash_gate_batch.MAX_DEPENDENCY_DEPTH", 4):
            self.assertEqual(check_graph(root, **options)["origins"], 4)
            with self.assertRaises(BatchLimit):
                check_graph(root, mining_job=True, **options)
        # Historical origin accounting remains valid at its old boundary;
        # a new job must leave a slot for validating its own future origin.
        with patch("hash_gate_batch.MAX_ORIGIN_CHECKS", 4):
            self.assertEqual(check_graph(root, **options)["origins"], 4)
            with self.assertRaises(BatchLimit):
                check_graph(root, mining_job=True, **options)

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
