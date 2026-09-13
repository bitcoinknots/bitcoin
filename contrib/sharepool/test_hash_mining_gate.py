#!/usr/bin/env python3
"""Deterministic v4 gate durability/policy tests with a native RPC double."""
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from hash_snapshot import Snapshot, RULES_HASH, MAX_SNAPSHOT_BYTES, parse_share, solve_share
from hash_mining_gate import HashMiningGate, TemplateOmission, SNAPSHOT, PROOF, TEMPLATE
from native_mining_gate import REGTEST_GENESIS, parse_block, JobOmission, template_id
from test_framework.messages import CBlockHeader
from test_hash_snapshot import fixture, SECRET, SCRIPT


class FakeRPC:
    def __init__(self):
        self.snapshots, self.hashes = {}, {0: REGTEST_GENESIS}
        self.tip, self.height, self.chain = REGTEST_GENESIS, 0, "regtest"
        self.template_error, self.share_error, self.bad_response, self.race = None, None, False, False
        self.calls, self.gate = [], None
        self.headers = {}

    def publish(self, block, snapshot):
        block.solve()
        self.snapshots[snapshot.hash_hex] = snapshot.serialize().hex()
        self.headers[block.hash] = CBlockHeader(block).serialize().hex()
        self.height, self.tip = block.m_height, block.hash
        self.hashes[self.height] = self.tip

    def __call__(self, method, *args):
        self.calls.append((method, args))
        if self.gate is not None and self.gate.db is not None:
            assert not self.gate.db.in_transaction, "RPC executed inside write transaction"
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.height}
        if method == "getblockhash":
            return self.hashes[args[0]]
        if method == "getbestblockhash":
            return self.tip
        if method == "getblockheader":
            return self.headers[args[0]]
        if method == "getsharepoolhashstatus":
            return {"mode": "hash-only-v4", "rules": f"{RULES_HASH:064x}", "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
                    "inventory": list(self.snapshots)}
        if method == "submitsharepoolhashsnapshot":
            snapshot = Snapshot.deserialize(bytes.fromhex(args[0]))
            present = snapshot.hash_hex in self.snapshots
            self.snapshots[snapshot.hash_hex] = args[0]
            return {"hash": snapshot.hash_hex, "status": "present" if present else "stored", "missing": []}
        if method == "getsharepoolhashsnapshot":
            return {"hash": args[0], "data": self.snapshots[args[0]]}
        if method == "validatesharepoolhashtemplate":
            if self.template_error:
                raise ValueError(self.template_error)
            block = parse_block(bytes.fromhex(args[0]))
            overlay = Snapshot.deserialize(bytes.fromhex(args[1])) if len(args) > 1 and args[1] is not None else None
            if overlay is not None:
                if overlay.hash != block.m_mm_rhs:
                    raise ValueError("snapshot commitment mismatch")
                if self.share_error and overlay.shares:
                    raise ValueError(self.share_error)
            elif f"{block.m_mm_rhs:064x}" not in self.snapshots:
                raise ValueError("sharepool-hash-data-missing")
            result = {"valid": True, "native_tip": self.tip, "native_parent": f"{block.hashPrevBlock:064x}",
                      "origin_height": block.m_height, "commitment": f"{block.m_mm_rhs:064x}"}
            if self.race:
                self.tip = "11" * 32
            return result
        if method == "validatesharepoolhashshare":
            if self.share_error:
                raise ValueError(self.share_error)
            share = parse_share(bytes.fromhex(args[0]))
            return {"valid": True, "native_tip": self.tip, "proof_id": "11" * 32 if self.bad_response else f"{share.proof_id:064x}",
                    "payout_script": share.envelope.payout_script.hex(), "pool": f"{share.envelope.pool:064x}",
                    "origin_height": share.envelope.height, "native_parent": f"{share.envelope.native_parent:064x}"}
        raise AssertionError(method)


class HashGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "gate.sqlite"
        self.origin, self.opening = fixture()
        self.rpc = FakeRPC()
        self.gate = self.open_gate()
        self.addCleanup(lambda: self.gate.close() if self.gate else None)
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())

    def open_gate(self, **extra):
        gate = HashMiningGate(self.path, rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key,
                             payout_script=SCRIPT, **extra)
        self.rpc.gate = gate
        return gate

    def reopen(self, **extra):
        self.gate.close()
        self.gate = self.open_gate(**extra)

    def job(self, shares=(), templates=None):
        return fixture(ntime=1700000002, shares=shares, templates=([self.origin] if shares else []) if templates is None else templates)

    def assert_not_admitted(self, block, snapshot, proofs=()):
        for kind, identity in ((SNAPSHOT, snapshot.hash_hex), (TEMPLATE, template_id(block))):
            with self.assertRaises(KeyError):
                self.gate._read(kind, identity)
        for proof in proofs:
            with self.assertRaises(KeyError):
                self.gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_one_hundred_acknowledgments_restart_and_frozen_authorization(self):
        proofs, nonce = [], 0
        for _ in range(100):
            proof = solve_share(self.origin, self.opening, start_nonce=nonce)
            nonce = proof.header.nNonce + 1
            self.assertTrue(self.gate.receive(proof))
            proofs.append(proof)
        head = self.gate.archive_head()
        self.assertEqual(head["receipt_revision"], 100)
        self.reopen()
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(len(self.gate.eligible_shares()), 100)
        self.assertFalse(self.gate.receive(proofs[0]))
        block, snapshot = self.job(proofs)
        authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(authorization.receipt_sequence, 100)
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        newer = solve_share(self.origin, self.opening, start_nonce=nonce)
        self.gate.receive(newer)
        self.assertFalse(self.gate.ready_for_dispatch(authorization))
        solved = solve_share(block, snapshot)
        self.assertEqual(parse_block(authorization.block_for_header(solved.header_bytes)).m_mm_rhs, snapshot.hash)
        changed = solved.header
        changed.m_mm_rhs ^= 1
        with self.assertRaises(ValueError):
            authorization.block_for_header(changed.serialize())

    def test_omission_survives_restart(self):
        proof = solve_share(self.origin, self.opening)
        self.gate.receive(proof)
        block, snapshot = self.job()
        head = self.gate.archive_head()
        with self.assertRaises(JobOmission) as failure:
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(failure.exception.proof_ids, (f"{proof.proof_id:064x}",))
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot)
        self.reopen()
        with self.assertRaises(JobOmission):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)

    def test_omitted_work_cannot_admit_offered_proofs_or_refresh_frozen_job(self):
        acknowledged = solve_share(self.origin, self.opening)
        self.gate.receive(acknowledged)
        accepted, accepted_snapshot = self.job(shares=[acknowledged])
        frozen = self.gate.authorize(accepted.serialize(), accepted_snapshot.serialize())
        offered, opening = fixture(ntime=1700000010, secret=(2).to_bytes(32, "big"))
        # Peers have the dependency, but this gate has not admitted it.
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proof = solve_share(offered, opening)
        block, snapshot = fixture(ntime=1700000011, templates=[self.origin, accepted, offered], shares=[proof])
        head = self.gate.archive_head()
        with self.assertRaises(JobOmission):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot, [proof])
        self.assert_not_admitted(offered, opening)
        self.assertTrue(self.gate.ready_for_dispatch(frozen))
        self.assertEqual([share.proof_id for share in self.gate.eligible_shares()], [acknowledged.proof_id])
        self.reopen()
        self.assertEqual(self.gate.archive_head(), head)
        self.assertFalse(self.gate.ready_for_dispatch(frozen))
        refreshed = self.gate.authorize(accepted.serialize(), accepted_snapshot.serialize())
        self.assertTrue(self.gate.ready_for_dispatch(refreshed))

    def test_template_omission_cannot_admit_offered_evidence(self):
        offered, opening = fixture(ntime=1700000010, secret=(2).to_bytes(32, "big"))
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proof = solve_share(self.origin, self.opening)
        block, snapshot = self.job(shares=[proof], templates=[offered])
        head = self.gate.archive_head()
        with self.assertRaises(TemplateOmission):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot, [proof])
        self.assert_not_admitted(offered, opening)

    def test_bad_job_policy_does_not_admit_snapshot(self):
        block, snapshot = fixture(pool=4, templates=[self.origin])
        head = self.gate.archive_head()
        with self.assertRaisesRegex(ValueError, "policy"):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot)

    def test_failed_native_job_or_proof_does_not_admit_evidence(self):
        offered, opening = fixture(ntime=1700000010, secret=(2).to_bytes(32, "big"))
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proof = solve_share(offered, opening)
        block, snapshot = self.job(shares=[proof], templates=[self.origin, offered])
        head = self.gate.archive_head()
        native_snapshots = dict(self.rpc.snapshots)
        for failure in ("template_error", "share_error"):
            with self.subTest(failure=failure):
                setattr(self.rpc, failure, "native validation refused")
                with self.assertRaisesRegex(ValueError, "native validation refused"):
                    self.gate.authorize(block.serialize(), snapshot.serialize())
                setattr(self.rpc, failure, None)
                self.assertEqual(self.gate.archive_head(), head)
                self.assert_not_admitted(block, snapshot, [proof])
                self.assert_not_admitted(offered, opening)
                self.assertEqual(self.rpc.snapshots, native_snapshots)

    def test_authorization_admits_complete_offer_in_one_commit(self):
        offered, opening = fixture(ntime=1700000010, secret=(2).to_bytes(32, "big"))
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proof = solve_share(offered, opening)
        block, snapshot = self.job(shares=[proof], templates=[offered])
        with patch.object(self.gate, "_persist", wraps=self.gate._persist) as persist:
            authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(persist.call_count, 1)
        self.assertEqual(authorization.receipt_sequence, 1)
        self.assertNotIn(snapshot.hash_hex, self.rpc.snapshots)
        head = self.gate.archive_head()
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        self.reopen()
        self.assertEqual(self.gate.archive_head(), head)
        self.assertFalse(self.gate.receive(proof))
        self.assertEqual(self.gate.snapshot_bytes(opening.hash_hex), opening.serialize())
        # The just-issued job is excluded from its own coverage on retry.
        self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)

    def test_failed_job_does_not_admit_rpc_fetched_candidate_or_parent(self):
        parent, parent_snapshot = self.job()
        self.rpc.publish(parent, parent_snapshot)
        block, snapshot = fixture(height=2, native_parent=int(self.rpc.tip, 16),
            ntime=1700000010, parent_snapshot=parent_snapshot)
        self.rpc.snapshots[snapshot.hash_hex] = snapshot.serialize().hex()
        head = self.gate.archive_head()
        self.rpc.template_error = "native validation refused"
        with self.assertRaisesRegex(ValueError, "native validation refused"):
            self.gate.authorize(block.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot)
        self.assert_not_admitted(parent, parent_snapshot)
        self.rpc.template_error = None
        self.gate.authorize(block.serialize())
        self.assertEqual(self.gate.snapshot_bytes(parent_snapshot.hash_hex), parent_snapshot.serialize())

    def test_authorization_quota_failure_rolls_back_whole_offer(self):
        offered, opening = fixture(ntime=1700000010, secret=(2).to_bytes(32, "big"))
        self.rpc.snapshots[opening.hash_hex] = opening.serialize().hex()
        proof = solve_share(offered, opening)
        acknowledged = solve_share(self.origin, self.opening)
        self.gate.receive(acknowledged)
        block, snapshot = self.job(shares=[acknowledged, proof], templates=[self.origin, offered])
        head = self.gate.archive_head()
        self.reopen(quota=max(4096, head["bytes"] + 1))
        with self.assertRaisesRegex(ValueError, "quota"):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot, [proof])
        self.assert_not_admitted(offered, opening)
        self.reopen()
        self.assertEqual(self.gate.archive_head(), head)
        self.gate.authorize(block.serialize(), snapshot.serialize())

    def test_unworked_inventory_is_retained_without_forcing_refresh_dependencies(self):
        other, opening = fixture(ntime=1700000003)
        self.gate.register_snapshot(opening.serialize())
        self.gate.register_template(other.serialize())
        block, snapshot = self.job()
        self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(snapshot.templates, ())
        self.assertEqual(len(self.gate.active_templates()), 3)

    def test_successful_storage_never_authorizes_missing_dependency(self):
        block, snapshot = self.job()
        self.gate.register_snapshot(snapshot.serialize())
        self.rpc.template_error = "sharepool-hash-data-missing"
        with self.assertRaisesRegex(ValueError, "data-missing"):
            self.gate.authorize(block.serialize())
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 0)

    def test_invalid_proof_and_wrong_response_never_acknowledge(self):
        proof = solve_share(self.origin, self.opening)
        head = self.gate.archive_head()
        self.rpc.share_error = "bad proof"
        with self.assertRaises(ValueError):
            self.gate.receive(proof)
        self.rpc.share_error, self.rpc.bad_response = None, True
        with self.assertRaises(ValueError):
            self.gate.receive(proof)
        self.assertEqual(self.gate.archive_head(), head)

    def test_proof_must_retain_exact_origin_job_signature(self):
        proof = solve_share(self.origin, self.opening)
        head = self.gate.archive_head()
        changed = replace(proof, owner_signature=b"x" * 64)
        self.assertEqual(changed.proof_id, proof.proof_id)
        with self.assertRaisesRegex(ValueError, "full origin snapshot"):
            self.gate.receive(changed)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertTrue(self.gate.receive(proof))

    def test_native_tip_race_refuses_authorization(self):
        block, snapshot = self.job()
        head = self.gate.archive_head()
        self.rpc.race = True
        with self.assertRaisesRegex(ValueError, "tip changed"):
            self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot)

    def test_final_tip_race_does_not_admit_previously_validated_evidence(self):
        block, snapshot = self.job()
        head = self.gate.archive_head()
        # The full candidate check, then the final precommit tip check.
        with patch.object(self.gate, "_stable", side_effect=[None, ValueError("native tip changed")]):
            with self.assertRaisesRegex(ValueError, "tip changed"):
                self.gate.authorize(block.serialize(), snapshot.serialize())
        self.assertEqual(self.gate.archive_head(), head)
        self.assert_not_admitted(block, snapshot)

    def test_seal_failure_returns_no_ack_and_restart_preserves_commit(self):
        proof = solve_share(self.origin, self.opening)
        with patch("hash_mining_gate.hash_gate_archive.write_head", side_effect=OSError("simulated fsync failure")):
            with self.assertRaises(OSError):
                self.gate.receive(proof)
        with self.assertRaisesRegex(ValueError, "restart"):
            self.gate.receive(proof)
        self.reopen()
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)
        self.assertFalse(self.gate.receive(proof))

    def test_quota_failure_rolls_back_then_larger_quota_retries_once(self):
        current = self.gate.archive_head()["bytes"]
        self.reopen(quota=max(4096, current + 1))
        nonce = 0
        while True:
            proof = solve_share(self.origin, self.opening, start_nonce=nonce)
            nonce = proof.header.nNonce + 1
            before = self.gate.archive_head()
            try:
                self.gate.receive(proof)
            except ValueError as error:
                self.assertIn("quota", str(error))
                break
        self.assertEqual(self.gate.archive_head(), before)
        self.reopen()
        self.assertTrue(self.gate.receive(proof))
        self.assertEqual(self.gate.archive_head()["receipt_revision"], before["receipt_revision"] + 1)

    def test_database_rollback_cannot_match_newer_protected_head(self):
        backup = Path(self.directory.name) / "old.sqlite"
        with sqlite3.connect(backup) as db:
            self.gate.db.backup(db)
        self.gate.receive(solve_share(self.origin, self.opening))
        self.gate.close()
        backup.replace(self.path)
        with self.assertRaisesRegex(ValueError, "high-water"):
            self.open_gate()

    def test_corrupt_acknowledged_bytes_fail_restart(self):
        self.gate.receive(solve_share(self.origin, self.opening))
        with self.gate.db:
            self.gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=2")
        self.gate.close()
        with self.assertRaises(ValueError):
            self.open_gate()

    def test_missing_head_and_second_owner_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "owning process"):
            self.open_gate()
        self.gate.close()
        self.gate.head_path.unlink()
        with self.assertRaises(ValueError):
            self.open_gate()

    def test_network_and_public_policy_are_bound(self):
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "another profile or miner"):
            HashMiningGate(self.path, rpc=self.rpc, pool=4, public_key=self.opening.envelope.public_key, payout_script=SCRIPT)
        self.rpc.chain = "main"
        with self.assertRaisesRegex(ValueError, "regtest"):
            self.open_gate()

    def test_payment_rollback_and_deep_expiry_do_not_delete_acknowledged_work(self):
        proof = solve_share(self.origin, self.opening)
        self.gate.receive(proof)
        block, snapshot = self.job(shares=(proof,))
        self.rpc.publish(block, snapshot)
        self.assertEqual(self.gate.eligible_shares(), ())
        for height in range(2, 163):
            block, snapshot = fixture(height=height, native_parent=int(self.rpc.tip, 16),
                ntime=1700000001 + height, parent_snapshot=snapshot)
            self.rpc.publish(block, snapshot)
        self.assertEqual(self.gate.eligible_shares(), ())
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.reopen()
        self.assertEqual([share.proof_id for share in self.gate.eligible_shares()], [proof.proof_id])
        block, snapshot = self.job()
        with self.assertRaises(JobOmission):
            self.gate.authorize(block.serialize(), snapshot.serialize())

    def test_historical_origin_is_revalidated_before_new_ack(self):
        proof = solve_share(self.origin, self.opening)
        self.rpc.template_error = "sharepool-hash-data-missing"
        with self.assertRaisesRegex(ValueError, "data-missing"):
            self.gate.receive(proof)
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 0)

    def test_oversized_journal_metadata_is_refused_before_body_materialization(self):
        with self.gate.db:
            self.gate.db.execute("UPDATE journal SET digest=? WHERE kind=1", ("a" * 8192,))
        with self.assertRaisesRegex(ValueError, "metadata exceeds"):
            self.gate.active_templates()
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "scalar metadata"):
            self.open_gate()

    def test_oversized_configuration_is_refused_before_materialization(self):
        with self.gate.db:
            self.gate.db.execute("UPDATE config SET value=zeroblob(8192)")
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "configuration exceeds"):
            self.open_gate()

    def test_oversized_checkpoint_metadata_is_refused_before_materialization(self):
        with self.gate.db:
            self.gate.db.execute("UPDATE journal_meta SET value=?", ("a" * 8192,))
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "checkpoint metadata exceeds"):
            self.open_gate()


if __name__ == "__main__":
    unittest.main()
