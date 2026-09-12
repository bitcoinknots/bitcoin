#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Miner policy/durability checks; real consensus is tested by functional nodes."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from native_enforcement import (MAX_MANIFEST, MAX_SHARE_AGE, MAX_SHARES, RULES_HASH,
                                SHARE_BITS, candidate, solve_share)
from native_mining_gate import (REGTEST_GENESIS, RETENTION_BLOCKS, JobOmission, NativeMiningGate,
                               RecoveryRequired, template_id,
                               parse_block, parse_share)
from test_framework.messages import CBlockHeader


SECRET = (1).to_bytes(32, "big")
SCRIPT = b"\x00\x14" + b"a" * 20
GENESIS = int(REGTEST_GENESIS, 16)


def fixture(shares=()):
    return candidate(genesis=GENESIS, native_parent=GENESIS, height=1, ntime=1700000001,
                     pool=3, secret=SECRET, payout_script=SCRIPT, shares=shares)


class FakeRPC:
    def __init__(self):
        self.chain, self.tip, self.height = "regtest", REGTEST_GENESIS, 0
        self.hashes = {0: REGTEST_GENESIS}
        self.proposal_error, self.share_error, self.race = None, None, False
        self.calls = []

    def advance(self, height):
        for index in range(1, height + 1):
            self.hashes.setdefault(index, hashlib.sha256(str(index).encode()).hexdigest())
        self.height, self.tip = height, self.hashes[height]

    def __call__(self, method, *args):
        self.calls.append((method, args))
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.height}
        if method == "getblockhash":
            return self.hashes.get(args[0], REGTEST_GENESIS)
        if method == "getbestblockhash":
            return self.tip
        if method == "validatesharepoolshare":
            if self.share_error:
                raise ValueError(self.share_error)
            share = parse_share(bytes.fromhex(args[0]))
            return {"valid": True, "proof_id": f"{share.proof_id:064x}",
                    "pool": f"{share.envelope.pool:064x}", "owner": share.envelope.public_key.hex(),
                    "origin_height": share.envelope.height, "payout_script": share.envelope.payout_script.hex(),
                    "share_bits": f"{SHARE_BITS:08x}"}
        if method == "validatesharepooltemplate":
            if self.proposal_error:
                raise ValueError(self.proposal_error)
            block = parse_block(bytes.fromhex(args[0]))
            if self.hashes.get(block.m_height - 1) != f"{block.hashPrevBlock:064x}":
                raise ValueError("origin parent is not an eligible active ancestor")
            return {"valid": True, "native_tip": self.tip,
                    "native_parent": f"{block.hashPrevBlock:064x}",
                    "origin_height": block.m_height, "commitment": f"{block.m_mm_rhs:064x}"}
        if method == "getblocktemplate":
            if args[0].get("mode") == "proposal":
                if self.race:
                    self.tip = "11" * 32
                return self.proposal_error
            return {"height": self.height + 1, "rules": ["!sharepool"], "sharepool": {
                "version": 1, "activation_height": 1, "genesis": REGTEST_GENESIS,
                "rules_root": f"{RULES_HASH:064x}", "share_bits": f"{SHARE_BITS:08x}",
                "max_share_age": MAX_SHARE_AGE, "max_shares": MAX_SHARES,
                "max_manifest_bytes": MAX_MANIFEST, "requires_completion": True}}
        raise AssertionError(method)


class NativeGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "gate.sqlite"
        self.block, self.manifest = fixture()
        self.rpc = FakeRPC()
        self.gate = self.open_gate()
        self.addCleanup(lambda: self.gate.close() if self.gate else None)
        self.gate.register_template(self.block.serialize())

    def open_gate(self, **overrides):
        kwargs = {"rpc": self.rpc, "pool": 3, "public_key": self.manifest.envelope.public_key,
                  "payout_script": SCRIPT}
        kwargs.update(overrides)
        return NativeMiningGate(self.path, **kwargs)

    def test_base_template_requires_explicit_completion_and_support(self):
        result = self.gate.base_template()
        self.assertTrue(result["sharepool"]["requires_completion"])
        params = self.rpc.calls[-1][1][0]
        self.assertIn("skip_validity_test", params["capabilities"])
        self.assertIn("sharepool", params["rules"])
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def test_receive_uses_native_validation_and_persists_once_across_restart(self):
        share = solve_share(self.block, self.manifest)
        self.assertTrue(self.gate.receive(share.serialize()))
        self.assertFalse(self.gate.receive(share.serialize()))
        self.gate.close()
        self.gate = self.open_gate()
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.rpc.share_error = "bad-sharepool-proof"
        with self.assertRaisesRegex(ValueError, "bad-sharepool-proof"):
            self.gate.receive(share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)

    def test_missing_known_work_rejects_job_but_not_native_block(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        with self.assertRaises(JobOmission) as omitted:
            self.gate.authorize(self.block.serialize())
        self.assertEqual(omitted.exception.proof_ids, (f"{share.proof_id:064x}",))
        full, unused = fixture((share,))
        authorization = self.gate.authorize(full.serialize())
        self.assertEqual(authorization.block_bytes, full.serialize())
        self.assertTrue(any(call[0] == "getblocktemplate" and call[1][0].get("mode") == "proposal"
                            for call in self.rpc.calls))

    def test_late_work_requests_refresh_without_rewriting_authorized_job(self):
        authorization = self.gate.authorize(self.block.serialize())
        original = authorization.block_bytes
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        self.assertTrue(self.gate.needs_refresh(authorization))
        self.assertFalse(self.gate.ready_for_dispatch(authorization))
        self.assertEqual(authorization.block_bytes, original)
        header = CBlockHeader(self.block)
        header.nNonce, header.m_nonce2, header.m_nonce3 = 13, 2, 7
        header.m_extranonce, header.m_time_offset = 91, 33
        solved = parse_block(authorization.block_for_header(header.serialize()))
        self.assertEqual(solved.m_mm_rhs, self.block.m_mm_rhs)
        self.assertEqual(solved.vtx[0].serialize(), self.block.vtx[0].serialize())
        header.m_mm_rhs ^= 1
        with self.assertRaisesRegex(ValueError, "authorized template"):
            authorization.block_for_header(header.serialize())

    def test_wrong_miner_binding_and_native_payout_failure_never_authorize(self):
        other, unused = candidate(genesis=GENESIS, native_parent=GENESIS, height=1, ntime=1700000001,
            pool=3, secret=(2).to_bytes(32, "big"), payout_script=SCRIPT)
        with self.assertRaisesRegex(ValueError, "registered key"):
            self.gate.authorize(other.serialize())
        self.rpc.proposal_error = "bad-sharepool-payouts"
        with self.assertRaisesRegex(ValueError, "bad-sharepool-payouts"):
            self.gate.authorize(self.block.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def test_tip_change_and_network_change_fail_closed(self):
        self.rpc.race = True
        with self.assertRaisesRegex(ValueError, "tip changed"):
            self.gate.authorize(self.block.serialize())
        self.rpc.chain = "main"
        with self.assertRaisesRegex(ValueError, "restricted to regtest"):
            self.gate.base_template()
        with self.assertRaisesRegex(ValueError, "restricted to regtest"):
            self.open_gate()

    def test_capacity_and_disk_failure_do_not_acknowledge_work(self):
        share = solve_share(self.block, self.manifest)
        with patch("native_mining_gate.MAX_RECEIPTS", 0):
            with self.assertRaisesRegex(ValueError, "archive is full"):
                self.gate.receive(share.serialize())
        self.gate.db.execute("CREATE TRIGGER fail_write BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'disk fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.gate.receive(share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)

    def test_store_is_bound_to_miner_and_detects_corrupt_receipt(self):
        self.gate.close()
        with self.assertRaisesRegex(ValueError, "another miner"):
            self.open_gate(pool=4)
        self.gate = self.open_gate()
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        with self.gate.db:
            self.gate.db.execute("UPDATE receipts SET proof_id=?", ("00" * 32,))
        full, unused = fixture((share,))
        with self.assertRaisesRegex(ValueError, "identity validation"):
            self.gate.authorize(full.serialize())

    def test_unknown_or_corrupt_full_origin_templates_do_not_receive_credit(self):
        other, other_manifest = fixture((solve_share(self.block, self.manifest),))
        share = solve_share(other, other_manifest)
        with self.assertRaisesRegex(ValueError, "not been validated locally"):
            self.gate.receive(share.serialize())
        self.rpc.proposal_error = "bad-txns-inputs-missingorspent"
        with self.assertRaisesRegex(ValueError, "bad-txns"):
            self.gate.register_template(other.serialize())
        self.rpc.proposal_error = None
        self.gate.register_template(other.serialize())
        with self.gate.db:
            self.gate.db.execute("UPDATE templates SET body_hash=?", ("00" * 32,))
        with self.assertRaisesRegex(ValueError, "origin template failed integrity"):
            self.gate.receive(share.serialize())

    def test_inactive_native_peer_cannot_authorize_even_if_proposal_accepts(self):
        original = self.rpc
        def inactive(method, *args):
            result = original(method, *args)
            if method == "getblocktemplate" and args[0].get("mode") != "proposal":
                result.pop("sharepool")
            return result
        self.gate.rpc = inactive
        with self.assertRaisesRegex(ValueError, "active settlement profile"):
            self.gate.authorize(self.block.serialize())

    def test_coordinator_cannot_inject_unknown_origin_and_new_work_stays_known(self):
        source, source_manifest = candidate(genesis=GENESIS, native_parent=GENESIS, height=1, ntime=1700000001,
            pool=3, secret=(2).to_bytes(32, "big"), payout_script=SCRIPT)
        share = solve_share(source, source_manifest)
        job, unused = fixture((share,))
        with self.assertRaisesRegex(ValueError, "not been validated locally"):
            self.gate.authorize(job.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
        self.gate.register_template(source.serialize())
        self.gate.authorize(job.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        with self.assertRaises(JobOmission):
            self.gate.authorize(self.block.serialize())

    def test_job_receipt_batch_rolls_back_when_capacity_is_exhausted(self):
        first = solve_share(self.block, self.manifest)
        second = solve_share(self.block, self.manifest, start_nonce=first.header.nNonce + 1)
        job, unused = fixture((first, second))
        with patch("native_mining_gate.MAX_RECEIPTS", 1):
            with self.assertRaisesRegex(ValueError, "archive is full"):
                self.gate.authorize(job.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def current_fixture(self, shares=(), parent_manifest=None):
        return candidate(genesis=GENESIS, native_parent=int(self.rpc.tip, 16),
                         height=self.rpc.height + 1, ntime=1700000001 + self.rpc.height,
                         pool=3, secret=SECRET, payout_script=SCRIPT, shares=shares,
                         parent_manifest=parent_manifest)

    def test_malicious_nested_counts_fail_before_framework_allocation(self):
        header = CBlockHeader(self.block).serialize()
        version = (2).to_bytes(4, "little")
        huge = b"\xff" * 9
        vin = self.block.vtx[0].vin[0].serialize()
        vout = bytes(8) + b"\x00"
        padding = bytes(128)
        cases = {
            "transactions": header + huge + padding,
            "inputs": header + b"\x01" + version + huge + padding,
            "outputs": header + b"\x01" + version + b"\x01" + vin + huge + padding,
            "input_script": header + b"\x01" + version + b"\x01" + bytes(36) + huge + padding,
            "output_script": header + b"\x01" + version + b"\x01" + vin + b"\x01" + bytes(8) + huge + padding,
            "witness_items": header + b"\x01" + version + b"\x00\x01\x01" + vin + b"\x01" + vout + huge + padding,
            "witness_item_size": header + b"\x01" + version + b"\x00\x01\x01" + vin + b"\x01" + vout + b"\x01" + huge + padding,
            "noncanonical_tx_count": header + b"\xfd\x01\x00" + self.block.vtx[0].serialize(),
            "noncanonical_input_count": header + b"\x01" + version + b"\xfd\x01\x00" + vin + b"\x01" + vout + bytes(4),
        }
        for name, raw in cases.items():
            with self.subTest(vector=name):
                with patch("native_mining_gate.CBlock.deserialize", side_effect=AssertionError("unsafe parser reached")):
                    with self.assertRaises(ValueError):
                        parse_block(raw)

    def test_truncated_blocks_fail_preflight_and_valid_witness_roundtrips(self):
        raw = self.block.serialize()
        for size in (1, 3, 80, 163, 164, 165, len(raw) - 4, len(raw) - 1):
            with self.subTest(size=size):
                with patch("native_mining_gate.CBlock.deserialize", side_effect=AssertionError("unsafe parser reached")):
                    with self.assertRaises(ValueError):
                        parse_block(raw[:size])
        witness, unused = candidate(genesis=GENESIS, native_parent=GENESIS, height=1,
                                    ntime=1700000001, pool=3, secret=SECRET,
                                    payout_script=SCRIPT, witness=True)
        self.assertEqual(parse_block(witness.serialize()).serialize(), witness.serialize())

    def test_historical_full_origin_uses_native_rewind_validation_only(self):
        # Simulate recovering a previously unknown height1 template at native3.
        with self.gate.db:
            self.gate.db.execute("DELETE FROM templates")
        self.rpc.advance(3)
        self.gate.register_template(self.block.serialize())
        self.assertTrue(any(call[0] == "validatesharepooltemplate" for call in self.rpc.calls))
        self.assertTrue(self.gate.receive(solve_share(self.block, self.manifest).serialize()))
        with self.assertRaisesRegex(ValueError, "native height mismatch"):
            self.gate.authorize(self.block.serialize())
        self.rpc.advance(4)
        with self.assertRaisesRegex(ValueError, "eligible native height"):
            self.gate.register_template(self.block.serialize())

    def test_historical_origin_rpc_binding_mismatch_is_not_cached(self):
        other, unused = fixture((solve_share(self.block, self.manifest),))
        original = self.gate.rpc
        def mismatched(method, *args):
            result = original(method, *args)
            if method == "validatesharepooltemplate":
                result["commitment"] = "ff" * 32
            return result
        self.gate.rpc = mismatched
        with self.assertRaisesRegex(ValueError, "does not match complete origin"):
            self.gate.register_template(other.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM templates").fetchone()[0], 1)

    def test_lifetime_exceeds_128_proofs_and_pruning_never_reuses_revision(self):
        # RPC is deliberately fake here: this verifies durable admission lifetime,
        # while native UTXO/ancestor consensus has separate functional coverage.
        for height in range(160):
            self.rpc.advance(height)
            block, manifest = self.current_fixture()
            self.gate.register_template(block.serialize())
            self.assertTrue(self.gate.receive(solve_share(block, manifest).serialize()))
        self.assertEqual(self.gate.maintenance()["revision"], 160)
        self.assertGreater(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 128)
        self.rpc.advance(320)
        snapshot = self.gate.maintenance()
        self.assertEqual(snapshot["pruned_through"], 160)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM templates").fetchone()[0], 0)
        self.gate.close()
        self.gate = self.open_gate()
        block, manifest = self.current_fixture()
        authorization = self.gate.authorize(block.serialize())
        self.assertEqual(authorization.receipt_sequence, 160)
        self.gate.receive(solve_share(block, manifest).serialize())
        self.assertEqual(self.gate.db.execute("SELECT sequence FROM receipts").fetchone()[0], 161)
        self.assertTrue(self.gate.needs_refresh(authorization))

    def test_paid_proof_and_body_survive_until_anchor_cannot_resurrect_it(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        settlement, manifest = fixture((share,))
        self.gate.authorize(settlement.serialize())
        self.rpc.advance(1)
        next_block, unused = self.current_fixture(parent_manifest=manifest)
        self.gate.authorize(next_block.serialize())  # authenticated paid state
        self.rpc.advance(RETENTION_BLOCKS + MAX_SHARE_AGE)
        self.gate.maintenance()  # anchor3; a rollback can still pay origin1 at4
        self.assertEqual(self.gate.receipt_bytes(f"{share.proof_id:064x}"), share.serialize())
        self.assertEqual(self.gate.template_bytes(template_id(share.header)), self.block.serialize())
        self.rpc.advance(MAX_SHARE_AGE)
        omitted, unused = self.current_fixture()
        with self.assertRaises(JobOmission):
            self.gate.authorize(omitted.serialize())
        self.rpc.advance(RETENTION_BLOCKS + MAX_SHARE_AGE + 1)
        self.gate.maintenance()  # anchor4; origin1 can never be eligible again
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)

    def test_deep_reorg_latches_recovery_even_after_original_chain_returns(self):
        self.rpc.advance(RETENTION_BLOCKS + 10)
        snapshot = self.gate.maintenance()
        self.assertEqual(snapshot["anchor_height"], 10)
        self.rpc.advance(9)
        with self.assertRaises(RecoveryRequired):
            self.gate.base_template()
        self.rpc.advance(RETENTION_BLOCKS + 10)
        with self.assertRaises(RecoveryRequired):
            self.gate.active_inventory()
        self.gate.close()
        self.gate = None
        with self.assertRaises(RecoveryRequired):
            self.open_gate()

    def test_same_height_anchor_replacement_requires_recovery(self):
        self.rpc.advance(RETENTION_BLOCKS + 10)
        self.gate.maintenance()
        self.rpc.hashes[10] = "ff" * 32
        with self.assertRaises(RecoveryRequired):
            self.gate.maintenance()

    def test_active_inventory_filters_expired_and_orphaned_but_keeps_archive(self):
        first = solve_share(self.block, self.manifest)
        self.gate.receive(first.serialize())
        snapshot = self.gate.active_inventory()
        self.assertEqual(snapshot["revision"], 1)
        self.assertEqual({item["kind"] for item in snapshot["items"]}, {"template", "receipt"})
        for item in snapshot["items"]:
            body = self.gate.receipt_bytes(item["id"]) if item["kind"] == "receipt" else self.gate.template_bytes(item["id"])
            self.assertEqual(item["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(item["bytes"], len(body))
        self.rpc.advance(1)
        second_block, second_manifest = self.current_fixture()
        second = solve_share(second_block, second_manifest)
        self.gate.register_template(second_block.serialize())
        self.gate.receive(second.serialize())
        self.rpc.hashes[1] = "ab" * 32
        self.rpc.tip = self.rpc.hashes[1]
        self.assertNotIn(f"{second.proof_id:064x}", [item["id"] for item in self.gate.active_inventory()["items"]])
        self.assertEqual(self.gate.receipt_bytes(f"{second.proof_id:064x}"), second.serialize())
        self.rpc.advance(5)
        self.assertEqual(self.gate.active_inventory()["items"], [])
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 2)

    def test_inventory_uses_bounded_metadata_without_reading_bodies(self):
        self.gate.receive(solve_share(self.block, self.manifest).serialize())
        with patch("native_mining_gate.parse_block", side_effect=AssertionError("inventory must not parse bodies")):
            with patch("native_mining_gate.parse_share", side_effect=AssertionError("inventory must not parse proofs")):
                self.assertEqual(len(self.gate.active_inventory()["items"]), 2)

    def test_v1_migration_preserves_receipts_and_origin_integrity(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        legacy_config = self.gate._config(1)
        self.gate.close()
        self.gate = None
        with sqlite3.connect(self.path) as db:
            db.execute("ALTER TABLE receipts RENAME TO old_receipts")
            db.execute("CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, proof_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
            db.execute("INSERT INTO receipts SELECT sequence,proof_id,data FROM old_receipts")
            db.execute("DROP TABLE old_receipts")
            db.execute("ALTER TABLE templates RENAME TO old_templates")
            db.execute("CREATE TABLE templates (job_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, data BLOB NOT NULL)")
            db.execute("INSERT INTO templates SELECT job_id,body_hash,data FROM old_templates")
            db.execute("DROP TABLE old_templates")
            db.execute("DROP TABLE state")
            db.execute("DROP TABLE archive_events")
            db.execute("DROP TABLE archive_state")
            db.execute("UPDATE config SET value=?", (legacy_config,))
            db.execute("PRAGMA user_version=0")
        self.path.with_name(self.path.name + ".archive-head.json").unlink()
        self.gate = self.open_gate()
        self.assertEqual(self.gate.db.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(self.gate.maintenance()["revision"], 1)
        self.assertFalse(self.gate.receive(share.serialize()))

    def test_interrupted_v1_schema_migration_rolls_back_all_ddl(self):
        legacy = Path(self.directory.name) / "legacy.sqlite"
        with sqlite3.connect(legacy) as db:
            db.execute("CREATE TABLE config (value TEXT NOT NULL)")
            db.execute("INSERT INTO config VALUES (?)", (self.gate._config(1),))
            db.execute("CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, proof_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
            db.execute("CREATE TABLE jobs (sequence INTEGER PRIMARY KEY, job_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
            db.execute("CREATE TABLE templates (job_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, data BLOB NOT NULL)")
        original = NativeMiningGate._config
        def failure(gate, version):
            if version == 2:
                raise OSError("migration interruption")
            return original(gate, version)
        with patch.object(NativeMiningGate, "_config", failure):
            with self.assertRaisesRegex(OSError, "migration interruption"):
                NativeMiningGate(legacy, rpc=self.rpc, pool=3,
                                 public_key=self.manifest.envelope.public_key, payout_script=SCRIPT)
        with sqlite3.connect(legacy) as db:
            self.assertEqual([row[1] for row in db.execute("PRAGMA table_info(receipts)")],
                             ["sequence", "proof_id", "data"])
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='state'").fetchone()[0], 0)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 0)
        with NativeMiningGate(legacy, rpc=self.rpc, pool=3,
                              public_key=self.manifest.envelope.public_key, payout_script=SCRIPT) as recovered:
            self.assertEqual(recovered.maintenance()["revision"], 0)

    def test_startup_detects_hash_corruption_before_exposing_inventory(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        with self.gate.db:
            self.gate.db.execute("UPDATE receipts SET data_hash=?", ("00" * 32,))
        self.gate.close()
        self.gate = None
        with self.assertRaisesRegex(ValueError, "hash or height"):
            self.open_gate()

    def test_startup_rejects_oversized_archive_before_decoding_blobs(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        self.gate.close()
        self.gate = None
        with patch("native_mining_gate.MAX_ARCHIVE_RECEIPTS", 0):
            with patch("native_mining_gate.parse_share", side_effect=AssertionError("must not decode")):
                with self.assertRaisesRegex(ValueError, "archive bounds"):
                    self.open_gate()

    def test_body_byte_limit_does_not_remove_existing_evidence(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        other, unused = fixture((share,))
        with patch("native_mining_gate.MAX_TEMPLATE_BYTES", len(self.block.serialize())):
            with self.assertRaisesRegex(ValueError, "archive is full"):
                self.gate.register_template(other.serialize())
        self.assertEqual(self.gate.receipt_bytes(f"{share.proof_id:064x}"), share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM templates").fetchone()[0], 1)

    def test_second_owner_cannot_race_retained_anchor_or_revisions(self):
        with self.assertRaisesRegex(ValueError, "owning process"):
            self.open_gate()
        self.gate.close()
        self.gate = self.open_gate()
        self.assertEqual(self.gate.maintenance()["revision"], 0)

    def test_pruning_detects_corrupt_height_before_deleting_acknowledged_work(self):
        share = solve_share(self.block, self.manifest)
        self.gate.receive(share.serialize())
        self.rpc.advance(RETENTION_BLOCKS + MAX_SHARE_AGE)
        with self.gate.db:
            self.gate.db.execute("UPDATE receipts SET origin_height=0")
        with self.assertRaisesRegex(ValueError, "height or parent"):
            self.gate.maintenance()
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM templates").fetchone()[0], 1)

    def test_revision_rollback_on_failed_receipt_insert(self):
        share = solve_share(self.block, self.manifest)
        self.gate.db.execute("CREATE TRIGGER fail_revision BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT,'revision fault'); END")
        # maintenance also updates state, so inject only at the receipt transaction.
        with patch.object(self.gate, "maintenance", return_value={}):
            with self.assertRaises(sqlite3.IntegrityError):
                self.gate.receive(share.serialize())
        self.assertEqual(self.gate.db.execute("SELECT revision FROM state").fetchone()[0], 0)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
