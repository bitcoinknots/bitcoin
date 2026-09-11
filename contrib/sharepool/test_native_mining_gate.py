#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Miner policy/durability checks; real consensus is tested by functional nodes."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from native_enforcement import (MAX_MANIFEST, MAX_SHARE_AGE, MAX_SHARES, RULES_HASH,
                                SHARE_BITS, candidate, solve_share)
from native_mining_gate import (REGTEST_GENESIS, JobOmission, NativeMiningGate,
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
        self.chain, self.tip = "regtest", REGTEST_GENESIS
        self.proposal_error, self.share_error, self.race = None, None, False
        self.calls = []

    def __call__(self, method, *args):
        self.calls.append((method, args))
        if method == "getblockchaininfo":
            return {"chain": self.chain}
        if method == "getblockhash":
            return REGTEST_GENESIS
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
        if method == "getblocktemplate":
            if args[0].get("mode") == "proposal":
                if self.race:
                    self.tip = "11" * 32
                return self.proposal_error
            return {"height": 1, "rules": ["!sharepool"], "sharepool": {
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
        with self.assertRaisesRegex(ValueError, "another miner"):
            self.open_gate(pool=4)
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


if __name__ == "__main__":
    unittest.main()
