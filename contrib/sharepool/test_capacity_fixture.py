#!/usr/bin/env python3
"""Bounded fixture construction checks; native validity is tested separately."""
from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))
from feature_sharepool_hash_capacity import SharePoolHashCapacityTest
from hash_snapshot import Snapshot, TIDES_RULES_HASH, TIDES_VERSION, candidate, job_hash
from native_mining_gate import parse_block
from native_signer import REGTEST_GENESIS
from test_framework.script import CScript, OP_DROP, OP_TRUE


def unsigned_fixture():
    block, snapshot = candidate(genesis=REGTEST_GENESIS, native_parent=REGTEST_GENESIS,
        height=102, ntime=1_700_000_001, pool=3, secret=(1).to_bytes(32, "big"),
        payout_script=b"\x00\x14" + b"a" * 20, witness=True)
    # Structural test input only. This does not emulate native TIDES payouts or
    # bypass the harness's real native preparation/finalization/authorization.
    snapshot = replace(snapshot, owner_signature=bytes(64),
        envelope=replace(snapshot.envelope, version=TIDES_VERSION, rules=TIDES_RULES_HASH))
    block.m_mm_rhs = snapshot.hash
    return {"template": block.serialize().hex(), "snapshot": snapshot.serialize().hex(), "reward": 5_000_000_000}


class CapacityFixtureTests(unittest.TestCase):
    def test_tag_changes_exact_root_and_signing_payload_preserves_payout_and_witness(self):
        original = unsigned_fixture()
        before = parse_block(bytes.fromhex(original["template"]))
        transformed = SharePoolHashCapacityTest.tag_unsigned_job(original, b"miner-001")
        after = parse_block(bytes.fromhex(transformed["template"]))
        snapshot = Snapshot.deserialize(bytes.fromhex(transformed["snapshot"]))
        self.assertNotEqual(after.hashMerkleRoot, before.hashMerkleRoot)
        self.assertEqual(after.hashMerkleRoot, after.calc_merkle_root())
        self.assertEqual([output.serialize() for output in after.vtx[0].vout],
                         [output.serialize() for output in before.vtx[0].vout])
        self.assertEqual(after.vtx[0].wit.serialize(), before.vtx[0].wit.serialize())
        self.assertEqual(after.m_mm_rhs, snapshot.hash)
        self.assertEqual(snapshot.job_commitment, job_hash(after))
        self.assertEqual(transformed["signing_payload"], snapshot.signing_payload.hex())
        self.assertEqual(transformed["signing_hash"], snapshot.owner_message[::-1].hex())
        self.assertEqual(snapshot.owner_signature, bytes(64))
        self.assertEqual(transformed["reward"], original["reward"])
        other = SharePoolHashCapacityTest.tag_unsigned_job(original, b"miner-002")
        self.assertNotEqual(other["job_commitment"], transformed["job_commitment"])
        self.assertNotEqual(other["signing_payload"], transformed["signing_payload"])
        self.assertEqual(original, unsigned_fixture())

    def test_tag_cannot_modify_an_already_signed_job_or_overrun_coinbase(self):
        original = unsigned_fixture()
        signed = dict(original, snapshot=replace(Snapshot.deserialize(bytes.fromhex(original["snapshot"])),
                                                owner_signature=b"x" * 64).serialize().hex())
        with self.assertRaises(AssertionError):
            SharePoolHashCapacityTest.tag_unsigned_job(signed, b"tag")
        for tag in (b"", b"x" * 33):
            with self.subTest(tag_length=len(tag)), self.assertRaises(AssertionError):
                SharePoolHashCapacityTest.tag_unsigned_job(original, tag)
        block = parse_block(bytes.fromhex(original["template"]))
        block.vtx[0].vin[0].scriptSig = CScript(bytes(99))
        with self.assertRaises(AssertionError):
            SharePoolHashCapacityTest.tag_unsigned_job(dict(original, template=block.serialize().hex()), b"tag")

    def test_heavy_witness_respects_existing_element_opcode_and_stack_bounds(self):
        harness = object.__new__(SharePoolHashCapacityTest)
        harness.options = SimpleNamespace(witness_heavy=True)
        redeem = CScript([OP_DROP] * 128 + [OP_TRUE])
        transaction = harness.fixture_spend(1, 0, 50_000_000, redeem, b"\x00\x20" + bytes(32), 11_000)
        stack = transaction.wit.vtxinwit[0].scriptWitness.stack
        self.assertEqual(len(stack), 129)
        self.assertEqual([len(item) for item in stack[:-1]], [256] * 128)
        self.assertEqual(stack[-1], bytes(redeem))
        self.assertLessEqual(len(stack), 1000)
        self.assertLessEqual(len(redeem) - 1, 201)
        self.assertLess(100 * transaction.get_weight() + 20_000, 4_000_000)


if __name__ == "__main__":
    unittest.main()
