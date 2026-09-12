#!/usr/bin/env python3
"""Deterministic wire and flat commitment tests; native validity is separate."""
from dataclasses import replace
import struct
import unittest

from hash_snapshot import (EnvelopeV2, Snapshot, TemplateRecord, RULES_HASH, MAX_SNAPSHOT_BYTES,
    MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES, SHARE_BITS, candidate, solve_share, parse_share,
    normalize_template, HashSigner)
from native_enforcement import compact_size, verify_schnorr
from native_signer import REGTEST_GENESIS, SignerError
from test_framework.messages import hash256, ser_uint256

SCRIPT = b"\x00\x14" + b"a" * 20
SECRET = (1).to_bytes(32, "big")


def fixture(**options):
    arguments = dict(genesis=REGTEST_GENESIS, native_parent=REGTEST_GENESIS,
        height=1, ntime=1700000001, pool=3, secret=SECRET, payout_script=SCRIPT)
    arguments.update(options)
    return candidate(**arguments)


class HashSnapshotTests(unittest.TestCase):
    def test_flat_complete_snapshot_hash_and_rules(self):
        block, snapshot = fixture()
        raw = snapshot.serialize()
        self.assertEqual(Snapshot.deserialize(raw).serialize(), raw)
        self.assertEqual(block.m_mm_rhs, int.from_bytes(hash256(b"SharePool/snapshot/v2\0" + raw), "little"))
        self.assertEqual(RULES_HASH, int.from_bytes(hash256(b"SharePool/rules/v2\0" + struct.pack(
            "<IIIIII", SHARE_BITS, 3, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES)), "little"))
        self.assertEqual(len(block.vtx[0].vout), 1)
        self.assertEqual(block.vtx[0].vout[0].serialize(), snapshot.payouts[0].serialize())

    def test_owner_domain_and_reserved_fields(self):
        unused, snapshot = fixture()
        self.assertTrue(verify_schnorr(snapshot.envelope.public_key, snapshot.owner_signature, snapshot.envelope.owner_message))
        with self.assertRaises(ValueError):
            replace(snapshot.envelope, shares_root=1).serialize()
        with self.assertRaises(ValueError):
            replace(snapshot.envelope, version=1).serialize()
        with self.assertRaises(ValueError):
            snapshot.envelope.root

    def test_one_hundred_distinct_proofs_roundtrip_and_payout(self):
        origin, opening = fixture()
        proofs, next_nonce = [], 0
        for _ in range(100):
            proof = solve_share(origin, opening, start_nonce=next_nonce)
            next_nonce = proof.header.nNonce + 1
            proofs.append(proof)
        unused, snapshot = fixture(templates=[origin], shares=proofs)
        self.assertEqual(len(Snapshot.deserialize(snapshot.serialize()).shares), 100)
        self.assertEqual(len(snapshot.post_state), 100)
        self.assertEqual(snapshot.payouts[0].nValue, 5_000_000_000)
        self.assertEqual(parse_share(proofs[0].serialize()), proofs[0])

    def test_templates_are_full_normalized_bodies(self):
        block, snapshot = fixture()
        block.nNonce, block.m_nonce2, block.m_time_offset = 123, 4, 5
        record = TemplateRecord.from_block(block)
        self.assertEqual(normalize_template(record.data), record.data)
        changed = bytearray(record.data)
        changed[-1] ^= 1
        with self.assertRaises(ValueError):
            replace(record, data=bytes(changed)).serialize()
        self.assertNotEqual(block.serialize(), record.data)
        with self.assertRaises(ValueError):
            replace(record, data=block.serialize()).serialize()

    def test_every_snapshot_component_is_committed(self):
        block, snapshot = fixture()
        record = TemplateRecord.from_block(block)
        other = replace(snapshot, templates=(record,))
        self.assertNotEqual(other.hash, snapshot.hash)
        altered = replace(snapshot, owner_signature=b"x" * 64)
        self.assertNotEqual(altered.hash, snapshot.hash)

    def test_template_order_is_serialized_bytes_not_numeric(self):
        left, unused = fixture(ntime=1700000001)
        right, unused = fixture(ntime=1700000002)
        unused, snapshot = fixture(templates=[left, right])
        identifiers = [ser_uint256(record.template_id) for record in snapshot.templates]
        self.assertEqual(identifiers, sorted(identifiers))
        with self.assertRaises(ValueError):
            replace(snapshot, templates=tuple(reversed(snapshot.templates))).serialize()
        with self.assertRaises(ValueError):
            replace(snapshot, templates=(snapshot.templates[0],) * 2).serialize()

    def test_huge_compact_sizes_and_truncation_fail_before_loops(self):
        unused, snapshot = fixture()
        prefix = snapshot.envelope.serialize() + snapshot.owner_signature
        for value in (253, 2**32, 2**63):
            with self.subTest(count=value), self.assertRaises(ValueError):
                Snapshot.deserialize(prefix + compact_size(value))
        with self.assertRaises(ValueError):
            Snapshot.deserialize(prefix + b"\xfd\x00\x00")
        for cut in (1, 20, 64, 100, 284, len(snapshot.serialize()) - 1):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                Snapshot.deserialize(snapshot.serialize()[:cut])
        with self.assertRaises(ValueError):
            Snapshot.deserialize(snapshot.serialize() + b"\x00")

    def test_wrong_signer_domain_and_policy_reject(self):
        unused, snapshot = fixture()
        signer = HashSigner.__new__(HashSigner)
        signer.pool, signer.payout_script, signer.public_key = 3, SCRIPT, snapshot.envelope.public_key
        signer._invoke = lambda command, raw, size: snapshot.owner_signature
        self.assertEqual(signer.sign_owner(snapshot.envelope), snapshot.owner_signature)
        with self.assertRaises(SignerError):
            signer.sign_owner(replace(snapshot.envelope, pool=4))
        signer._invoke = lambda command, raw, size: b"x" * 64
        with self.assertRaises(SignerError):
            signer.sign_owner(snapshot.envelope)


if __name__ == "__main__":
    unittest.main()
