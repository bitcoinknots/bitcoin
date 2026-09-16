#!/usr/bin/env python3
"""Deterministic wire and flat commitment tests; native validity is separate."""
from copy import deepcopy
from dataclasses import replace
import struct
import unittest

from hash_snapshot import (EnvelopeV2, Snapshot, TemplateRecord, CompactTemplateRecord, Reader, RULES_HASH, MAX_SNAPSHOT_BYTES,
    MAX_TEMPLATE_BYTES, MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES, SHARE_BITS, SHARE_TARGET_SHIFT, share_target, share_work, work_outputs, job_hash, candidate, solve_share, parse_share,
    normalize_template, HashSigner, PHYSICAL_FIELDS, winner_share)
from native_enforcement import compact_size, verify_schnorr
from native_signer import REGTEST_GENESIS, SignerError
from test_framework.messages import CBlockHeader, CTransaction, CTxIn, COutPoint, CTxOut, hash256, ser_uint256, uint256_from_compact

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
        self.assertEqual(block.m_mm_rhs, int.from_bytes(hash256(b"SharePool/snapshot/v4\0" + raw), "little"))
        self.assertEqual(RULES_HASH, int.from_bytes(hash256(b"SharePool/rules/v4\0" + struct.pack(
            "<10I", SHARE_BITS, SHARE_TARGET_SHIFT, 3, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES, MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS)), "little"))
        self.assertEqual(len(block.vtx[0].vout), 1)
        self.assertEqual(block.vtx[0].vout[0].serialize(), snapshot.payouts[0].serialize())

    def test_owner_domain_and_reserved_fields(self):
        unused, snapshot = fixture()
        self.assertTrue(verify_schnorr(snapshot.envelope.public_key, snapshot.owner_signature, snapshot.owner_message))
        with self.assertRaises(ValueError):
            replace(snapshot.envelope, shares_root=1).serialize()
        with self.assertRaises(ValueError):
            replace(snapshot.envelope, version=1).serialize()
        with self.assertRaises(ValueError):
            snapshot.envelope.root
        with self.assertRaisesRegex(ValueError, "exact snapshot"):
            snapshot.envelope.owner_message
        for commitment in (-1, 1 << 256, True, 1.0, b"invalid"):
            with self.subTest(commitment=commitment), self.assertRaisesRegex(ValueError, "256-bit"):
                replace(snapshot, job_commitment=commitment).serialize()

    def test_signature_attests_each_snapshot_component(self):
        origin, opening = fixture()
        proof = solve_share(origin, opening)
        unused, snapshot = fixture(templates=[origin], shares=[proof])
        changes = {
            "round binding": replace(snapshot, envelope=replace(snapshot.envelope, height=2)),
            "exact job": replace(snapshot, job_commitment=snapshot.job_commitment ^ 1),
            "templates": replace(snapshot, templates=()),
            "proofs": replace(snapshot, shares=()),
            "paid state": replace(snapshot, post_state=()),
            "payouts": replace(snapshot, payouts=(CTxOut(snapshot.payouts[0].nValue - 1, SCRIPT),)),
        }
        for field, changed in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(snapshot.contents_hash, changed.contents_hash)
                self.assertFalse(verify_schnorr(snapshot.envelope.public_key, snapshot.owner_signature, changed.owner_message))
        # Excluding only the current signature breaks the self-reference; the
        # final snapshot hash still commits that signature's exact bytes.
        changed = replace(snapshot, owner_signature=b"x" * 64)
        self.assertEqual(changed.contents_hash, snapshot.contents_hash)
        self.assertEqual(changed.owner_message, snapshot.owner_message)
        self.assertNotEqual(changed.hash, snapshot.hash)

    def test_job_signature_binds_template_but_allows_physical_search_fields(self):
        block, snapshot = fixture(witness=True)
        expected = snapshot.job_commitment
        self.assertEqual(job_hash(block), expected)
        for field in PHYSICAL_FIELDS:
            changed = deepcopy(block)
            setattr(changed, field, 1)
            with self.subTest(search_field=field):
                self.assertEqual(job_hash(changed), expected)
                self.assertTrue(verify_schnorr(snapshot.envelope.public_key, snapshot.owner_signature,
                    replace(snapshot, job_commitment=job_hash(changed)).owner_message))
        for field in ("nTime", "nBits", "hashPrevBlock", "hashMerkleRoot", "m_height", "m_txcount"):
            changed = deepcopy(block)
            setattr(changed, field, getattr(changed, field) ^ 1)
            with self.subTest(template_field=field):
                changed_hash = job_hash(changed)
                self.assertNotEqual(changed_hash, expected)
                self.assertFalse(verify_schnorr(snapshot.envelope.public_key, snapshot.owner_signature,
                    replace(snapshot, job_commitment=changed_hash).owner_message))
        # Coinbase witness data is excluded from its txid, but included in the
        # signed full job body. A header-only attestation would miss this edit.
        changed = deepcopy(block)
        changed.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = b"x" * 32
        self.assertEqual(changed.calc_merkle_root(), block.hashMerkleRoot)
        self.assertNotEqual(job_hash(changed), expected)
        # The final settlement hash is deliberately removed from the job hash
        # and separately checked against the complete signed snapshot.
        changed = deepcopy(block)
        changed.m_mm_rhs ^= 1
        self.assertEqual(job_hash(changed), expected)

    def test_native_target_scales_share_difficulty_and_rejects_noncanonical_bits(self):
        native_target = 0xffff << 208
        expected_share_target = native_target << 10
        self.assertEqual(share_target(0x1d00ffff), expected_share_target)
        self.assertEqual(share_work(0x1d00ffff), (1 << 256) // (expected_share_target + 1))
        self.assertGreater(share_work(0x1c00ffff), share_work(0x1d00ffff))
        self.assertEqual(share_target(SHARE_BITS), uint256_from_compact(SHARE_BITS))
        self.assertEqual(share_work(SHARE_BITS), 2)
        for bits, target in ((0x01010000, 1), (0x02008000, 128), (0x03008000, 32768)):
            with self.subTest(small_target=target):
                self.assertEqual(share_target(bits), target << 10)
        invalid = (0, -1, 1 << 32, True, 1.0, 0x1d80ffff, 0x23010000,
                   0x01000000, 0x01010001, 0x02000100, 0x1d000001)
        for bits in invalid:
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                share_target(bits)

    def test_mixed_difficulty_payouts_use_work_and_aggregate_payout_scripts(self):
        # Accounting fixtures need no solved header: this test isolates payout
        # arithmetic; actual proof and nBits validity is tested natively.
        other_script = b"\x00\x14" + b"b" * 20
        easy, easy_snapshot = fixture(native_bits=0x1d00ffff)
        hard, hard_snapshot = fixture(native_bits=0x1c00ffff, payout_script=other_script)
        another_easy = deepcopy(easy)
        another_easy.nNonce = 1
        proofs = [winner_share(easy, easy_snapshot), winner_share(another_easy, easy_snapshot),
                  winner_share(hard, hard_snapshot)]
        easy_weight = (1 << 256) // ((0xffff << 218) + 1)
        hard_weight = (1 << 256) // ((0xffff << 210) + 1)
        # One proof's higher difficulty has a larger weight than two easier
        # proofs, and both easier proofs credit the same payout destination.
        total_weight = 2 * easy_weight + hard_weight
        payouts = work_outputs(proofs, total_weight, b"\x00\x14" + b"c" * 20)
        self.assertEqual({bytes(output.scriptPubKey): output.nValue for output in payouts},
                         {SCRIPT: 2 * easy_weight, other_script: hard_weight})
        self.assertEqual(sum(output.nValue for output in payouts), total_weight)
        self.assertEqual([bytes(output.scriptPubKey) for output in payouts], [SCRIPT, other_script])
        rounded = work_outputs(proofs, 100, SCRIPT)
        self.assertEqual([(bytes(output.scriptPubKey), output.nValue) for output in rounded],
                         [(SCRIPT, 1), (other_script, 99)])

    def test_payout_remainder_is_exact_and_ties_use_script_order(self):
        other_script = b"\x00\x14" + b"b" * 20
        left, left_snapshot = fixture()
        right, right_snapshot = fixture(payout_script=other_script)
        proofs = [winner_share(right, right_snapshot), winner_share(left, left_snapshot)]
        for reward in (0, 1, 5, 21_000_000 * 100_000_000):
            with self.subTest(reward=reward):
                payouts = work_outputs(proofs, reward, SCRIPT)
                self.assertEqual([(bytes(output.scriptPubKey), output.nValue) for output in payouts],
                                 [(SCRIPT, (reward + 1) // 2), (other_script, reward // 2)])
                self.assertEqual(sum(output.nValue for output in payouts), reward)
        self.assertEqual(work_outputs([], 123, SCRIPT)[0].nValue, 123)

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

    def test_hundred_large_templates_share_bytes_and_remain_distinct(self):
        # Wire-capacity fixture, not a claim about transaction script validity.
        # Each reconstructed template is close to4MB; one common transaction is
        # encoded once. Header time distinguishes all100 exact template IDs.
        block, snapshot = fixture()
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(123, 0))]
        transaction.vout = [CTxOut(1, b"x" * 3_850_000)]
        block.vtx.append(transaction)
        block.m_txcount = len(block.vtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        base = CompactTemplateRecord.from_record(TemplateRecord.from_block(block))
        with self.assertRaises(ValueError):
            CompactTemplateRecord(base.template_id, bytearray(base.header_bytes), base.transactions)
        records = []
        for index in range(100):
            header = CBlockHeader(block)
            header.nTime += index
            from native_mining_gate import template_id
            records.append(CompactTemplateRecord(int(template_id(header), 16), header.serialize(), base.transactions))
        records.sort(key=lambda value: ser_uint256(value.template_id))
        encoded = replace(snapshot, templates=tuple(records)).serialize()
        self.assertLess(len(encoded), 3_900_000)
        decoded = Snapshot.deserialize(encoded)
        self.assertEqual(len({record.template_id for record in decoded.templates}), 100)
        self.assertGreater(sum(record.expanded_bytes for record in decoded.templates), 385_000_000)
        self.assertTrue(all(record.transactions[1] is decoded.templates[0].transactions[1] for record in decoded.templates))
        self.assertEqual(decoded.serialize(), encoded)
        with self.assertRaises(AttributeError):
            decoded.templates[0].transactions[1].raw = b"corrupted"
        with self.assertRaises(AttributeError):
            decoded.templates[0].header_bytes = b"corrupted"

    def test_transaction_table_is_unique_ordered_and_fully_referenced(self):
        origin, opening = fixture()
        unused, snapshot = fixture(templates=[origin], shares=[solve_share(origin, opening)])
        raw = snapshot.serialize()
        reader = Reader(raw)
        reader.take(len(snapshot.envelope.serialize()) + 64 + 32)
        table_offset = reader.stream.tell()
        self.assertEqual(reader.size(100), 1)
        entry_offset = reader.stream.tell()
        entry = reader.variable(MAX_TEMPLATE_BYTES)
        template_offset = reader.stream.tell()
        self.assertEqual(reader.size(100), 1)
        reader.take(32 + 164)
        self.assertEqual(reader.size(100), 1)
        reference_offset = reader.stream.tell()
        self.assertEqual(reader.size(100), 0)
        cases = [
            raw[:reference_offset] + b"\x01" + raw[reference_offset + 1:],
            raw[:table_offset] + b"\x02" + raw[entry_offset:template_offset] * 2 + raw[template_offset:],
            raw[:template_offset] + b"\x00" + raw[reader.stream.tell():],
        ]
        for altered in cases:
            with self.subTest(size=len(altered)), self.assertRaises(ValueError):
                Snapshot.deserialize(altered)

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
        prefix = snapshot.envelope.serialize() + snapshot.owner_signature + ser_uint256(snapshot.job_commitment)
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
        self.assertEqual(signer.sign_owner(snapshot), snapshot.owner_signature)
        with self.assertRaisesRegex(SignerError, "complete snapshot"):
            signer.sign_owner(snapshot.envelope)
        with self.assertRaisesRegex(SignerError, "policy"):
            signer.sign_owner(replace(snapshot, job_commitment=0))
        with self.assertRaises(SignerError):
            signer.sign_owner(replace(snapshot, envelope=replace(snapshot.envelope, pool=4)))
        signer._invoke = lambda command, raw, size: b"x" * 64
        with self.assertRaises(SignerError):
            signer.sign_owner(snapshot)


if __name__ == "__main__":
    unittest.main()
