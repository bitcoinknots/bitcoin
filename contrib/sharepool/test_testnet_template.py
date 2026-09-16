#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Full-candidate and physical Sia search-space binding regressions."""

import copy
import hashlib
from io import BytesIO
import unittest

from testnet_template import build_template, proof_from_sia, sia_notify
from test_framework.messages import CBlock, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, hash256
from test_framework.script import CScript


SCRIPT = bytes.fromhex("0014" + "33" * 20)


def fixture(witness=True):
    transactions, entries = [], []
    for index in range(2):
        tx = CTransaction()
        parent = 123 if not transactions else int(transactions[-1].rehash(), 16)
        tx.vin = [CTxIn(COutPoint(parent, 0), CScript(), 0xfffffffe)]
        tx.vout = [CTxOut(10000 - 100 * index, CScript(SCRIPT))]
        if witness:
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b"test witness only"]
        entries.append({"data": tx.serialize().hex(), "txid": tx.rehash(), "hash": tx.getwtxid(),
                        "weight": tx.get_weight(), "fee": 100, "sigops": 0,
                        "depends": [1] if index else []})
        transactions.append(tx)
    gbt = {"rules": ["csv", "!segwit", "!blake2b", "taproot", "reduced_data"],
           "version": 0xa0000010, "vbrequired": 0x10, "height": 150903,
           "curtime": 1789158160, "mintime": 1789158000, "bits": "1d00ffff",
           "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
           "previousblockhash": "55" * 32, "coinbasevalue": 5000000200,
           "weightlimit": 800000, "sizelimit": 4000000, "sigoplimit": 80000,
           "transactions": entries, "coinbaseaux": {}}
    if witness:
        root = CBlock.get_merkle_root([bytes(32)] + [hash256(tx.serialize()) for tx in transactions])
        gbt["default_witness_commitment"] = (bytes.fromhex("6a24aa21a9ed") + hash256(root.to_bytes(32, "little") + bytes(32))).hex()
    return gbt


def job(gbt=None, **kwargs):
    gbt = fixture() if gbt is None else gbt
    return build_template(gbt, [(SCRIPT, gbt["coinbasevalue"])], b"r" * 32, b"DATUM/test", **kwargs)


def block(raw):
    result = CBlock()
    result.deserialize(BytesIO(raw))
    return result


def proof(j=None, **kwargs):
    defaults = {"prefix": b"ABCD", "extranonce2": bytes.fromhex("0102030405060708"),
                "ntime": "fefdfcfbfaf9f8f7", "nonce": "8877665544332211"}
    defaults.update(kwargs)
    return proof_from_sia(job() if j is None else j, **defaults)


class TestnetTemplateTests(unittest.TestCase):
    def test_real_transaction_bytes_witness_and_reward_survive_assembly(self):
        gbt, j = fixture(), job()
        candidate = block(j.block())
        self.assertEqual(len(j.header_bytes), 164)
        self.assertEqual(candidate.m_txcount, 3)
        self.assertEqual(candidate.calc_merkle_root(), candidate.hashMerkleRoot)
        self.assertEqual([tx.serialize().hex() for tx in candidate.vtx[1:]], [entry["data"] for entry in gbt["transactions"]])
        self.assertEqual(candidate.vtx[0].vout[0].nValue, gbt["coinbasevalue"])
        self.assertEqual(bytes(candidate.vtx[0].vout[0].scriptPubKey), SCRIPT)
        self.assertEqual(candidate.vtx[0].wit.vtxinwit[0].scriptWitness.stack, [bytes(32)])
        self.assertEqual(bytes(candidate.vtx[0].vout[-1].scriptPubKey).hex(), gbt["default_witness_commitment"])

    def test_no_witness_template_does_not_invent_witness(self):
        candidate = block(job(fixture(witness=False)).block())
        self.assertTrue(all(tx.wit.is_null() for tx in candidate.vtx))
        self.assertEqual(len(candidate.vtx[0].vout), 1)

    def test_full_64bit_nonce_and_time_map_to_native_hash(self):
        j, p = job(), proof()
        candidate = block(p.block)
        self.assertEqual(p.hash, hashlib.blake2b(p.work, digest_size=32).digest())
        self.assertEqual(candidate.rehash(), p.hash_int)
        self.assertEqual(p.display_hash, f"{candidate.sha256:064x}")
        self.assertEqual(candidate.nNonce, 0x55667788)
        self.assertEqual(candidate.m_nonce2, 0x11223344)
        self.assertEqual(candidate.m_time_offset, 0xfbfcfdfe)
        self.assertEqual(candidate.m_nonce3, 0xf7f8f9fa)
        self.assertEqual(candidate.nTime, j.header.nTime)
        self.assertEqual(candidate.get_time_on_wire(), j.header.get_time_on_wire())
        self.assertEqual(candidate.m_extranonce.to_bytes(16, "little"), bytes(4) + b"ABCD" + bytes.fromhex("0102030405060708"))
        self.assertEqual(candidate.calc_merkle_root(), candidate.hashMerkleRoot)

    def test_miner_extranonce_never_mutates_bitcoin_coinbase(self):
        j = job()
        first, second = proof(j), proof(j, prefix=b"WXYZ", extranonce2=b"87654321")
        left, right = block(first.block), block(second.block)
        self.assertEqual(left.vtx[0].serialize(), j.coinbase)
        self.assertEqual(right.vtx[0].serialize(), j.coinbase)
        self.assertEqual(left.hashMerkleRoot, right.hashMerkleRoot)
        self.assertNotEqual(first.hash, second.hash)
        # Reproduces the old integration defect: inserting miner search bytes
        # into the Bitcoin coinbase invalidates already performed ASIC work.
        left.vtx[0].vin[0].scriptSig = CScript(bytes(left.vtx[0].vin[0].scriptSig) + b"ABCD12345678")
        left.vtx[0].rehash()
        left.hashMerkleRoot = left.calc_merkle_root()
        self.assertNotEqual(left.rehash(), first.hash_int)

    def test_notify_has_exact_sia_leaf_layout(self):
        j, prefix = job(), b"ABCD"
        notice = sia_notify(j, prefix)
        self.assertEqual(notice[0], j.job_id)
        self.assertEqual(notice[3:5], ["", []])
        self.assertEqual(notice[5], "20000010")
        self.assertEqual(len(bytes.fromhex(notice[2])), 39)
        self.assertEqual(bytes.fromhex(notice[2])[:3], bytes(3))
        self.assertEqual(bytes.fromhex(notice[2])[-4:], bytes(4))
        self.assertEqual(len(bytes(1) + bytes.fromhex(notice[2]) + prefix + bytes(8)), 52)

    def test_legacy_32bit_fields_follow_datum_hex_rules(self):
        result = block(proof(ntime="01020304", nonce="11223344").block)
        self.assertEqual(result.nNonce, 0x11223344)
        self.assertEqual(result.m_nonce2, 0)
        self.assertEqual(result.m_time_offset, 0x01020304)
        self.assertEqual(result.m_nonce3, 0)

    def test_commitment_tag_and_payout_change_hashed_work(self):
        gbt = fixture()
        jobs = [job(), build_template(gbt, [(SCRIPT, gbt["coinbasevalue"])], b"s" * 32, b"DATUM/test"),
                build_template(gbt, [(SCRIPT, gbt["coinbasevalue"])], b"r" * 32, b"DATUM/other"),
                build_template(gbt, [(bytes.fromhex("0014" + "44" * 20), gbt["coinbasevalue"])], b"r" * 32, b"DATUM/test")]
        self.assertEqual(len({proof(j).hash for j in jobs}), 4)
        self.assertEqual(jobs[0].header.m_mm_rhs.to_bytes(32, "little"), b"r" * 32)

    def test_fixed_header_mutation_and_returned_header_mutation(self):
        j = job()
        changed = j.header
        changed.nTime += 1
        with self.assertRaisesRegex(ValueError, "fixed template"):
            j.block(changed.serialize())
        self.assertNotEqual(changed.nTime, j.header.nTime)
        changed = j.header
        changed.m_mm_rhs += 1
        with self.assertRaisesRegex(ValueError, "fixed template"):
            j.block(changed.serialize())

    def test_wrong_network_and_unknown_required_rules_fail(self):
        for chain in ("main", "test", "signet", "regtest"):
            with self.subTest(chain=chain), self.assertRaisesRegex(ValueError, "Testnet4"):
                job(chain=chain)
        for rules in (["!segwit"], ["!segwit", "!blake2b", "!unknown"], ["!blake2b"]):
            changed = fixture()
            changed["rules"] = rules
            with self.subTest(rules=rules), self.assertRaisesRegex(ValueError, "consensus rules"):
                job(changed)

    def test_unsupported_header_features_fail_closed(self):
        for field, value in (("version", 0x20000010), ("header_flags", 4), ("h1_flags", 1),
                             ("time_offset", 1), ("xor_key", "11" * 16),
                             ("xor_key_mask_clear_bits", 1), ("merge_mining_rhs", "11" * 32),
                             ("header_version", 1), ("height", 150308)):
            changed = fixture()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                job(changed)

    def test_transaction_identity_weight_order_and_bytes_checked(self):
        for field, value in (("txid", "00" * 32), ("hash", "00" * 32), ("weight", 1),
                             ("depends", [2]), ("depends", [[1]]), ("data", "00"),
                             ("fee", -1), ("sigops", -1)):
            changed = fixture()
            changed["transactions"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                job(changed)
        changed = fixture()
        changed["transactions"][1] = copy.deepcopy(changed["transactions"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            job(changed)

    def test_changed_witness_cannot_keep_old_witness_commitment(self):
        changed = fixture()
        entry = changed["transactions"][0]
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(entry["data"])))
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"changed witness"]
        entry.update(data=tx.serialize().hex(), hash=tx.getwtxid(), weight=tx.get_weight())
        with self.assertRaisesRegex(ValueError, "witness commitment"):
            job(changed)

    def test_reward_and_bounds_checked_before_hardware(self):
        for field, value in (("coinbasevalue", 1), ("curtime", 1), ("weightlimit", 100),
                             ("sizelimit", 100), ("target", "11" * 32), ("bits", "207fffff"),
                             ("vbrequired", 0x100), ("coinbaseaux", {"flags": "11" * 100})):
            changed = fixture()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                job(changed)
        gbt = fixture()
        for payouts in ([(SCRIPT, 1)], [(SCRIPT, -1)], [(SCRIPT, True)],
                        [(SCRIPT, 2500000100), (SCRIPT, 2500000100)]):
            with self.subTest(payouts=payouts), self.assertRaises(ValueError):
                build_template(gbt, payouts, b"r" * 32, b"test")

    def test_bad_sia_lengths_and_whitespace_rejected(self):
        for kwargs in ({"prefix": b"short"}, {"extranonce2": bytes(7)}, {"ntime": "00"},
                       {"nonce": "zz" * 8}, {"nonce": "00 00000"}, {"nonce": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                proof(**kwargs)


if __name__ == "__main__":
    unittest.main()
