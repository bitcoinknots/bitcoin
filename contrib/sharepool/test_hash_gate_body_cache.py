#!/usr/bin/env python3
"""Repeated bodies reuse decoding while evidence and native checks stay fresh."""
import unittest
from unittest.mock import patch

from hash_gate_body_cache import OriginBodyCache
from hash_mining_gate import TEMPLATE, PROOF
from hash_snapshot import CompactTemplateRecord, TemplateRecord, solve_share
from native_mining_gate import parse_block, template_id
from test_framework.messages import CTxInWitness
from test_hash_compact import compact_fixture
import test_hash_gate_origin_cache as origin_tests


class OriginBodyCacheTests(unittest.TestCase):
    def test_exact_body_reuses_canonical_record(self):
        block, _ = compact_fixture()
        raw, cache = block.serialize(), OriginBodyCache()
        with patch("hash_gate_body_cache.parse_block", wraps=parse_block) as decode:
            first = cache.capture(raw, 7)
            again = cache.capture(bytes(bytearray(raw)), 7)
        self.assertIs(first, again)
        self.assertEqual(decode.call_count, 1)
        expected = CompactTemplateRecord.from_record(TemplateRecord.from_block(raw))
        self.assertEqual(first.serialize(), expected.serialize())
        with self.assertRaises(AttributeError):
            first.header_bytes = b"changed"
        with self.assertRaises(AttributeError):
            first.transactions[0].raw = b"changed"

    def test_witness_profile_and_transaction_changes_do_not_hit(self):
        block, _ = compact_fixture()
        block.vtx[0].wit.vtxinwit = [CTxInWitness()]
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"x" * 32]
        a = block.serialize()
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"y" * 32]
        b = block.serialize()
        cache = OriginBodyCache()
        left, right = cache.capture(a, 7), cache.capture(b, 7)
        self.assertEqual(left.header_bytes, right.header_bytes)
        self.assertNotEqual(left.data, right.data)
        cache.capture(a, 8)
        self.assertEqual(cache.stats()["misses"], 3)

    def test_malformed_or_unnormalized_body_cannot_populate_cache(self):
        block, _ = compact_fixture()
        raw, cache = block.serialize(), OriginBodyCache()
        cache.capture(raw, 7)
        bad = [b"", raw + b"\0", bytearray(raw), b"x" * 4_000_001]
        for field in ("nNonce", "m_nonce2", "m_nonce3", "m_time_offset", "m_extranonce",
                      "hashMerkleRoot", "m_txcount"):
            changed = parse_block(raw)
            setattr(changed, field, getattr(changed, field) + 1)
            bad.append(changed.serialize())
        for encoded in bad:
            with self.subTest(size=len(encoded)), self.assertRaises(ValueError):
                cache.capture(encoded, 7)
        self.assertEqual(cache.stats()["entries"], 1)
        for version in (True, 7.0, 9):
            with self.assertRaises(ValueError):
                cache.capture(raw, version)

    def test_lru_charged_bound_and_disabled_results(self):
        a, _ = compact_fixture()
        b, _ = compact_fixture(ntime=1700000040)
        cache = OriginBodyCache(max_entries=1)
        first = cache.capture(a.serialize(), 7)
        charge = cache.stats()["bytes"]
        cache.capture(b.serialize(), 7)
        self.assertEqual(cache.stats()["entries"], 1)
        self.assertEqual(cache.capture(a.serialize(), 7).data, first.data)
        self.assertEqual(cache.stats()["misses"], 3)
        for options in ({"max_entries": 0}, {"max_bytes": charge - 1}):
            small = OriginBodyCache(**options)
            for _ in range(2):
                self.assertEqual(small.capture(a.serialize(), 7).data, first.data)
            self.assertEqual(small.stats()["entries"], 0)
            self.assertEqual(small.stats()["oversized"], 2)
        bounded = OriginBodyCache(max_bytes=charge + 128)
        bounded.capture(a.serialize(), 7)
        bounded.capture(b.serialize(), 7)
        self.assertLessEqual(bounded.stats()["bytes"], charge + 128)
        self.assertEqual(bounded.stats()["entries"], 1)
        cache.clear()
        self.assertEqual(cache.stats()["bytes"], 0)


class GateBodyReuseTests(unittest.TestCase):
    gate = origin_tests.GateOriginReuseTests.gate

    def test_repeated_shares_decode_origin_once_with_fresh_native_verdicts(self):
        with self.gate(7) as (gate, rpc, block, opening, _):
            with patch("hash_gate_body_cache.parse_block", wraps=parse_block) as decode:
                nonce = 0
                for _ in range(4):
                    proof = solve_share(block, opening, start_nonce=nonce)
                    nonce = proof.header.nNonce + 1
                    with patch.object(gate, "_read", wraps=gate._read) as read:
                        self.assertTrue(gate.receive(proof))
                    # One initial authenticated body and one durable equality
                    # check. Provenance/native binding share the operation's bytes.
                    self.assertEqual(sum(c.args[0] == TEMPLATE for c in read.call_args_list), 2)
            self.assertEqual(decode.call_count, 1)
            self.assertEqual(gate._origin_body_cache.stats()["hits"], 3)
            self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in rpc.calls), 4)
            self.assertEqual(gate.archive_head()["receipt_revision"], 4)

    def test_corrupt_body_between_requests_cannot_use_warm_decode(self):
        with self.gate(7) as (gate, rpc, block, opening, proof):
            self.assertTrue(gate.receive(proof))
            next_proof = solve_share(block, opening, start_nonce=proof.header.nNonce + 1)
            before = gate.archive_head()
            with gate.db:
                gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=? AND identity=?",
                                (TEMPLATE, template_id(block)))
            rpc.calls.clear()
            with self.assertRaisesRegex(ValueError, "read-time integrity"):
                gate.receive(next_proof)
            self.assertEqual(gate.archive_head(), before)
            self.assertFalse(any(name == "validatesharepoolhashshare" for name, _ in rpc.calls))

    def test_body_changed_during_native_rpc_cannot_be_acknowledged(self):
        with self.gate(7) as (gate, rpc, block, _, proof):
            before = gate.archive_head()
            def changing(method, *args):
                result = rpc(method, *args)
                if method == "validatesharepoolhashshare":
                    with gate.db:
                        gate.db.execute("UPDATE journal SET data=zeroblob(length(data)) WHERE kind=? AND identity=?",
                                        (TEMPLATE, template_id(block)))
                return result
            gate.rpc = changing
            with self.assertRaisesRegex(ValueError, "read-time integrity"):
                gate.receive(proof)
            self.assertEqual(gate.archive_head(), before)
            with self.assertRaises(KeyError):
                gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_cache_disable_preserves_receipts_and_native_refusal(self):
        receipts = []
        for enabled in (True, False):
            with self.gate(8) as (gate, rpc, block, opening, proof):
                gate._origin_body_cache = OriginBodyCache(max_entries=32 if enabled else 0)
                self.assertTrue(gate.receive(proof))
                self.assertFalse(gate.receive(proof))
                receipts.append((gate.archive_head(), gate._read(PROOF, f"{proof.proof_id:064x}")))
                rpc.share_error = "fresh native refusal"
                with self.assertRaisesRegex(ValueError, "fresh native refusal"):
                    gate.receive(solve_share(block, opening, start_nonce=proof.header.nNonce + 1))
                self.assertEqual(gate.archive_head(), receipts[-1][0])
                gate.close()
                self.assertEqual(gate._origin_body_cache.stats()["entries"], 0)
        self.assertEqual(receipts[0], receipts[1])


if __name__ == "__main__":
    unittest.main()
