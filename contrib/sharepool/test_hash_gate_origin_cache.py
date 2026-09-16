#!/usr/bin/env python3
"""Origin parsing reuse preserves exact full jobs, native verdicts and ACKs."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hash_gate_origin_cache import OriginFactsCache
from hash_mining_gate import HashMiningGate, SNAPSHOT, TEMPLATE, PROOF
from hash_snapshot import job_hash, solve_share, rules_hash
from native_mining_gate import immutable_header, parse_block, template_id
from test_framework.messages import CTxInWitness
from test_hash_compact import CompactRPC, compact_fixture
from test_hash_snapshot import SCRIPT
from test_hash_variable import variable_fixture


class AssignedRPC(CompactRPC):
    """Control-flow double only; native integration verifies actual validity."""
    def __call__(self, method, *args):
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            result.update(mode="hash-only-v8-vardiff-tides", rules=f"{rules_hash(8):064x}")
        return result


class OriginFactsTests(unittest.TestCase):
    def test_repeated_full_bytes_reuse_only_immutable_metadata(self):
        block, _ = compact_fixture()
        raw = block.serialize()
        cache = OriginFactsCache()
        with patch("hash_gate_origin_cache.parse_block", wraps=parse_block) as parse:
            first = cache.describe(raw, 7)
            again = cache.describe(bytes(bytearray(raw)), 7)
            self.assertIs(first, again)
            self.assertEqual(parse.call_count, 1)
        self.assertEqual(first, (immutable_header(block), job_hash(block)))
        self.assertEqual(cache.stats()["hits"], 1)
        self.assertLess(cache.stats()["bytes"], 2048)
        with self.assertRaises(AttributeError):
            first.job_commitment = 0
        self.assertNotIn(raw, next(iter(cache._entries)))

    def test_equal_header_and_length_witness_variants_never_share_job_facts(self):
        block, _ = compact_fixture()
        block.vtx[0].wit.vtxinwit = [CTxInWitness()]
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"x" * 32]
        a = block.serialize()
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"y" * 32]
        b = block.serialize()
        self.assertEqual(len(a), len(b))
        cache = OriginFactsCache()
        left, right = cache.describe(a, 7), cache.describe(b, 7)
        self.assertEqual(left.header, right.header)
        self.assertNotEqual(left.job_commitment, right.job_commitment)
        self.assertEqual(cache.stats()["entries"], 2)
        cache.describe(a, 8)
        self.assertEqual(cache.stats()["misses"], 3)

    def test_byte_entry_disable_and_input_bounds(self):
        first, _ = compact_fixture()
        second, _ = compact_fixture(ntime=1700000002)
        cache = OriginFactsCache(max_entries=1)
        expected = cache.describe(first.serialize(), 7)
        charge = cache.stats()["bytes"]
        cache.describe(second.serialize(), 7)
        self.assertEqual(cache.stats()["entries"], 1)
        self.assertEqual(cache.describe(first.serialize(), 7), expected)
        self.assertEqual(cache.stats()["misses"], 3)
        byte_limited = OriginFactsCache(max_bytes=charge + 128, max_entries=8)
        byte_limited.describe(first.serialize(), 7)
        byte_limited.describe(second.serialize(), 7)
        self.assertEqual(byte_limited.stats()["entries"], 1)
        self.assertLessEqual(byte_limited.stats()["bytes"], charge + 128)
        self.assertEqual(byte_limited.describe(first.serialize(), 7), expected)
        self.assertEqual(byte_limited.stats()["misses"], 3)
        for options in ({"max_entries": 0}, {"max_bytes": charge - 1}):
            disabled = OriginFactsCache(**options)
            self.assertEqual(disabled.describe(first.serialize(), 7), expected)
            self.assertEqual(disabled.describe(first.serialize(), 7), expected)
            self.assertEqual(disabled.stats()["entries"], 0)
            self.assertEqual(disabled.stats()["oversized"], 2)
        for value in (b"", bytearray(first.serialize()), b"x" * 4_000_001, first.serialize() + b"\0"):
            with self.assertRaises(ValueError):
                cache.describe(value, 7)
        for version in (True, 7.0, 9):
            with self.assertRaises(ValueError):
                cache.describe(first.serialize(), version)
        for options in ({"max_bytes": -1}, {"max_entries": True}):
            with self.assertRaises(ValueError):
                OriginFactsCache(**options)
        cache.clear()
        self.assertEqual(cache.stats(), {"entries": 0, "bytes": 0, "hits": 0, "misses": 0, "oversized": 0})


class GateOriginReuseTests(unittest.TestCase):
    @contextmanager
    def gate(self, version=7):
        block, opening = variable_fixture(share_work_bits=2) if version == 8 else compact_fixture()
        rpc = AssignedRPC() if version == 8 else CompactRPC()
        with tempfile.TemporaryDirectory(prefix="origin-facts-") as directory:
            gate = HashMiningGate(Path(directory) / "gate.sqlite", rpc=rpc, pool=3,
                public_key=opening.envelope.public_key, payout_script=SCRIPT, profile_version=version,
                **({"share_work_bits": 2} if version == 8 else {}))
            try:
                rpc.gate = gate
                gate.register_snapshot(opening.serialize())
                gate.register_template(block.serialize())
                gate._native_template(block.serialize(), rpc.tip, mining=False)
                rpc.calls.clear()
                yield gate, rpc, block, opening, solve_share(block, opening)
            finally:
                gate.close()

    def test_warm_proofs_read_current_evidence_and_get_fresh_native_verdicts(self):
        for version in (7, 8):
            with self.subTest(version=version), self.gate(version) as (gate, rpc, block, _, proof):
                with patch.object(gate, "_read", wraps=gate._read) as read, \
                        patch("hash_gate_origin_cache.parse_block", wraps=parse_block) as parse:
                    gate._native_share(proof, rpc.tip)
                    gate._native_share(proof, rpc.tip)
                    self.assertEqual(parse.call_count, 1)
                    self.assertEqual([call.args[0] for call in read.call_args_list], [TEMPLATE, SNAPSHOT] * 2)
                self.assertEqual(sum(name == "validatesharepoolhashshare" for name, _ in rpc.calls), 2)
                self.assertEqual(gate._origin_facts_cache.stats()["hits"], 1)
                self.assertEqual(gate.archive_head()["receipt_revision"], 0)
                rpc.share_error = "native proof refused"
                before = gate.archive_head()
                with self.assertRaisesRegex(ValueError, "native proof refused"):
                    gate.receive(proof)
                self.assertEqual(gate.archive_head(), before)
                with self.assertRaises(KeyError):
                    gate._read(PROOF, f"{proof.proof_id:064x}")

    def test_warm_cache_cannot_hide_assignment_signature_or_witness_relabelling(self):
        with self.gate(8) as (gate, rpc, block, opening, proof):
            gate._native_share(proof, rpc.tip)
            before = gate.archive_head()
            for changed in (replace(proof, owner_signature=b"x" * 64),
                            replace(proof, envelope=replace(proof.envelope, share_work_bits=3))):
                with self.assertRaisesRegex(ValueError, "full origin snapshot"):
                    gate.receive(changed)
                self.assertEqual(gate.archive_head(), before)
            changed = parse_block(block.serialize())
            changed.vtx[0].wit.vtxinwit = [CTxInWitness()]
            changed.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"x" * 32]
            staged = {(TEMPLATE, template_id(block)): changed.serialize(),
                      (SNAPSHOT, opening.hash_hex): opening.serialize()}
            rpc.calls.clear()
            with self.assertRaisesRegex(ValueError, "exact committed job"):
                gate._native_share(proof, rpc.tip, staged)
            self.assertFalse(any(name == "validatesharepoolhashshare" for name, _ in rpc.calls))

    def test_cold_evidence_disappearance_fails_even_with_warm_facts(self):
        with self.gate() as (gate, rpc, _, _, proof):
            segment = gate.path.parent / "cold.spharc"
            gate.rotate_archive(segment)
            gate._native_share(proof, rpc.tip)
            segment.unlink()
            rpc.calls.clear()
            with self.assertRaisesRegex(ValueError, "cold archive data is unavailable"):
                gate._native_share(proof, rpc.tip)
            self.assertFalse(any(name == "validatesharepoolhashshare" for name, _ in rpc.calls))

    def test_cache_disabled_and_enabled_admit_identical_exact_receipt(self):
        receipts = []
        for enabled in (False, True):
            with self.gate(8) as (gate, rpc, _, _, proof):
                gate._origin_facts_cache = OriginFactsCache(max_entries=1024 if enabled else 0)
                self.assertTrue(gate.receive(proof))
                self.assertFalse(gate.receive(proof))
                receipts.append((gate.archive_head(), gate._read(PROOF, f"{proof.proof_id:064x}")))
                self.assertEqual(gate.archive_head()["receipt_revision"], 1)
                self.assertEqual(gate._origin_facts_cache.stats()["hits"] > 0, enabled)
                gate.close()
                self.assertEqual(gate._origin_facts_cache.stats()["entries"], 0)
        self.assertEqual(receipts[0], receipts[1])


if __name__ == "__main__":
    unittest.main()
