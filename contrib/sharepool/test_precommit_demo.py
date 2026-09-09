#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests of the synthetic commitment experiment, not node acceptance tests."""

from dataclasses import FrozenInstanceError
import hashlib
from io import BytesIO
import itertools
import json
import unittest

from precommit_demo import (
    CBlockHeader,
    DOMAIN,
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    REPO_ROOT,
    SYNTHETIC_CONTEXT,
    Snapshot,
    make_header,
    meets_synthetic_target,
    run_demo,
    solve_header,
    uint256_from_compact,
)


class SnapshotTest(unittest.TestCase):
    def test_order_independent_and_duplicate_rejected(self):
        records = [b"A", b"B", b"C"]
        roots = {Snapshot(SYNTHETIC_CONTEXT, order).root
                 for order in itertools.permutations(records)}
        self.assertEqual(len(roots), 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            Snapshot(SYNTHETIC_CONTEXT, [b"A", b"B", bytearray(b"A")])

    def test_snapshot_is_copied_and_frozen(self):
        mutable_record = bytearray(b"A")
        mutable_context = bytearray(SYNTHETIC_CONTEXT)
        source = [mutable_record, b"B"]
        snapshot = Snapshot(mutable_context, source)
        original_root = snapshot.root
        mutable_record[:] = b"Z"
        mutable_context[0] ^= 1
        source.append(b"C")
        self.assertEqual(snapshot.records, (b"A", b"B"))
        self.assertEqual(snapshot.context, SYNTHETIC_CONTEXT)
        self.assertEqual(snapshot.root, original_root)
        with self.assertRaises(FrozenInstanceError):
            snapshot.records = ()

    def test_root_count_context_and_leaf_boundary_binding(self):
        # Independent single-leaf formula verifies count/context framing.
        leaf = hashlib.sha256(DOMAIN + b"\x00" + (1).to_bytes(4, "big") + b"A").digest()
        expected = hashlib.sha256(DOMAIN + b"\x03" + SYNTHETIC_CONTEXT + (1).to_bytes(8, "big") + leaf).digest()
        self.assertEqual(Snapshot(SYNTHETIC_CONTEXT, [b"A"]).root, expected)
        wrong_count = hashlib.sha256(DOMAIN + b"\x03" + SYNTHETIC_CONTEXT + (2).to_bytes(8, "big") + leaf).digest()
        self.assertNotEqual(expected, wrong_count)
        self.assertNotEqual(expected, Snapshot(bytes(32), [b"A"]).root)
        self.assertNotEqual(Snapshot(SYNTHETIC_CONTEXT, [b"A", b"BC"]).root,
                            Snapshot(SYNTHETIC_CONTEXT, [b"AB", b"C"]).root)
        self.assertNotEqual(Snapshot(SYNTHETIC_CONTEXT, []).root, expected)

    def test_input_bounds(self):
        for context in [b"short", "x" * 32]:
            with self.assertRaises(ValueError):
                Snapshot(context, [])
        for records in [[b""], [b"x" * (MAX_RECORD_BYTES + 1)],
                        [i.to_bytes(4, "big") for i in range(MAX_RECORDS + 1)]]:
            with self.assertRaises(ValueError):
                Snapshot(SYNTHETIC_CONTEXT, records)
        with self.assertRaises(TypeError):
            Snapshot(SYNTHETIC_CONTEXT, ["not bytes"])


class HeaderCommitmentTest(unittest.TestCase):
    def test_upstream_header_v2_hash_vectors(self):
        vector_path = REPO_ROOT / "src" / "test" / "data" / "block_header_v2.json"
        vectors = json.loads(vector_path.read_text(encoding="utf-8"))["headers"]
        self.assertEqual(len(vectors), 5)
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                serialized = bytes.fromhex(vector["serialized"])
                header = CBlockHeader()
                header.deserialize(BytesIO(serialized))
                header.rehash()
                self.assertTrue(header.m_header_v2)
                self.assertEqual(header.serialize(), serialized)
                self.assertEqual(header.hash, vector["block_hash"])

    def test_v2_root_serialization_and_pow_binding(self):
        first = Snapshot(SYNTHETIC_CONTEXT, [b"A", b"B"])
        second = Snapshot(SYNTHETIC_CONTEXT, [b"A", b"B", b"C"])
        header = make_header(first)
        solve_header(header)
        self.assertTrue(header.m_header_v2)
        self.assertEqual(header.serialize()[-32:], first.root)
        self.assertTrue(meets_synthetic_target(header))
        original_hash = header.hash

        restored = CBlockHeader()
        restored.deserialize(BytesIO(header.serialize()))
        self.assertEqual(restored.rehash(), header.rehash())
        self.assertEqual(restored.m_mm_rhs, header.m_mm_rhs)

        changed = CBlockHeader(header)
        changed.m_mm_rhs = int.from_bytes(second.root, "little")
        result = meets_synthetic_target(changed)
        self.assertEqual(changed.nNonce, header.nNonce)
        self.assertNotEqual(changed.hash, original_hash)
        self.assertEqual(result, changed.sha256 <= uint256_from_compact(changed.nBits))
        self.assertEqual(header.hash, original_hash)
        self.assertEqual(header.serialize()[-32:], first.root)

    def test_changed_commitment_can_also_pass_easy_target(self):
        # Exhibit both outcomes at the same nonce; changing a root does NOT
        # logically imply that the newly hashed header fails the target.
        header = make_header(Snapshot(SYNTHETIC_CONTEXT, [b"original"]))
        solve_header(header)
        outcomes = set()
        for i in range(128):
            changed = CBlockHeader(header)
            snapshot = Snapshot(SYNTHETIC_CONTEXT, [b"replacement " + i.to_bytes(2, "big")])
            changed.m_mm_rhs = int.from_bytes(snapshot.root, "little")
            outcomes.add(meets_synthetic_target(changed))
            self.assertNotEqual(changed.hash, header.hash)
            if outcomes == {True, False}:
                break
        self.assertEqual(outcomes, {True, False})

    def test_search_is_bounded(self):
        header = make_header(Snapshot(SYNTHETIC_CONTEXT, []))
        for budget in [0, 100_001]:
            with self.assertRaises(ValueError):
                solve_header(header, budget)
        # Target one cannot be reached by nonce zero for this fixed fixture.
        header.nBits = 0x03000001
        with self.assertRaisesRegex(RuntimeError, "exhausted"):
            solve_header(header, 1)

    def test_demo_reports_limited_scope(self):
        result = run_demo()
        self.assertTrue(result["original_meets_synthetic_target"])
        self.assertTrue(result["hash_changed"])
        self.assertIn("synthetic header only", result["scope"])
        self.assertIn("by chance", result["lesson"])


if __name__ == "__main__":
    unittest.main()
