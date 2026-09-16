#!/usr/bin/env python3
"""Decode-cache bounds and mutation isolation; native validity is separate."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from hash_gate_cache import SnapshotDecodeCache, _retained_size
from hash_snapshot import Snapshot, solve_share
from test_framework.messages import CTxOut
from test_framework.script import CScript
from test_hash_compact import compact_fixture
from test_hash_snapshot import fixture
from test_hash_tides import codec_fixture


class SnapshotDecodeCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block, cls.opening = compact_fixture()
        proofs, nonce = [], 0
        for _ in range(4):
            proof = solve_share(cls.block, cls.opening, start_nonce=nonce)
            proofs.append(proof)
            nonce = proof.header.nNonce + 1
        cls.snapshots = [cls.opening]
        for count in (1, 2, 4):
            _, snapshot = compact_fixture(templates=(cls.block,), shares=proofs[:count], ntime=1700000010 + count)
            cls.snapshots.append(snapshot)
        cls.raw = [value.serialize() for value in cls.snapshots]

    def test_reuse_clones_mutable_payouts_and_keeps_wire_state(self):
        cache = SnapshotDecodeCache()
        with patch.object(Snapshot, "deserialize", wraps=Snapshot.deserialize) as decode:
            first = cache.decode(self.raw[2], 7)
            original_amount = first.payouts[0].nValue
            original_script = bytes(first.payouts[0].scriptPubKey)
            first.payouts[0].nValue += 1
            first.payouts[0].scriptPubKey = CScript(b"\x51")
            second = cache.decode(self.raw[2], 7)
            self.assertEqual(decode.call_count, 1)
            self.assertIsNot(first, second)
            self.assertIsNot(first.payouts[0], second.payouts[0])
            self.assertEqual(second.payouts[0].nValue, original_amount)
            self.assertEqual(bytes(second.payouts[0].scriptPubKey), original_script)
            self.assertIs(first.envelope, second.envelope)
            self.assertIs(first.shares, second.shares)
            self.assertEqual((second.post_state, second.certificates), ((), ()))
            self.assertEqual(second.serialize(), self.raw[2])

    def test_changed_bytes_and_wrong_profile_cannot_hit(self):
        cache = SnapshotDecodeCache()
        first = cache.decode(self.raw[0], 7)
        changed = replace(first, payouts=(CTxOut(first.payouts[0].nValue - 1,
                                               CScript(bytes(first.payouts[0].scriptPubKey))),))
        raw = changed.serialize()
        self.assertNotEqual(raw, self.raw[0])
        self.assertEqual(cache.decode(raw, 7).serialize(), raw)
        with self.assertRaisesRegex(ValueError, "profile differs"):
            cache.decode(self.raw[0], 6)
        self.assertEqual(cache.stats()["entries"], 2)
        self.assertEqual(cache.stats()["hits"], 0)
        for invalid in (self.raw[0] + b"x", b"", bytearray(self.raw[0])):
            with self.assertRaises(ValueError):
                cache.decode(invalid, 7)
        self.assertEqual(cache.stats()["entries"], 2)

    def test_lru_eviction(self):
        cache = SnapshotDecodeCache(max_entries=2)
        with patch.object(Snapshot, "deserialize", wraps=Snapshot.deserialize) as decode:
            for index in (0, 1, 0, 2, 0):
                cache.decode(self.raw[index], 7)
            self.assertEqual(decode.call_count, 3)
            cache.decode(self.raw[1], 7)
            self.assertEqual(decode.call_count, 4)
        self.assertEqual(cache.stats()["entries"], 2)

    def test_decoded_memory_not_only_compact_wire_is_charged(self):
        measured = SnapshotDecodeCache()
        measured.decode(self.raw[3], 7)
        charge = measured.stats()["bytes"]
        self.assertGreater(charge, len(self.raw[3]))
        cache = SnapshotDecodeCache(max_bytes=charge - 1)
        with patch.object(Snapshot, "deserialize", wraps=Snapshot.deserialize) as decode:
            self.assertEqual(cache.decode(self.raw[3], 7).serialize(), self.raw[3])
            cache.decode(self.raw[3], 7)
            self.assertEqual(decode.call_count, 2)
        self.assertEqual(cache.stats()["entries"], 0)
        self.assertEqual(cache.stats()["bytes"], 0)
        self.assertEqual(cache.stats()["oversized"], 2)

    def test_share_limit_eviction_and_oversize_preserve_other_entries(self):
        cache = SnapshotDecodeCache(max_shares=3)
        cache.decode(self.raw[1], 7)
        cache.decode(self.raw[2], 7)
        self.assertEqual(cache.stats()["shares"], 3)
        cache.decode(self.raw[3], 7)
        self.assertEqual(cache.stats()["entries"], 2)
        self.assertEqual(cache.stats()["shares"], 3)
        # Another two-proof snapshot needs eviction even with ample byte space.
        alternate = replace(self.snapshots[2], job_commitment=self.snapshots[2].job_commitment ^ 1).serialize()
        cache.decode(alternate, 7)
        self.assertEqual(cache.stats()["entries"], 1)
        self.assertEqual(cache.stats()["shares"], 2)
        self.assertLessEqual(cache.stats()["bytes"], cache.max_bytes)

    def test_memory_limit_eviction_and_shared_object_accounting(self):
        measured = SnapshotDecodeCache()
        measured.decode(self.raw[0], 7)
        first_charge = measured.stats()["bytes"]
        measured.clear()
        measured.decode(self.raw[1], 7)
        second_charge = measured.stats()["bytes"]
        cache = SnapshotDecodeCache(max_bytes=max(first_charge, second_charge))
        cache.decode(self.raw[0], 7)
        cache.decode(self.raw[1], 7)
        self.assertEqual(cache.stats()["entries"], 1)
        self.assertLessEqual(cache.stats()["bytes"], cache.max_bytes)
        shared = b"a" * 4096
        separate = bytes(bytearray(shared))
        self.assertIsNot(shared, separate)
        self.assertLess(_retained_size((shared, shared)), _retained_size((shared, separate)))

    def test_existing_profiles_roundtrip_with_isolated_outputs(self):
        cache = SnapshotDecodeCache()
        for version, builder in ((4, fixture), (5, lambda: fixture(version=5)), (6, codec_fixture)):
            _, value = builder()
            raw = value.serialize()
            first = cache.decode(raw, version)
            second = cache.decode(raw, version)
            self.assertEqual(second.serialize(), raw)
            self.assertIsNot(first.payouts[0], second.payouts[0])
        self.assertEqual(cache.stats()["entries"], 3)

    def test_clear_disable_and_invalid_budget(self):
        cache = SnapshotDecodeCache()
        cache.decode(self.raw[1], 7)
        cache.clear()
        self.assertEqual(cache.stats(), dict(entries=0, bytes=0, shares=0, hits=0, misses=0, oversized=0))
        for options in ({"max_entries": 0}, {"max_bytes": 0}, {"max_shares": 0}):
            disabled = SnapshotDecodeCache(**options)
            self.assertEqual(disabled.decode(self.raw[1], 7).serialize(), self.raw[1])
            self.assertEqual(disabled.stats()["entries"], 0)
        for options in ({"max_bytes": -1}, {"max_shares": True}, {"max_entries": 1.5}):
            with self.assertRaises(ValueError):
                SnapshotDecodeCache(**options)
        for version in (True, 3, "7"):
            with self.assertRaises(ValueError):
                cache.decode(self.raw[0], version)


if __name__ == "__main__":
    unittest.main()
