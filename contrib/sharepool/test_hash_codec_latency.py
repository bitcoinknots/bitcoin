#!/usr/bin/env python3
"""Exact codec invariants and CPU-only serialization microbenchmarks.

The benchmark exercises synthetic signed codec fixtures. It excludes native
validation, networking, scripts, signature verification and fixture creation.
"""
from dataclasses import replace
from pathlib import Path
import argparse
import cProfile
import hashlib
import io
import json
import platform
import pstats
import statistics
import sys
import time
import unittest
from unittest.mock import patch

from hash_snapshot import Snapshot, Share, solve_share
from native_mining_gate import immutable_header, template_id
from test_hash_compact import compact_fixture
from test_hash_snapshot import fixture
from test_hash_tides import codec_fixture
from test_framework.messages import CBlockHeader, BLOCK_HEADER_FLAG_USE_TIME_OFFSET
from test_framework.script import CScript


def workload(jobs, proofs_per_job):
    origins = [compact_fixture(ntime=1700000001 + index, pool=3 + index) for index in range(jobs)]
    proofs = []
    for block, opening in origins:
        for nonce in range(proofs_per_job):
            header = CBlockHeader(block)
            header.nNonce = nonce + 1
            proofs.append(Share(header.serialize(), opening.envelope, opening.owner_signature))
    _, result = compact_fixture(templates=tuple(block for block, unused in origins), shares=tuple(proofs))
    return result


def triplet(value):
    return value.serialize(), value.hash, value.owner_message


class CodecLatencyTests(unittest.TestCase):
    def test_capture_matches_each_profile_and_serializes_once(self):
        for version in (4, 5, 6, 7):
            with self.subTest(version=version):
                builder = compact_fixture if version == 7 else codec_fixture if version == 6 else lambda **kw: fixture(version=version, **kw)
                block, opening = builder()
                _, value = builder(templates=(block,), shares=(solve_share(block, opening),))
                expected = (value.serialize(), value.hash, value.contents_hash, value.signing_payload, value.owner_message)
                original, calls = Snapshot.serialize, []
                def counted(item):
                    calls.append(item)
                    return original(item)
                with patch.object(Snapshot, "serialize", counted):
                    captured = value.capture()
                    for _ in range(3):
                        self.assertEqual((captured.raw, captured.hash, captured.contents_hash,
                            captured.signing_payload, captured.owner_message), expected)
                    self.assertEqual(len(calls), 1)
                self.assertEqual(captured.snapshot.serialize(), expected[0])
                self.assertIs(captured.snapshot, captured.snapshot)
                self.assertIsNot(captured.snapshot, value)
                self.assertTrue(all(hasattr(share, "_header_facts") for share in captured.snapshot.shares))

    def test_capture_detaches_mutable_payouts_and_new_operations_observe_edits(self):
        _, value = compact_fixture()
        captured = value.capture()
        original = captured.raw, captured.hash, captured.owner_message
        first = captured.snapshot
        old_amount = first.payouts[0].nValue
        value.payouts[0].nValue -= 1
        value.payouts[0].scriptPubKey = CScript(b"\x00\x14" + b"z" * 20)
        changed = value.capture()
        self.assertNotEqual(changed.raw, original[0])
        self.assertNotEqual(changed.hash, original[1])
        self.assertNotEqual(changed.owner_message, original[2])
        self.assertEqual((captured.raw, captured.hash, captured.owner_message), original)
        self.assertEqual(first.payouts[0].nValue, old_amount)
        self.assertEqual(first.serialize(), original[0])
        with self.assertRaises(AttributeError):
            first.payouts[0].nValue = 1
        with self.assertRaises(AttributeError):
            captured.raw = changed.raw
        value.payouts[0].nValue = -1
        with self.assertRaisesRegex(ValueError, "money range"):
            value.capture()
        with self.assertRaisesRegex(ValueError, "money range"):
            value.hash

    def test_capture_isolated_before_lazy_decode(self):
        _, value = compact_fixture()
        captured = value.capture()
        old_amount = value.payouts[0].nValue
        value.payouts[0].nValue -= 1
        self.assertEqual(captured.snapshot.payouts[0].nValue, old_amount)
        self.assertEqual(captured.snapshot.serialize(), captured.raw)

    def test_header_facts_preserve_exact_physical_fields_and_offset_semantics(self):
        block, opening = compact_fixture()
        for flags in (0, BLOCK_HEADER_FLAG_USE_TIME_OFFSET):
            for offset in (0, 1, 0xffffffff):
                header = CBlockHeader(block)
                header.nNonce, header.m_nonce2, header.m_nonce3 = 17, 0xffffffff, 91
                header.m_extranonce, header.m_time_offset, header.m_flags = 1 << 127, offset, flags
                share = Share(header.serialize(), opening.envelope, opening.owner_signature)
                reference = share.header
                facts = share.header_facts
                self.assertEqual(facts.proof_id, reference.rehash())
                self.assertEqual(facts.template_id, int(template_id(reference), 16))
                self.assertEqual(facts.immutable_header, immutable_header(reference))
                self.assertEqual(facts.native_bits, reference.nBits)
                self.assertEqual(facts.height, reference.m_height)
                self.assertEqual(facts.native_parent, reference.hashPrevBlock)
                self.assertIs(facts, share.header_facts)
                with patch.object(CBlockHeader, "rehash", side_effect=AssertionError("rehashed immutable proof")):
                    self.assertEqual(share.proof_id, facts.proof_id)
                mutable = share.header
                mutable.nNonce += 1
                self.assertEqual(share.header_facts, facts)
                self.assertEqual(share.header.nNonce, 17)

    def test_replaced_or_mutable_header_bytes_never_reuse_stale_facts(self):
        block, opening = compact_fixture()
        share = Share(CBlockHeader(block).serialize(), opening.envelope, opening.owner_signature)
        first = share.header_facts
        changed = share.header
        changed.nNonce += 1
        replaced = replace(share, header_bytes=changed.serialize())
        self.assertNotEqual(replaced.proof_id, first.proof_id)
        self.assertEqual(replaced.header_facts.immutable_header, first.immutable_header)
        # Even bypassing a frozen dataclass assignment cannot reuse stale facts.
        object.__setattr__(share, "header_bytes", changed.serialize())
        self.assertEqual(share.proof_id, replaced.proof_id)
        object.__setattr__(share, "header_bytes", changed.serialize() + b"\0")
        with self.assertRaises(ValueError):
            share.proof_id
        raw = bytearray(replaced.header_bytes)
        mutable = replace(replaced, header_bytes=raw)
        identity = mutable.proof_id
        raw[76] ^= 1
        self.assertNotEqual(mutable.proof_id, identity)
        self.assertFalse(hasattr(mutable, "_header_facts"))

    def test_memoized_proofs_do_not_skip_current_descriptor_or_resource_checks(self):
        value = workload(1, 2)
        first = value.capture()
        proof = value.shares[0]
        changed = replace(value, shares=(proof, replace(value.shares[1], owner_signature=b"x" * 64)))
        with self.assertRaisesRegex(ValueError, "inconsistent compact job"):
            changed.capture()
        with patch("hash_snapshot.MAX_COMPACT_SHARES", 1):
            with self.assertRaisesRegex(ValueError, "original work bound"):
                value.capture()
        with patch("hash_snapshot.MAX_SNAPSHOT_BYTES", len(first.raw) - 1):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                value.capture()
        # A later operation revalidates even forcibly changed envelope fields.
        object.__setattr__(proof.envelope, "payout_script", b"invalid")
        with self.assertRaisesRegex(ValueError, "envelope"):
            value.capture()


def benchmark(output, label, repeats=3):
    rows = []
    for jobs, count in ((1, 1024), (16, 64)):
        value = workload(jobs, count)
        expected = triplet(value)
        profiles = cProfile.Profile()
        profiles.enable()
        assert triplet(value) == expected
        profiles.disable()
        profile_text = io.StringIO()
        pstats.Stats(profiles, stream=profile_text).sort_stats("cumtime").print_stats(18)
        modes = {"serialize_hash_owner": lambda: triplet(value)}
        if hasattr(value, "capture"):
            def captured():
                capture = value.capture()
                return capture.raw, capture.hash, capture.owner_message
            modes["one_operation_capture"] = captured
        timings = {}
        for name, operation in modes.items():
            samples = []
            for _ in range(repeats):
                wall, cpu = time.perf_counter(), time.process_time()
                observed = operation()
                samples.append({"cpu_seconds": time.process_time() - cpu, "wall_seconds": time.perf_counter() - wall})
                assert observed == expected
            timings[name] = {"samples": samples, "median_cpu_seconds": statistics.median(sample["cpu_seconds"] for sample in samples)}
        rows.append({"jobs": jobs, "shares": jobs * count, "encoded_bytes": len(expected[0]),
                     "raw_sha256": hashlib.sha256(expected[0]).hexdigest(), "snapshot_hash": f"{expected[1]:064x}",
                     "owner_message": expected[2].hex(), "timings": timings, "profile": profile_text.getvalue()})
    report = {"label": label, "scope": "CPU serialization and hashing only; no native validation or throughput claim",
              "python": platform.python_version(), "platform": platform.platform(), "repeats": repeats,
              "codec_sha256": hashlib.sha256(Path(__file__).with_name("hash_snapshot.py").read_bytes()).hexdigest(),
              "workloads": rows}
    Path(output).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    if "--benchmark" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--benchmark", required=True)
        parser.add_argument("--label", required=True)
        parser.add_argument("--repeats", type=int, default=3)
        args = parser.parse_args()
        benchmark(args.benchmark, args.label, args.repeats)
    else:
        unittest.main()
