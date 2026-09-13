#!/usr/bin/env python3
"""Independent v7 codec, bounded state and gate tests; native validity is separate."""
from dataclasses import replace
from pathlib import Path
import hashlib
import struct
import tempfile
import unittest
import weakref
from unittest.mock import patch
from hash_snapshot import (Snapshot, Share, Reader, EnvelopeV2, TemplateRecord, COMPACT_TIDES_VERSION,
    COMPACT_TIDES_RULES_HASH, MAX_SHARE_AGE, MAX_COMPACT_SHARES, build_snapshot,
    attest, solve_share, materialize_compact_state, rules_hash, profile_snapshot_hash, candidate)
from hash_gate_batch import check_graph, BatchLimit, NATIVE_STATE_CACHE_ENTRIES
from hash_mining_gate import HashMiningGate
from native_enforcement import compact_size, h256, sign_schnorr
from test_framework.messages import CBlockHeader, ser_uint256
from test_hash_snapshot import fixture, SECRET, SCRIPT
from test_hash_tides import TidesRPC, codec_fixture


def compact_fixture(*, parent_snapshot=None, templates=(), shares=(), **options):
    block, base = fixture(**options)
    proposal = build_snapshot(genesis=base.envelope.genesis, height=base.envelope.height,
        native_parent=base.envelope.native_parent, pool=base.envelope.pool,
        payout_script=base.envelope.payout_script, reward=0, secret=options.get("secret", SECRET),
        version=7, templates=templates, shares=shares, parent_snapshot=parent_snapshot)
    return block, attest(block, replace(proposal, payouts=base.payouts), secret=options.get("secret", SECRET))


def dictionary_offset(raw):
    reader = Reader(raw)
    EnvelopeV2.read(reader)
    reader.take(96)
    for _ in range(reader.size(16 * 1024 * 1024)):
        reader.variable(16 * 1024 * 1024)
    for _ in range(reader.size(16 * 1024 * 1024)):
        reader.take(196)
        for _ in range(reader.size(16 * 1024 * 1024)):
            reader.size(16 * 1024 * 1024)
    return reader.stream.tell()


class CompactSnapshotTests(unittest.TestCase):
    def test_existing_signed_v4_v5_v6_wire_vectors_are_unchanged(self):
        # Recorded from the pre-v7 88d4ab0 codec, including one full proof.
        expected = {
            4: (1247, "9261dc22e830cab38ffa47235ceba64b7498e0f8b8ee7f21046a388961c7b396"),
            5: (1449, "465749304435aceb1f4bb8eebc4c3d4e1ad5aa74aed141a37dfd047a853d3cb3"),
            6: (1380, "4b218b30094a9f4630b512025e7f831a4a06516a57bd7cfe21651ebb9686fcda"),
        }
        for version, vector in expected.items():
            builder = codec_fixture if version == 6 else lambda **options: fixture(version=version, **options)
            block, origin = builder()
            proof = solve_share(block, origin)
            _, settlement = builder(templates=(block,), shares=(proof,))
            raw = settlement.serialize()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), vector)

    def test_empty_wire_and_separate_domains(self):
        _, value = compact_fixture()
        expected = (value.envelope.serialize() + value.owner_signature + ser_uint256(value.job_commitment) +
                    b"\0\0\0\0" + compact_size(len(value.payouts)) +
                    b"".join(output.serialize() for output in value.payouts) + ser_uint256(value.history_head))
        self.assertEqual(value.serialize(), expected)
        self.assertEqual(value.hash, h256(b"SharePool/snapshot/v7\0", expected))
        self.assertEqual(Snapshot.deserialize(expected).serialize(), expected)
        self.assertNotEqual(COMPACT_TIDES_RULES_HASH, rules_hash(6))
        for raw in (b"", b"\x05garbage", b"\x07garbage"):
            self.assertEqual(profile_snapshot_hash(raw, 7), h256(b"SharePool/snapshot/v7\0", raw))
        with self.assertRaisesRegex(ValueError, "native history-aware builder"):
            candidate(genesis=1, native_parent=1, height=1, ntime=1, pool=1, payout_script=SCRIPT, secret=SECRET, version=7)

    def test_dictionary_reconstructs_exact_proof_and_all_search_fields(self):
        a, sa = compact_fixture()
        b, sb = compact_fixture(pool=8, ntime=1700000002)
        proofs = []
        for index, (block, origin) in enumerate(((a, sa), (a, sa), (b, sb))):
            header = CBlockHeader(block)
            header.nNonce, header.m_nonce2, header.m_nonce3 = index + 1, index + 2, index + 3
            header.m_extranonce, header.m_time_offset = (1 << 127) + index, index + 4
            proofs.append(Share(header.serialize(), origin.envelope, origin.owner_signature))
        _, value = compact_fixture(templates=(a, b), shares=proofs)
        raw, decoded = value.serialize(), Snapshot.deserialize(value.serialize())
        self.assertEqual([proof.serialize() for proof in decoded.shares], [proof.serialize() for proof in value.shares])
        self.assertEqual(decoded.job_commitment, value.job_commitment)
        self.assertEqual((decoded.post_state, decoded.certificates), ((), ()))
        reader = Reader(raw[dictionary_offset(raw):])
        self.assertEqual(reader.size(16 * 1024 * 1024), 2)
        for index in range(2):
            self.assertEqual(reader.size(16 * 1024 * 1024), index)
            EnvelopeV2.read(reader)
            reader.take(64)
        self.assertEqual(reader.size(16 * 1024 * 1024), 3)
        begin = reader.stream.tell()
        for proof in value.shares:
            self.assertIn(reader.size(16 * 1024 * 1024), (0, 1))
            header = proof.header
            self.assertEqual(reader.take(32), struct.pack("<III", header.nNonce, header.m_nonce2, header.m_nonce3) +
                             header.m_extranonce.to_bytes(16, "little") + struct.pack("<I", header.m_time_offset))
        self.assertEqual(reader.stream.tell() - begin, 99)
        self.assertEqual(replace(value, post_state=(object(),), certificates=(object(),)).serialize(), raw)

    def test_malformed_dictionary_and_original_work_bound(self):
        block, origin = compact_fixture()
        proof = solve_share(block, origin)
        _, value = compact_fixture(templates=(block,), shares=(proof,))
        raw, offset = value.serialize(), dictionary_offset(value.serialize())
        share_count_offset = offset + 2 + len(origin.envelope.serialize()) + 64
        malformed = (
            raw[:offset + 1] + b"\x01" + raw[offset + 2:],
            raw[:share_count_offset] + b"\x00" + raw[share_count_offset + 34:],
            raw[:share_count_offset + 1] + b"\x01" + raw[share_count_offset + 2:],
            raw[:offset] + b"\x02" + raw[offset + 1:share_count_offset] * 2 + raw[share_count_offset:],
            raw + b"\0",
        )
        for changed in malformed:
            with self.assertRaises(ValueError):
                Snapshot.deserialize(changed)
        with patch("hash_snapshot.MAX_COMPACT_SHARES", 0):
            with self.assertRaisesRegex(ValueError, "original work bound"):
                value.serialize()
            with self.assertRaisesRegex(ValueError, "original work bound"):
                Snapshot.deserialize(raw)
        self.assertEqual(MAX_COMPACT_SHARES, 32768)

    def test_descriptor_does_not_allow_template_or_owner_substitution(self):
        block, origin = compact_fixture()
        proof = solve_share(block, origin)
        _, value = compact_fixture(templates=(block,), shares=(proof,))
        header = CBlockHeader(proof.header)
        header.nBits ^= 1
        with self.assertRaisesRegex(ValueError, "exact declared template"):
            replace(value, shares=(replace(proof, header_bytes=header.serialize()),)).serialize()
        other = replace(solve_share(block, origin, start_nonce=proof.header.nNonce + 1), owner_signature=b"x" * 64)
        with self.assertRaisesRegex(ValueError, "inconsistent compact job"):
            replace(value, shares=tuple(sorted((proof, other), key=lambda item: item.proof_id))).serialize()

    def test_bounded_native_suffix_reconstructs_state_and_expires_old_work(self):
        origin, job = compact_fixture()
        proof = solve_share(origin, job)
        block, previous = compact_fixture(templates=(origin,), shares=(proof,))
        ancestors, originals = {block.sha256: Snapshot.deserialize(previous.serialize())}, [previous]
        for height in range(2, 8):
            block, previous = compact_fixture(height=height, native_parent=block.sha256, parent_snapshot=previous)
            ancestors[block.sha256] = Snapshot.deserialize(previous.serialize())
            originals.append(previous)
        for target in originals:
            calls = []
            def lookup(identity, height):
                calls.append(height)
                value = ancestors[identity]
                self.assertEqual(value.envelope.height, height)
                return value
            decoded = replace(Snapshot.deserialize(target.serialize()), post_state=(object(),), certificates=(object(),))
            derived = materialize_compact_state(decoded, parent_snapshot=lookup)
            self.assertEqual((derived.post_state, derived.certificates, derived.history_head),
                             (target.post_state, target.certificates, target.history_head))
            self.assertEqual(len(calls), min(MAX_SHARE_AGE, target.envelope.height - 1))
        target = originals[-1]
        with self.assertRaisesRegex(ValueError, "missing compact"):
            materialize_compact_state(target, parent_snapshot=lambda identity, height: None)
        bad = replace(target, history_head=target.history_head ^ 1)
        bad = replace(bad, owner_signature=sign_schnorr(SECRET, bad.owner_message))
        with self.assertRaisesRegex(ValueError, "history head"):
            materialize_compact_state(bad, parent_snapshot=lambda identity, height: ancestors[identity])

    def test_origin_suffix_is_charged_even_with_a_newer_trusted_parent(self):
        block, previous = compact_fixture()
        chain, snapshots, originals = {block.sha256: previous}, {previous.hash: previous}, [(block, previous)]
        for height in range(2, 9):
            block, previous = compact_fixture(height=height, native_parent=block.sha256, parent_snapshot=previous)
            chain[block.sha256], snapshots[previous.hash] = previous, previous
            originals.append((block, previous))
        calls, observed = [], {}
        def parent(identity, height):
            calls.append(height)
            value = chain[identity]
            self.assertEqual(value.envelope.height, height)
            return Snapshot.deserialize(value.serialize())
        origin_block, origin = originals[4]
        resources = check_graph(Snapshot.deserialize(origin.serialize()), lookup=lambda identity: snapshots[identity],
            parent_snapshot=parent, trusted_parent=originals[6][1], root_origin=TemplateRecord.from_block(origin_block),
            on_snapshot=lambda identity, raw: observed.__setitem__(identity, raw))
        # Native origin at H5 needs its H4 parent materialized through H1;
        # the top H7 parent's H4..H6 suffix alone would undercount work.
        self.assertIn(1, calls)
        self.assertEqual(resources["dependency_bytes"], sum(map(len, observed.values())))
        self.assertEqual(len(observed), 7)

    def test_certified_origin_keeps_exact_opening_without_old_suffix(self):
        block, previous = compact_fixture()
        chain = {block.sha256: previous}
        for height in range(2, 7):
            block, previous = compact_fixture(height=height, native_parent=block.sha256, parent_snapshot=previous)
            chain[block.sha256] = previous
        origin_block, origin = compact_fixture(height=7, native_parent=block.sha256, parent_snapshot=previous)
        proof = solve_share(origin_block, origin)
        block, previous = compact_fixture(height=7, native_parent=block.sha256, parent_snapshot=previous,
            templates=(origin_block,), shares=(proof,))
        chain[block.sha256] = previous
        for height in (8, 9):
            block, previous = compact_fixture(height=height, native_parent=block.sha256, parent_snapshot=previous)
            chain[block.sha256] = previous
        calls = []
        def parent(identity, height):
            calls.append(height)
            self.assertGreaterEqual(height, 6, "certified origin incorrectly required old derivation suffix")
            return Snapshot.deserialize(chain[identity].serialize())
        observed = {}
        resources = check_graph(origin, lookup=lambda identity: self.fail("certified origin recursed"),
            parent_snapshot=parent, trusted_parent=previous, root_origin=TemplateRecord.from_block(origin_block),
            root_depth=1, on_snapshot=lambda identity, raw: observed.__setitem__(identity, raw))
        self.assertEqual(sorted(calls), [6, 7, 8])
        self.assertEqual(len(observed), 5)
        self.assertIn(origin.hash, observed)
        self.assertEqual(resources["dependency_shares"], 1)
        self.assertEqual(resources["dependency_bytes"], sum(map(len, observed.values())))

    def test_many_alternative_jobs_do_not_retain_repeated_derived_state(self):
        seed_block, seed = compact_fixture()
        seed_proofs = tuple(solve_share(seed_block, seed, start_nonce=nonce) for nonce in range(64))
        parent_block, parent = compact_fixture(templates=(seed_block,), shares=seed_proofs)
        alternatives = [compact_fixture(height=2, native_parent=parent_block.sha256,
            parent_snapshot=parent, pool=100 + index) for index in range(64)]
        openings = {opening.hash: opening for _, opening in alternatives}
        proofs = tuple(solve_share(block, opening) for block, opening in alternatives)
        _, root = compact_fixture(height=2, native_parent=parent_block.sha256, parent_snapshot=parent,
            templates=tuple(block for block, _ in alternatives), shares=proofs)
        live_origins, peaks, observed = [], [], {}
        def materialize(value, **options):
            result = materialize_compact_state(value, **options)
            if value.hash in openings:
                self.assertEqual(len(result.post_state), 64)
                live_origins.append(weakref.ref(result))
                peaks.append(sum(reference() is not None for reference in live_origins))
            return result
        with patch("hash_gate_batch.materialize_compact_state", side_effect=materialize):
            result = check_graph(root, lookup=lambda identity: openings[identity],
                parent_snapshot=lambda identity, height: parent,
                on_snapshot=lambda identity, raw: observed.__setitem__(identity, raw))
        self.assertEqual(len(live_origins), 64)
        self.assertEqual(max(peaks), 1)
        self.assertTrue(all(reference() is None for reference in live_origins))
        self.assertEqual(result["dependency_shares"], 128)
        self.assertEqual(result["dependency_bytes"], sum(map(len, observed.values())))
        self.assertEqual(len(observed), 66)  # Current proposal, native parent, 64 alternatives.

    def test_provisional_fork_graph_has_a_bounded_parent_state_cache(self):
        seed_block, seed = compact_fixture()
        seed_proofs = tuple(solve_share(seed_block, seed, start_nonce=nonce) for nonce in range(32))
        forks = [compact_fixture(pool=1000 + index, ntime=1700000001 + index,
            templates=(seed_block,), shares=seed_proofs) for index in range(12)]
        parents = {block.sha256: state for block, state in forks}
        parent_hashes = {state.hash for state in parents.values()}
        jobs = [compact_fixture(height=2, native_parent=block.sha256, parent_snapshot=state, pool=2000 + index)
                for index, (block, state) in enumerate(forks)]
        openings = {opening.hash: opening for _, opening in jobs}
        proofs = tuple(solve_share(block, opening) for block, opening in jobs)
        _, root = compact_fixture(height=2, native_parent=forks[0][0].sha256, parent_snapshot=forks[0][1],
            templates=tuple(block for block, _ in jobs), shares=proofs)
        states, checked = [], []
        def materialize(value, **options):
            # Before the next operation, only the bounded cache and the top
            # trusted-parent local may retain earlier returned parent objects.
            self.assertLessEqual(sum(ref() is not None for ref in states), NATIVE_STATE_CACHE_ENTRIES + 1)
            result = materialize_compact_state(value, **options)
            if value.hash in parent_hashes:
                states.append(weakref.ref(result))
                checked.append(value.hash)
            return result
        with patch("hash_gate_batch.materialize_compact_state", side_effect=materialize):
            result = check_graph(root, lookup=lambda identity: openings[identity],
                parent_snapshot=lambda identity, height: parents[identity])
        self.assertEqual(len(set(checked)), 12)
        self.assertTrue(all(ref() is None for ref in states))
        self.assertEqual(result["dependency_shares"], 12 * 32 + 12)
        # This resource preflight deliberately precedes native chain validity;
        # these mutually competing parents do not make a valid settlement.

    def test_graph_proof_count_resists_compression_amplification(self):
        block, origin = compact_fixture()
        proof = solve_share(block, origin)
        _, value = compact_fixture(templates=(block,), shares=(proof,))
        resources = check_graph(value, lookup=lambda identity: origin, parent_snapshot=lambda *unused: None)
        self.assertEqual(resources["dependency_shares"], 1)
        with patch("hash_gate_batch.MAX_DEPENDENCY_SHARES", 0):
            with self.assertRaisesRegex(BatchLimit, "share count"):
                check_graph(value, lookup=lambda identity: origin, parent_snapshot=lambda *unused: None)


class CompactRPC(TidesRPC):
    def __call__(self, method, *args):
        value = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            value.update(mode="hash-only-v7-compact-tides", rules=f"{COMPACT_TIDES_RULES_HASH:064x}")
        return value


class CompactGateTests(unittest.TestCase):
    def test_native_construction_admission_and_receipts(self):
        with tempfile.TemporaryDirectory(prefix="gate-v7-") as directory:
            rpc = CompactRPC()
            block, opening = compact_fixture()
            gate = HashMiningGate(Path(directory) / "gate.sqlite", rpc=rpc, pool=3,
                public_key=opening.envelope.public_key, payout_script=SCRIPT, profile_version=7)
            try:
                rpc.gate = gate
                gate.register_snapshot(opening.serialize())
                gate.register_template(block.serialize())
                proof = solve_share(block, opening)
                gate.receive(proof)
                with patch("hash_snapshot.MAX_COMPACT_SHARES", 0):
                    self.assertEqual(gate.batch_status()["selected_proofs"], ())
                    self.assertEqual(gate.batch_status()["deferred_count"], 1)
                job, snapshot = gate.make_native(sign_owner=lambda value: sign_schnorr(SECRET, value.owner_message))
                self.assertEqual(snapshot.envelope.version, 7)
                self.assertEqual([item.serialize() for item in snapshot.shares], [proof.serialize()])
                self.assertEqual([output.nValue for output in snapshot.payouts], [40, 60])
                self.assertTrue(gate.ready_for_dispatch(gate.authorize(job.serialize(), snapshot.serialize())))
                rpc.publish(job, snapshot)
                self.assertEqual(gate.receipt_status()["receipts"][0]["status"], "confirmed_admitted")
                self.assertEqual(gate.batch_status()["selected_proofs"], ())
            finally:
                gate.close()


if __name__ == "__main__":
    unittest.main()
