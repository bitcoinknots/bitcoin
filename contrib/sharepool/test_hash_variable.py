#!/usr/bin/env python3
"""V8 assigned-work codec/authentication vectors; native validation is separate."""
from dataclasses import replace
import hashlib
import struct
import unittest
from unittest.mock import patch

from hash_snapshot import (EnvelopeV2, Reader, Snapshot, LedgerCredit,
    VARIABLE_TIDES_VERSION, VARIABLE_TIDES_RULES_HASH, MIN_SHARE_WORK_BITS, MAX_SHARE_WORK_BITS,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH,
    MAX_DEPENDENCY_BYTES, MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES,
    MAX_ORIGIN_CHECKS, MAX_CERTIFICATE_BYTES, MAX_DEPENDENCY_SHARES,
    is_tides_profile, is_compact_tides_profile, rules_hash, profile_snapshot_hash,
    HashSigner, build_snapshot, attest, solve_share, parse_share, share_target, share_work,
    proof_target, proof_work, work_outputs, materialize_compact_state)
from native_enforcement import h256, compact_size, vector, verify_schnorr
from native_mining_gate import template_id
from native_signer import SignerError
from hash_gate_batch import check_graph
from hash_state_cache import CompactStateCache
from test_framework.messages import CBlockHeader, ser_uint256
from test_hash_compact import compact_fixture
from test_hash_snapshot import fixture, SECRET, SCRIPT
from test_hash_tides import codec_fixture


def variable_fixture(*, share_work_bits=0, parent_snapshot=None, templates=(), shares=(), **options):
    """Synthetic signed model bytes, not a native history-aware payout builder."""
    block, base = fixture(**options)
    proposal = build_snapshot(genesis=base.envelope.genesis, height=base.envelope.height,
        native_parent=base.envelope.native_parent, pool=base.envelope.pool,
        payout_script=base.envelope.payout_script, reward=0, secret=options.get("secret", SECRET),
        version=VARIABLE_TIDES_VERSION, share_work_bits=share_work_bits,
        templates=templates, shares=shares, parent_snapshot=parent_snapshot)
    return block, attest(block, replace(proposal, payouts=base.payouts), secret=options.get("secret", SECRET))


class VariableSnapshotTests(unittest.TestCase):
    def test_pre_v8_signed_wire_vectors_are_unchanged(self):
        expected = {
            4: (1247, "9261dc22e830cab38ffa47235ceba64b7498e0f8b8ee7f21046a388961c7b396"),
            5: (1449, "465749304435aceb1f4bb8eebc4c3d4e1ad5aa74aed141a37dfd047a853d3cb3"),
            6: (1380, "4b218b30094a9f4630b512025e7f831a4a06516a57bd7cfe21651ebb9686fcda"),
            7: (1113, "3cc644637fa3a8958e1f2177d3f0877a5c7ea3c20994b15f866ff2a2810bb728"),
        }
        for version, vector_value in expected.items():
            builder = {6: codec_fixture, 7: compact_fixture}.get(version,
                lambda **options: fixture(version=version, **options))
            block, origin = builder()
            _, settlement = builder(templates=(block,), shares=(solve_share(block, origin),))
            raw = settlement.serialize()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), vector_value)

    def test_rules_and_profile_domains_bind_assignment_range(self):
        values = (0, 255, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES,
            MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES, MAX_EXPANDED_TEMPLATE_BYTES,
            MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS, MAX_CERTIFICATE_BYTES,
            8, 2, 1, MAX_DEPENDENCY_SHARES)
        self.assertEqual(VARIABLE_TIDES_RULES_HASH, h256(b"SharePool/rules/v8\0", struct.pack("<15I", *values)))
        self.assertEqual(f"{VARIABLE_TIDES_RULES_HASH:064x}", "173ff6fa511f227cc8d4751bb15373afdca5c8ec235dc69ca2680d7ade13ea31")
        self.assertEqual((MIN_SHARE_WORK_BITS, MAX_SHARE_WORK_BITS), (0, 255))
        self.assertTrue(is_tides_profile(8))
        self.assertTrue(is_compact_tides_profile(8))
        self.assertFalse(is_compact_tides_profile(6))
        for raw in (b"", b"\x07legacy", b"\x08malformed"):
            self.assertEqual(profile_snapshot_hash(raw, 8), h256(b"SharePool/snapshot/v8\0", raw))

    def test_assignment_byte_is_after_script_before_reserved_roots(self):
        _, value = variable_fixture(share_work_bits=255)
        env = value.envelope
        prefix = (b"\x08" + ser_uint256(env.genesis) + ser_uint256(env.rules) + struct.pack("<I", env.height) +
            ser_uint256(env.native_parent) + ser_uint256(env.pool) + env.public_key + vector(env.payout_script))
        expected = prefix + b"\xff" + bytes(96)
        self.assertEqual(env.serialize(), expected)
        reader = Reader(expected)
        self.assertEqual(EnvelopeV2.read(reader), env)
        self.assertFalse(reader.stream.read())
        self.assertEqual(Snapshot.deserialize(value.serialize()).serialize(), value.serialize())
        self.assertEqual(len(env.serialize()), len(replace(env, version=7, rules=rules_hash(7), share_work_bits=0).serialize()) + 1)
        for bits in (-1, 256, None, True, 1.0, b"\x01"):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                replace(env, share_work_bits=bits).serialize()
        for version in (4, 5, 6, 7):
            with self.subTest(version=version), self.assertRaises(ValueError):
                replace(env, version=version, rules=rules_hash(version), share_work_bits=1).serialize()

    def test_exact_assigned_target_and_weight_ignore_native_difficulty_changes(self):
        for native in (0x207fffff, 0x1d00ffff, 0x1c00ffff):
            for bits in (0, 1, 2, 8, 32, 128, 255):
                self.assertEqual(share_target(native, 8, bits), (1 << (256 - bits)) - 1)
                self.assertEqual(share_work(native, 8, bits), 1 << bits)
        for value in (None, -1, 256, True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                share_work(0x207fffff, 8, value)
        for native in (0, -1, 0x20800001, 0x23000001, True):
            with self.subTest(native=native), self.assertRaises(ValueError):
                share_target(native, 8, 1)
        for version in (4, 5, 6, 7):
            with self.subTest(version=version), self.assertRaises(ValueError):
                share_work(0x207fffff, version, 1)

    def test_assignment_is_signed_and_changes_exact_template_identity(self):
        block, original = variable_fixture(share_work_bits=1)
        original_id = template_id(block)
        changed = replace(original, envelope=replace(original.envelope, share_work_bits=2))
        self.assertNotEqual(original.signing_payload, changed.signing_payload)
        self.assertNotEqual(original.hash, changed.hash)
        self.assertFalse(verify_schnorr(original.envelope.public_key, original.owner_signature, changed.owner_message))
        for snapshot in (original, changed):
            captured = snapshot.capture()
            self.assertEqual((captured.raw, captured.hash, captured.contents_hash, captured.signing_payload, captured.owner_message),
                (snapshot.serialize(), snapshot.hash, snapshot.contents_hash, snapshot.signing_payload, snapshot.owner_message))
        changed = attest(block, changed, secret=SECRET)
        self.assertTrue(verify_schnorr(changed.envelope.public_key, changed.owner_signature, changed.owner_message))
        self.assertNotEqual(template_id(block), original_id)

    def test_native_signer_adapter_passes_exact_assignment_payload_and_rejects_relabelled_signature(self):
        _, snapshot = variable_fixture(share_work_bits=3)
        signer = HashSigner.__new__(HashSigner)
        signer.pool, signer.payout_script, signer.public_key = 3, SCRIPT, snapshot.envelope.public_key
        calls = []
        def invoke(command, raw, size):
            calls.append((command, raw, size))
            return snapshot.owner_signature
        signer._invoke = invoke
        self.assertEqual(signer.sign_owner(snapshot), snapshot.owner_signature)
        self.assertEqual(calls, [("sign-job", snapshot.signing_payload, 64)])
        with self.assertRaisesRegex(SignerError, "signature failed"):
            signer.sign_owner(replace(snapshot, envelope=replace(snapshot.envelope, share_work_bits=4)))

    def test_one_compact_origin_cannot_claim_two_assignments(self):
        block, origin = variable_fixture(share_work_bits=2)
        first = solve_share(block, origin)
        second = solve_share(block, origin, start_nonce=first.header.nNonce + 1)
        changed = replace(second, envelope=replace(origin.envelope, share_work_bits=3))
        with self.assertRaisesRegex(ValueError, "inconsistent compact job owner"):
            variable_fixture(templates=(block,), shares=(first, changed))

    def test_compact_roundtrip_and_payout_weights_use_each_origin_assignment(self):
        other_script = b"\x00\x14" + b"b" * 20
        a, sa = variable_fixture(share_work_bits=1)
        b, sb = variable_fixture(share_work_bits=4, payout_script=other_script, ntime=1700000002)
        proofs = (solve_share(a, sa), solve_share(b, sb))
        _, batch = variable_fixture(share_work_bits=9, templates=(a, b), shares=proofs)
        decoded = Snapshot.deserialize(batch.serialize())
        self.assertEqual([p.serialize() for p in decoded.shares], [p.serialize() for p in batch.shares])
        self.assertEqual({p.envelope.share_work_bits for p in decoded.shares}, {1, 4})
        for proof in decoded.shares:
            self.assertEqual(parse_share(proof.serialize()).serialize(), proof.serialize())
            self.assertLessEqual(proof.proof_id, proof_target(proof))
            self.assertEqual(proof_work(proof), 1 << proof.envelope.share_work_bits)
        self.assertEqual({bytes(o.scriptPubKey): o.nValue for o in work_outputs(decoded.shares, 180, SCRIPT)},
                         {SCRIPT: 20, other_script: 160})
        self.assertEqual((decoded.post_state, decoded.certificates), ((), ()))

    def test_v8_history_serializes_origin_assignment_without_changing_ledger_bytes(self):
        block, origin = variable_fixture(share_work_bits=3)
        proof = solve_share(block, origin)
        _, batch = variable_fixture(share_work_bits=9, templates=(block,), shares=(proof,))
        credit = LedgerCredit(1, 1, proof.proof_id, proof.envelope.pool, proof.header.nBits, proof.envelope.payout_script)
        legacy = (struct.pack("<II", 1, 1) + ser_uint256(proof.proof_id) + ser_uint256(proof.envelope.pool) +
                  struct.pack("<I", proof.header.nBits) + vector(proof.envelope.payout_script))
        self.assertEqual(credit.serialize(), legacy)
        history = (ser_uint256(batch.envelope.genesis) + ser_uint256(batch.envelope.native_parent) +
                   struct.pack("<I", 1) + bytes(32) + compact_size(1) + legacy + b"\x03")
        self.assertEqual(batch.history_head, h256(b"SharePool/history/v8\0", history))
        _, new_assignment = variable_fixture(share_work_bits=1, templates=(block,), shares=(proof,))
        self.assertEqual(batch.history_head, new_assignment.history_head)
        relabelled = replace(proof, envelope=replace(proof.envelope, share_work_bits=4))
        _, invalid_origin = variable_fixture(share_work_bits=9, templates=(block,), shares=(relabelled,))
        self.assertNotEqual(batch.history_head, invalid_origin.history_head)

    def test_compact_state_replay_reconstructs_v8_and_refuses_v7_parent(self):
        first_block, first = variable_fixture(share_work_bits=2)
        proof = solve_share(first_block, first)
        _, second = variable_fixture(height=2, native_parent=first_block.rehash(), parent_snapshot=first,
            share_work_bits=5, templates=(first_block,), shares=(proof,))
        decoded = Snapshot.deserialize(second.serialize())
        reconstructed = materialize_compact_state(decoded, parent_snapshot=lambda parent, height: first)
        self.assertEqual(reconstructed.post_state, second.post_state)
        self.assertEqual(reconstructed.history_head, second.history_head)
        _, legacy = compact_fixture()
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            materialize_compact_state(decoded, parent_snapshot=lambda parent, height: legacy)

    def test_graph_cache_retains_origin_weight_and_still_authenticates_changed_bytes(self):
        first_block, first = variable_fixture(share_work_bits=2)
        proof = solve_share(first_block, first)
        _, second = variable_fixture(height=2, native_parent=first_block.rehash(), parent_snapshot=first,
            share_work_bits=7, templates=(first_block,), shares=(proof,))
        cache, reads = CompactStateCache(), []
        def parent(identity, height):
            reads.append((identity, height))
            return first
        def graph():
            return check_graph(second, lookup=lambda identity: {first.hash: first}[identity],
                               parent_snapshot=parent, state_cache=cache)
        self.assertEqual(graph(), graph())
        self.assertTrue(reads)
        self.assertGreater(cache.stats()["hits"], 0)
        derived = materialize_compact_state(second, parent_snapshot=parent, state_cache=cache)
        saved = cache.get((1, 8, (first.serialize(), second.serialize())))
        self.assertIsNotNone(saved)
        self.assertEqual([proof_work(value) for value in saved.shares], [4])
        self.assertEqual(saved.envelope.share_work_bits, 7)
        self.assertEqual(derived.post_state, saved.post_state)
        self.assertIsNone(cache.get((1, 7, (first.serialize(), second.serialize()))))
        changed = replace(first, envelope=replace(first.envelope, share_work_bits=3))
        with self.assertRaisesRegex(ValueError, "authorization"):
            materialize_compact_state(second, parent_snapshot=lambda identity, height: changed, state_cache=cache)

    def test_synthetic_zero_endpoint_survives_v8_admission_history_and_cache(self):
        # Inject the otherwise infeasible endpoint, not a claim of finding real
        # 255-bit work. All canonical bytes/signatures/state paths stay real.
        block, origin = variable_fixture(share_work_bits=255)
        with patch.object(CBlockHeader, "rehash", return_value=0):
            proof = solve_share(block, origin)
            self.assertEqual(proof.proof_id, 0)
            self.assertEqual(proof_target(proof), 1)
            self.assertEqual(proof_work(proof), 1 << 255)
            _, value = variable_fixture(templates=(block,), shares=(proof,))
            decoded = Snapshot.deserialize(value.serialize())
            self.assertEqual(decoded.shares[0].proof_id, 0)
            self.assertEqual(parse_share(proof.serialize()).proof_id, 0)
            cache = CompactStateCache()
            derived = materialize_compact_state(decoded, parent_snapshot=lambda *args: None, state_cache=cache)
            repeated = materialize_compact_state(decoded, parent_snapshot=lambda *args: None, state_cache=cache)
            self.assertEqual(derived.post_state[0].proof_id, 0)
            self.assertEqual(derived.history_head, repeated.history_head)
            self.assertEqual(proof_work(repeated.shares[0]), 1 << 255)
            self.assertGreater(cache.stats()["hits"], 0)
            with self.assertRaisesRegex(ValueError, "duplicate admitted proof"):
                variable_fixture(templates=(block,), shares=(proof, proof))

    def test_synthetic_upper_endpoint_and_legacy_zero_rejection(self):
        block, origin = variable_fixture(share_work_bits=255)
        with patch.object(CBlockHeader, "rehash", return_value=1):
            proof = solve_share(block, origin)
            self.assertEqual(proof.proof_id, 1)
            self.assertLessEqual(proof.proof_id, proof_target(proof))
        self.assertEqual(share_target(block.nBits, 8, 255) + 1, 2)
        self.assertEqual((1 << 256) // 2, share_work(block.nBits, 8, 255))
        for builder in (codec_fixture, compact_fixture):
            legacy_block, legacy_origin = builder()
            with patch.object(CBlockHeader, "rehash", return_value=0):
                zero = solve_share(legacy_block, legacy_origin)
                with self.assertRaisesRegex(ValueError, "zero proof identity"):
                    builder(templates=(legacy_block,), shares=(zero,))


if __name__ == "__main__":
    unittest.main()
