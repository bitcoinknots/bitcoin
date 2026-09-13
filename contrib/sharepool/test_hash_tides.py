#!/usr/bin/env python3
"""v6 wire, state construction and local gate policy; native validity is separate."""
from dataclasses import replace
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hash_gate_batch import check_graph
from hash_mining_gate import HashMiningGate
from hash_snapshot import (Snapshot, TemplateRecord, LedgerCredit, TIDES_VERSION, TIDES_RULES_HASH,
    RULES_HASH, LEDGER_RULES_HASH, MAX_CERTIFICATE_BYTES, MAX_SHARE_AGE, build_snapshot,
    candidate, apply_tides_state, attest, origin_certificate, profile_snapshot_hash,
    snapshot_hash, share_target, share_work, solve_share, job_hash)
from native_enforcement import compact_size, h256, sign_schnorr, verify_schnorr
from native_mining_gate import REGTEST_GENESIS, parse_block
from test_framework.messages import CTxOut, CBlockHeader, ser_uint256, uint256_from_compact
from test_framework.script import CScript
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SECRET, SCRIPT


def codec_fixture(*, parent_snapshot=None, templates=(), shares=(), **options):
    """Synthetic exact signed bytes only; not a native TIDES payout builder."""
    block, base = fixture(**options)
    proposal = build_snapshot(genesis=base.envelope.genesis, height=base.envelope.height,
        native_parent=base.envelope.native_parent, pool=base.envelope.pool,
        payout_script=base.envelope.payout_script, reward=0, secret=options.get("secret", SECRET),
        version=TIDES_VERSION, templates=templates, shares=shares, parent_snapshot=parent_snapshot)
    proposal = replace(proposal, payouts=base.payouts)
    return block, attest(block, proposal, secret=options.get("secret", SECRET))


class TidesRPC(FakeRPC):
    """Checks gate control flow only; deliberately not a consensus implementation."""
    def __init__(self):
        super().__init__()
        self.corrupt_history = False
        self.reject_built_template = False

    @staticmethod
    def response(block, opening, reward=101):
        return {"template": block.serialize().hex(), "snapshot": opening.serialize().hex(),
                "reward": reward, "native_parent": f"{block.hashPrevBlock:064x}", "height": block.m_height,
                "commitment": opening.hash_hex, "job_commitment": f"{opening.job_commitment:064x}",
                "signing_payload": opening.signing_payload.hex(), "signing_hash": opening.owner_message[::-1].hex()}

    def __call__(self, method, *args):
        if method == "getsharepoolhashtidesbudget":
            self.calls.append((method, args))
            return {"native_tip": self.tip, "native_bits": 0x207fffff, "pool": args[0],
                    "payout_script": args[1], "output_count": 1, "output_bytes": 9 + len(bytes.fromhex(args[1]))}
        if method == "preparesharepoolhashjob":
            self.calls.append((method, args))
            proposal = Snapshot.deserialize(bytes.fromhex(args[0]))
            block, _ = fixture(native_parent=int(self.tip, 16), height=self.height + 1,
                               pool=proposal.envelope.pool, payout_script=proposal.envelope.payout_script)
            # A deliberately distinct test payout, accepted only by this double.
            outputs = (CTxOut(40, CScript(SCRIPT)), CTxOut(60, CScript(b"\x00\x14" + b"z" * 20)))
            block.vtx[0].vout = list(outputs)
            block.vtx[0].rehash()
            block.hashMerkleRoot = block.calc_merkle_root()
            opening = replace(proposal, payouts=outputs, job_commitment=job_hash(block),
                              history_head=proposal.history_head ^ int(self.corrupt_history))
            block.m_mm_rhs = opening.hash
            block.rehash()
            return self.response(block, opening)
        if method == "finalizesharepoolhashjob":
            self.calls.append((method, args))
            block, opening = parse_block(bytes.fromhex(args[0])), Snapshot.deserialize(bytes.fromhex(args[1]))
            block.m_mm_rhs = opening.hash
            block.rehash()
            return self.response(block, opening)
        if method == "validatesharepoolhashtemplate" and self.reject_built_template:
            raise ValueError("native TIDES payout validation refused")
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            result.update(mode="hash-only-v6-tides", rules=f"{TIDES_RULES_HASH:064x}")
        return result


class TidesSnapshotTests(unittest.TestCase):
    def test_rules_and_flat_profile_domain_are_separate(self):
        _, opening = codec_fixture()
        self.assertNotIn(TIDES_RULES_HASH, (RULES_HASH, LEDGER_RULES_HASH))
        self.assertEqual(opening.envelope.rules, TIDES_RULES_HASH)
        self.assertEqual(opening.hash, h256(b"SharePool/snapshot/v6\0", opening.serialize()))
        self.assertEqual(Snapshot.deserialize(opening.serialize()).serialize(), opening.serialize())
        self.assertEqual(opening.serialize()[-33:], b"\x00" + ser_uint256(opening.history_head))

    def test_legacy_malformed_preimage_hashing_is_unchanged(self):
        for raw in (b"", b"\x04", b"\x05", b"\x06", b"malformed", b"\x05garbage"):
            version = 5 if raw[:1] == b"\x05" else 4
            legacy = h256(f"SharePool/snapshot/v{version}\0".encode(), raw)
            self.assertEqual(snapshot_hash(raw), legacy)
            self.assertEqual(profile_snapshot_hash(raw, 4), legacy)
            self.assertEqual(profile_snapshot_hash(raw, 5), legacy)
            self.assertEqual(profile_snapshot_hash(raw, 6), h256(b"SharePool/snapshot/v6\0", raw))
        with self.assertRaises(ValueError):
            profile_snapshot_hash(b"raw", 8)

    def test_v6_history_commitment_binds_parent_and_original_pool_script_admissions(self):
        a, sa = codec_fixture(pool=3)
        b, sb = codec_fixture(pool=4, ntime=1700000002)  # Same address, independent pool.
        proofs = (solve_share(a, sa), solve_share(b, sb))
        anchor, current = codec_fixture(pool=9, templates=(a, b), shares=proofs)
        credits = [LedgerCredit(1, proof.envelope.height, proof.proof_id, proof.envelope.pool,
                                proof.header.nBits, proof.envelope.payout_script)
                   for proof in sorted(proofs, key=lambda proof: proof.proof_id)]
        raw = (ser_uint256(current.envelope.genesis) + ser_uint256(current.envelope.native_parent) +
               struct.pack("<I", 1) + bytes(32) + compact_size(2) + b"".join(value.serialize() for value in credits))
        self.assertEqual(current.history_head, h256(b"SharePool/history/v6\0", raw))
        self.assertEqual({credit.pool for credit in credits}, {3, 4})
        self.assertEqual({credit.payout_script for credit in credits}, {SCRIPT})
        self.assertEqual((current.pending, current.settled), ((), ()))
        _, next_state = codec_fixture(height=2, native_parent=anchor.sha256, parent_snapshot=current)
        expected = h256(b"SharePool/history/v6\0", ser_uint256(next_state.envelope.genesis) +
            ser_uint256(anchor.sha256) + struct.pack("<I", 2) + ser_uint256(current.history_head) + b"\x00")
        self.assertEqual(next_state.history_head, expected)
        self.assertNotEqual(current.history_head, next_state.history_head)

    def test_history_and_certificate_bytes_are_attested(self):
        origin, previous = codec_fixture()
        proof = solve_share(origin, previous)
        _, opening = codec_fixture(templates=(origin,), shares=(proof,))
        self.assertEqual(opening.certificates, (origin_certificate(TemplateRecord.from_block(origin)),))
        for changed in (replace(opening, history_head=opening.history_head ^ 1),
                        replace(opening, certificates=()), replace(opening, shares=())):
            self.assertNotEqual(opening.hash, changed.hash)
            self.assertFalse(verify_schnorr(opening.envelope.public_key, opening.owner_signature, changed.owner_message))

    def test_legacy_state_cannot_be_silently_migrated(self):
        _, opening = codec_fixture()
        _, v5 = fixture(version=5)
        credit = LedgerCredit(1, 1, 1, 3, 0x207fffff, SCRIPT)
        for changed in (replace(opening, pending=(credit,)), replace(opening, settled=(credit,)),
                        replace(v5, history_head=1)):
            with self.assertRaises(ValueError):
                changed.serialize()
        with self.assertRaisesRegex(ValueError, "parent profile"):
            apply_tides_state(replace(opening, envelope=replace(opening.envelope, height=2)), v5)
        self.assertEqual(Snapshot.deserialize(replace(opening, payouts=()).serialize()).payouts, ())

    def test_replay_rejection_recent_expiry_and_certificate_budget(self):
        origin, previous = codec_fixture()
        proof = solve_share(origin, previous)
        anchor, opening = codec_fixture(templates=(origin,), shares=(proof,))
        duplicate = replace(opening, envelope=replace(opening.envelope, height=2, native_parent=anchor.sha256))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            apply_tides_state(duplicate, opening)
        for height in range(2, MAX_SHARE_AGE + 3):
            anchor, opening = codec_fixture(height=height, native_parent=anchor.sha256, parent_snapshot=opening)
        self.assertEqual((opening.post_state, opening.certificates), ((), ()))
        self.assertNotEqual(opening.history_head, 0)
        with patch("hash_snapshot.MAX_CERTIFICATE_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "certificate capacity"):
                codec_fixture(templates=(origin,), shares=(proof,))

    def test_v6_share_targets_have_exact_power_of_two_work(self):
        for bits in (0x1d00ffff, 0x1c00ffff, 0x1b0404cb, 0x207fffff):
            target = share_target(bits, TIDES_VERSION)
            work = share_work(bits, TIDES_VERSION)
            self.assertEqual(work & (work - 1), 0)
            self.assertEqual((target + 1) * work, 1 << 256)
            floor = (1 << 256) // (uint256_from_compact(bits) + 1)
            desired = max(1, floor >> 10)
            self.assertLessEqual(work, desired)
            self.assertLess(desired, 2 * work)
            self.assertEqual(share_target(bits), share_target(bits, 5))
        self.assertEqual(share_target(0x207fffff, 6), (1 << 256) - 1)
        self.assertEqual(share_work(0x207fffff, 6), 1)

    def test_many_proofs_reuse_one_origin_certificate_calculation(self):
        origin, previous = codec_fixture()
        proofs = tuple(solve_share(origin, previous, start_nonce=nonce) for nonce in range(20))
        with patch("hash_snapshot.origin_certificate", wraps=origin_certificate) as certificate:
            _, opening = codec_fixture(templates=(origin,), shares=proofs)
            self.assertEqual(certificate.call_count, 1)
        self.assertEqual(len(opening.shares), 20)
        self.assertEqual(len(opening.certificates), 1)

    def test_candidate_v6_fails_instead_of_using_legacy_payouts(self):
        with self.assertRaisesRegex(ValueError, "native history-aware builder"):
            candidate(genesis=1, native_parent=1, height=1, ntime=1, pool=1, payout_script=SCRIPT, secret=SECRET, version=6)


class TidesGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="gate-v6-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "gate.sqlite"
        self.rpc = TidesRPC()
        self.origin, self.opening = codec_fixture()
        self.gate = HashMiningGate(self.path, rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key,
                                   payout_script=SCRIPT, profile_version=6)
        self.rpc.gate = self.gate
        self.addCleanup(self.gate.close)
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        self.proof = solve_share(self.origin, self.opening)

    def test_native_builder_uses_native_payout_validation_and_preserves_exact_evidence(self):
        signer = lambda snapshot: sign_schnorr(SECRET, snapshot.owner_message)
        with patch("hash_mining_gate.work_outputs", side_effect=AssertionError("v4 payout fallback")), \
             patch("hash_mining_gate.credit_outputs", side_effect=AssertionError("v5 payout fallback")):
            block, opening = self.gate.make_native(sign_owner=signer)
        self.assertEqual([output.nValue for output in opening.payouts], [40, 60])
        self.assertTrue(any(method == "validatesharepoolhashtemplate" for method, _ in self.rpc.calls))
        self.assertTrue(verify_schnorr(opening.envelope.public_key, opening.owner_signature, opening.owner_message))
        authorization = self.gate.authorize(block.serialize(), opening.serialize())
        self.assertTrue(self.gate.ready_for_dispatch(authorization))
        with self.assertRaisesRegex(ValueError, "make_native"):
            self.gate.make(ntime=1, sign_owner=signer)

    def test_changed_history_or_native_payout_refusal_cannot_dispatch(self):
        signer = lambda snapshot: sign_schnorr(SECRET, snapshot.owner_message)
        head = self.gate.archive_head()
        self.rpc.corrupt_history = True
        with self.assertRaisesRegex(ValueError, "changed the proposed"):
            self.gate.make_native(sign_owner=signer)
        self.rpc.corrupt_history = False
        self.rpc.reject_built_template = True
        with self.assertRaisesRegex(ValueError, "payout validation refused"):
            self.gate.make_native(sign_owner=signer)
        self.assertEqual(self.gate.archive_head(), head)

    def test_batch_reserves_historical_and_current_recipients_and_count_prefix(self):
        self.gate.receive(self.proof)
        rpc = self.rpc
        def historical(method, *args):
            value = rpc(method, *args)
            if method == "getsharepoolhashtidesbudget":
                value.update(output_count=252, output_bytes=252 * 31)
            return value
        self.gate.rpc = historical
        status = self.gate.batch_status()
        # 252 historical slots + one current script crosses CompactSize's
        # one-byte boundary. Historical zero-rounding must not erase slots.
        self.assertEqual(status["resources"]["payout_reservation_bytes"], 252 * 31 + 2)
        reserved = status["resources"]["reserved_snapshot_bytes"]
        self.gate.snapshot_budget = reserved - 1  # Deliberate boundary fixture.
        self.assertEqual(self.gate.batch_status()["selected_proofs"], ())
        self.assertEqual(self.gate.archive_head()["receipt_revision"], 1)
        self.gate.snapshot_budget = reserved
        self.assertEqual(self.gate.batch_status()["selected_proofs"], (f"{self.proof.proof_id:064x}",))

    def test_foreign_pool_proofs_do_not_reserve_local_payouts(self):
        origin, opening = codec_fixture(pool=7)
        proof = solve_share(origin, opening)
        self.gate.register_snapshot(opening.serialize())
        self.gate.register_template(origin.serialize())
        self.gate.receive(proof)
        status = self.gate.batch_status()
        self.assertEqual(status["resources"]["payout_reservation_bytes"], 0)
        self.assertEqual(status["selected_proofs"], (f"{proof.proof_id:064x}",))

    def test_bad_reservation_context_or_sizes_never_reach_the_signer(self):
        rpc = self.rpc
        for mutation in ({"native_tip": "ab" * 32}, {"pool": "cd" * 32}, {"output_count": True},
                         {"output_count": 0}, {"output_bytes": 30}, {"output_bytes": 44}, {"native_bits": 0}):
            with self.subTest(mutation=mutation):
                def broken(method, *args):
                    result = rpc(method, *args)
                    return dict(result, **mutation) if method == "getsharepoolhashtidesbudget" else result
                self.gate.rpc = broken
                with self.assertRaisesRegex(ValueError, "payout reservation failed"):
                    self.gate.make_native(sign_owner=lambda unused: self.fail("signer called"))

    def test_difficulty_change_after_reservation_requires_new_job(self):
        rpc = self.rpc
        def changed(method, *args):
            result = rpc(method, *args)
            return dict(result, native_bits=0x207ffffe) if method == "getsharepoolhashtidesbudget" else result
        self.gate.rpc = changed
        with self.assertRaisesRegex(ValueError, "difficulty changed after payout reservation"):
            self.gate.make_native(sign_owner=lambda unused: self.fail("signer called"))

    def test_payout_reservation_also_counts_toward_dependency_bytes(self):
        self.gate.receive(self.proof)
        size = self.gate.batch_status()["resources"]["dependency_bytes"]
        with patch("hash_mining_gate.MAX_DEPENDENCY_BYTES", size):
            result = self.gate.batch_status()
        self.assertEqual(result["selected_proofs"], ())
        self.assertEqual(result["deferred_count"], 1)

    def test_confirmed_receipt_never_claims_paid_once_or_current_window_eligibility(self):
        self.gate.receive(self.proof)
        self.assertEqual(self.gate.receipt_status()["receipts"][0]["status"], "provisional")
        block, opening = codec_fixture(pool=9, templates=(self.origin,), shares=(self.proof,))
        self.rpc.publish(block, opening)
        status = self.gate.receipt_status()["receipts"][0]
        self.assertEqual(status["status"], "confirmed_admitted")
        self.assertEqual(status["admitted_in"], block.hash)
        self.assertIsNone(status["reward_window_eligible"])
        self.assertFalse(status["reward_history_verified"])
        self.assertNotIn("settled_in", status)
        self.assertEqual(self.gate.batch_status()["selected_proofs"], ())
        self.rpc.height, self.rpc.tip = 0, REGTEST_GENESIS
        self.assertEqual(self.gate.receipt_status()["receipts"][0]["status"], "provisional")

    def test_missing_admission_history_stays_unknown(self):
        self.gate.receive(self.proof)
        anchor, admitted = codec_fixture(pool=9, templates=(self.origin,), shares=(self.proof,))
        self.rpc.publish(anchor, admitted)
        successor, state = codec_fixture(pool=9, native_parent=anchor.sha256, height=2, parent_snapshot=admitted)
        self.rpc.publish(successor, state)
        del self.rpc.snapshots[admitted.hash_hex]
        self.assertEqual(self.gate.receipt_status()["receipts"][0]["status"], "unknown")

    def test_v6_parent_certificates_are_supported_without_changing_identity_domain(self):
        proof = self.proof
        anchor, parent = codec_fixture(pool=9, templates=(self.origin,), shares=(proof,))
        _, current = codec_fixture(native_parent=anchor.sha256, height=2, parent_snapshot=parent)
        result = check_graph(current, lookup=lambda identity: self.opening,
                             parent_snapshot=lambda *unused: parent)
        self.assertEqual(result["origins"], 0)
        self.assertEqual(parent.certificates[0], origin_certificate(TemplateRecord.from_block(self.origin)))


if __name__ == "__main__":
    unittest.main()
