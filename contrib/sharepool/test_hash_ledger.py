#!/usr/bin/env python3
"""Independent wire/selection examples for v5; native validity is tested separately."""
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch
import unittest

from hash_snapshot import (Snapshot, TemplateRecord, LEDGER_RULES_HASH, apply_ledger_state,
    credit_outputs, origin_certificate, solve_share)
from native_enforcement import verify_schnorr
from test_hash_snapshot import fixture, SCRIPT


class ConfirmedLedgerTests(unittest.TestCase):
    def admitted(self):
        origins, shares = [], []
        for number, pool in ((1, 3), (2, 3), (3, 4)):
            origin, opening = fixture(version=5, pool=pool, secret=number.to_bytes(32, "big"),
                payout_script=b"\x00\x14" + bytes([number]) * 20)
            origins.append(origin)
            shares.append(solve_share(origin, opening))
        anchor, snapshot = fixture(version=5, pool=9, templates=origins, shares=shares)
        return anchor, snapshot, origins, shares

    def test_flat_v5_roundtrip_and_confirmed_parent_cutoff(self):
        anchor, parent, _, shares = self.admitted()
        self.assertEqual(parent.envelope.rules, LEDGER_RULES_HASH)
        self.assertEqual(Snapshot.deserialize(parent.serialize()).serialize(), parent.serialize())
        self.assertEqual(set(c.proof_id for c in parent.pending), set(s.proof_id for s in shares))
        self.assertEqual(parent.settled, ())
        self.assertEqual([bytes(p.scriptPubKey) for p in parent.payouts], [SCRIPT])
        _, current = fixture(version=5, native_parent=anchor.sha256, height=2, parent_snapshot=parent)
        self.assertEqual(len(current.settled), 2)
        self.assertEqual(len(current.pending), 1)
        self.assertEqual(current.pending[0].pool, 4)
        self.assertEqual([p.nValue for p in current.payouts], [2_500_000_000] * 2)
        self.assertEqual(current.shares, ())

    def test_fresh_admissions_cannot_change_current_payout(self):
        anchor, parent, origins, _ = self.admitted()
        late_origin, late_opening = fixture(version=5, secret=(7).to_bytes(32, "big"),
            payout_script=b"\x00\x14" + b"l" * 20)
        late = solve_share(late_origin, late_opening)
        _, current = fixture(version=5, native_parent=anchor.sha256, height=2, parent_snapshot=parent,
            templates=[late_origin], shares=[late])
        self.assertEqual(len(current.settled), 2)
        self.assertNotIn(late.proof_id, {c.proof_id for c in current.settled})
        self.assertIn(late.proof_id, {c.proof_id for c in current.pending})
        self.assertNotIn(late.envelope.payout_script, [bytes(p.scriptPubKey) for p in current.payouts])

    def test_confirmed_credits_survive_proof_admission_age(self):
        block, current, _, _ = self.admitted()
        expected = current.pending
        for height in range(2, 8):
            block, current = fixture(version=5, native_parent=block.sha256, height=height,
                pool=9, parent_snapshot=current)
            self.assertEqual(current.pending, expected)
            self.assertEqual(current.settled, ())
        self.assertEqual(current.post_state, ())
        self.assertEqual(current.certificates, ())
        _, paying = fixture(version=5, native_parent=block.sha256, height=8, pool=4, parent_snapshot=current)
        self.assertEqual(len(paying.settled), 1)
        self.assertEqual(paying.settled[0].origin_height, 1)

    def test_deterministic_prefix_and_backpressure_never_drop_confirmed_credit(self):
        anchor, parent, _, _ = self.admitted()
        _, proposal = fixture(version=5, native_parent=anchor.sha256, height=2, pool=3, parent_snapshot=parent)
        one_credit_bytes = 1 + len(parent.pending[0].serialize())
        with patch("hash_snapshot.MAX_SETTLEMENT_BYTES", one_credit_bytes):
            bounded = apply_ledger_state(proposal, parent)
        self.assertEqual(len(bounded.settled), 1)
        self.assertEqual(len(bounded.pending), 2)
        self.assertEqual({c.proof_id for c in bounded.pending + bounded.settled}, {c.proof_id for c in parent.pending})
        first = next(c for c in parent.pending if c.pool == 3)
        self.assertEqual(bounded.settled, (first,))
        with patch("hash_snapshot.MAX_LEDGER_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "capacity"):
                apply_ledger_state(proposal, parent)
        self.assertEqual(len(parent.pending), 3)

    def test_state_mutation_breaks_exact_authorization(self):
        _, parent, _, _ = self.admitted()
        for changed in (replace(parent, pending=parent.pending[:-1]),
                        replace(parent, certificates=()),
                        replace(parent, pending=(replace(parent.pending[0], native_bits=0x207ffffe),) + parent.pending[1:])):
            self.assertNotEqual(changed.hash, parent.hash)
            self.assertFalse(verify_schnorr(parent.envelope.public_key, parent.owner_signature, changed.owner_message))

    def test_certificate_binds_witness_and_rhs(self):
        block, _ = fixture(version=5, witness=True)
        original = origin_certificate(TemplateRecord.from_block(block))
        changed = deepcopy(block)
        changed.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = b"z" * 32
        self.assertEqual(changed.calc_merkle_root(), block.calc_merkle_root())
        witness = origin_certificate(TemplateRecord.from_block(changed))
        self.assertNotEqual(witness.identity, original.identity)
        changed = deepcopy(block)
        changed.m_mm_rhs ^= 1
        self.assertNotEqual(origin_certificate(TemplateRecord.from_block(changed)).identity, original.identity)

    def test_duplicate_and_cross_profile_admissions_rejected(self):
        anchor, parent, origins, shares = self.admitted()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            fixture(version=5, native_parent=anchor.sha256, height=2, parent_snapshot=parent,
                    templates=[origins[0]], shares=[shares[0]])
        with self.assertRaisesRegex(ValueError, "profile differs"):
            replace(parent, envelope=fixture()[1].envelope).serialize()


if __name__ == "__main__":
    unittest.main()
