#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent SPN1 wire and arithmetic vectors; native tests are separate."""
from dataclasses import replace
import copy
import unittest

from native_enforcement import (RULES_HASH, Manifest, Reader, StateEntry, candidate,
    compact_size, parse_coinbase, solve_share, monetary_outputs, derive_state,
    verify_schnorr, carrier_outputs)


SECRET = (1).to_bytes(32, "big")
SCRIPT = b"\x00\x14" + b"a" * 20


def fixture():
    return candidate(genesis=1, native_parent=2, height=1, ntime=1700000001,
                     pool=3, secret=SECRET, payout_script=SCRIPT)


class NativeWireTests(unittest.TestCase):
    def test_fixed_cross_language_domain_vector_and_signature(self):
        block, manifest = fixture()
        self.assertEqual(f"{RULES_HASH:064x}", "068afe304d17019542089f3b2f00d4998cd522983b0571e32f0bacb9d4c44af1")
        self.assertEqual(f"{manifest.envelope.root:064x}", "7ff30080210857ee529629bf56d2fe98f2ac70db11852ed3ef95474ad458789a")
        self.assertTrue(verify_schnorr(manifest.envelope.public_key, manifest.owner_signature,
                                      manifest.envelope.owner_message))
        self.assertEqual(block.m_mm_rhs, manifest.envelope.root)
        self.assertEqual(len(manifest.serialize()), 351)
        self.assertEqual(Manifest.deserialize(manifest.serialize()), manifest)

    def test_carrier_layout_roundtrip_and_rdts_bound(self):
        block, manifest = fixture()
        parsed, money = parse_coinbase(block.vtx[0])
        self.assertEqual(parsed, manifest)
        self.assertEqual(sum(output.nValue for output in money), 5000000000)
        self.assertTrue(all(len(output.scriptPubKey) <= 83 for output in block.vtx[0].vout))
        for change in ("missing", "duplicate", "nonzero", "order"):
            changed = copy.deepcopy(block.vtx[0])
            if change == "missing":
                changed.vout.pop()
            elif change == "duplicate":
                changed.vout.append(copy.deepcopy(changed.vout[-1]))
            elif change == "nonzero":
                changed.vout[-1].nValue = 1
            else:
                changed.vout[-1], changed.vout[-2] = changed.vout[-2], changed.vout[-1]
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_coinbase(changed)

    def test_noncanonical_compact_size_trailing_and_parent_discriminator(self):
        for raw in (b"\xfd\x01\x00", b"\xfe\xff\xff\x00\x00", b"\xff\xff\xff\xff\xff\x00\x00\x00\x00"):
            with self.assertRaises(ValueError):
                Reader(raw).size(1 << 64)
        _, manifest = fixture()
        with self.assertRaises(ValueError):
            Manifest.deserialize(manifest.serialize() + b"\x00")
        raw = bytearray(manifest.serialize())
        raw[len(manifest.envelope.serialize()) + 64] = 2
        with self.assertRaises(ValueError):
            Manifest.deserialize(bytes(raw))
        for value in (0, 252, 253, 65535, 65536, (1 << 32), (1 << 64) - 1):
            self.assertEqual(Reader(compact_size(value)).size(1 << 64), value)

    def test_different_signatures_never_change_proof_id(self):
        block, manifest = fixture()
        share = solve_share(block, manifest)
        self.assertEqual(share.proof_id, replace(share, owner_signature=bytes(64)).proof_id)
        changed = replace(manifest, shares=(share, share))
        with self.assertRaises(ValueError):
            Manifest.deserialize(changed.serialize())

    def test_shared_destination_and_largest_remainder_allocation(self):
        block, manifest = fixture()
        first = solve_share(block, manifest)
        second = solve_share(block, manifest, start_nonce=first.header.nNonce + 1)
        other_script = b"\x00\x14" + b"b" * 20
        third = replace(first, envelope=replace(first.envelope, payout_script=other_script))
        outputs = monetary_outputs((first, second, third), reward=100003, fallback_script=SCRIPT)
        self.assertEqual([(bytes(output.scriptPubKey), output.nValue) for output in outputs],
                         [(SCRIPT, 66669), (other_script, 33334)])
        outputs = monetary_outputs((first, third), reward=1, fallback_script=SCRIPT)
        self.assertEqual([output.nValue for output in outputs], [1, 0])

    def test_state_pruning_and_native_eligibility_boundary(self):
        entries = (StateEntry(2, 5), StateEntry(3, 8))
        self.assertEqual(derive_state(entries, (), 5), entries)
        self.assertEqual(derive_state(entries, (), 6), (entries[1],))


if __name__ == "__main__":
    unittest.main()
