#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests of real hashes and synthetic template binding; no live-node acceptance."""

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
import unittest

from proof_fixtures import (BASE_BITS, CBlockHeader, CTransaction, ShareProof,
                            fixture_payout_script, make_share, verify_share)
from work_accounting import evaluate


def change_header(share, field, value):
    header = CBlockHeader()
    header.deserialize(BytesIO(share.header))
    setattr(header, field, value)
    return replace(share, header=header.serialize())


class ProofFixtureTest(unittest.TestCase):
    def setUp(self):
        self.share = make_share(b"datum-A", 123, 100)

    def verify(self, share):
        return verify_share(share, 123, 100, b"pool-A")

    def test_real_proof_and_stable_tag_across_jobs(self):
        other = make_share(b"datum-A", 123, 100, nonce_seed=1)
        first, second = self.verify(self.share), self.verify(other)
        self.assertEqual(first.share_id, self.share.share_id)
        self.assertNotEqual(first.share_id, second.share_id)
        self.assertEqual(first.group_id, fixture_payout_script(b"datum-A"))
        self.assertEqual(self.share.declared_tag, other.declared_tag)
        result = evaluate([first, second])
        self.assertEqual((result.group_count, result.total_work), (1, 4))
        with self.assertRaises(ValueError):
            evaluate([first, first])

    def test_tag_template_changes_and_false_declaration(self):
        other = make_share(b"datum-B", 123, 100)
        self.assertNotEqual(self.share.coinbase, other.coinbase)
        self.assertNotEqual(self.share.header, other.header)
        with self.assertRaisesRegex(ValueError, "tag/pool"):
            self.verify(replace(self.share, declared_tag=b"datum-B"))
        with self.assertRaisesRegex(ValueError, "Merkle"):
            self.verify(replace(self.share, coinbase=other.coinbase, declared_tag=b"datum-B"))

    def test_distinct_tags_share_the_actual_bound_payout_group(self):
        destination = b"\x00\x20" + b"\x41" * 32
        first = make_share(b"miner-A", 123, 100, payout_script=destination)
        second = make_share(b"miner-B", 123, 100, payout_script=destination)
        self.assertNotEqual(first.declared_tag, second.declared_tag)
        self.assertNotEqual(first.share_id, second.share_id)
        self.assertEqual(self.verify(first).group_id, destination)
        self.assertEqual(self.verify(second).group_id, destination)
        result = evaluate([self.verify(first), self.verify(second)])
        self.assertEqual((result.group_count, result.total_work), (1, 4))

    def test_payout_destination_is_bound_before_hashing_and_not_redirectable(self):
        original = self.verify(self.share)
        destination = b"\x00\x20" + b"\x42" * 32
        changed_job = make_share(b"datum-A", 123, 100, payout_script=destination)
        self.assertEqual(self.verify(changed_job).group_id, destination)
        self.assertEqual(self.verify(self.share), original)
        self.assertNotEqual(original.group_id, destination)
        # Replacing the coinbase without redoing its committed work is invalid.
        with self.assertRaisesRegex(ValueError, "Merkle"):
            self.verify(replace(self.share, coinbase=changed_job.coinbase))

    def test_parent_height_pool_target_and_commitment_binding(self):
        for kwargs in ({"expected_parent": 124}, {"expected_height": 101},
                       {"expected_pool": b"pool-B"}, {"allowed_bits": 0x203FFFFF}):
            context = dict(expected_parent=123, expected_height=100, expected_pool=b"pool-A")
            context.update(kwargs)
            with self.assertRaises(ValueError):
                verify_share(self.share, **context)
        for field, value in (("m_mm_rhs", 0), ("m_txcount", 2), ("m_xor_key", 1),
                             ("m_header_v2", False), ("hashMerkleRoot", 0), ("nBits", 0x207FFFFF)):
            with self.assertRaises(ValueError):
                self.verify(change_header(self.share, field, value))
        with self.assertRaises(ValueError):
            self.verify(replace(self.share, pool_id=b"pool-B"))

    def test_actual_pow_is_checked(self):
        header = CBlockHeader()
        header.deserialize(BytesIO(self.share.header))
        for nonce in range(128):
            header.nNonce = nonce
            if header.rehash() > (0x7FFFFF << 232):
                break
        else:
            self.fail("fixed fixture did not exhibit a non-solution")
        with self.assertRaisesRegex(ValueError, "target"):
            self.verify(replace(self.share, header=header.serialize()))

    def test_preapproved_target_controls_credit(self):
        harder = make_share(b"datum-A", 123, 100, share_bits=0x203FFFFF)
        credited = verify_share(harder, 123, 100, b"pool-A", allowed_bits=0x203FFFFF)
        self.assertEqual(credited.credited_work, 4)
        for share in (self.share, harder):
            header = CBlockHeader()
            header.deserialize(BytesIO(share.header))
            self.assertEqual(header.nBits, BASE_BITS)
        with self.assertRaises(ValueError):
            self.verify(harder)

    def test_exact_deserialization_and_coinbase_shape(self):
        for field in ("header", "coinbase"):
            data = getattr(self.share, field)
            for bad in (b"", data[:-1], data + b"trailing"):
                with self.assertRaises(ValueError):
                    self.verify(replace(self.share, **{field: bad}))
        coinbase = CTransaction()
        coinbase.deserialize(BytesIO(self.share.coinbase))
        coinbase.vin[0].prevout.hash = 7
        with self.assertRaisesRegex(ValueError, "coinbase input"):
            self.verify(replace(self.share, coinbase=coinbase.serialize()))

    def test_immutable_bytes_and_input_bounds(self):
        with self.assertRaises(FrozenInstanceError):
            self.share.declared_tag = b"other"
        with self.assertRaises(TypeError):
            ShareProof(bytearray(self.share.header), self.share.coinbase, b"tag", b"pool")
        for kwargs in ({"tag": b""}, {"tag": b"t" * 33}, {"height": 0},
                       {"parent_hash": -1}, {"nonce_seed": True}, {"share_bits": 0},
                       {"payout_script": b""}, {"payout_script": b"x" * 1025},
                       {"payout_script": bytearray(b"\x51")}):
            arguments = dict(tag=b"tag", parent_hash=123, height=100)
            arguments.update(kwargs)
            with self.assertRaises(ValueError):
                make_share(**arguments)


if __name__ == "__main__":
    unittest.main()
