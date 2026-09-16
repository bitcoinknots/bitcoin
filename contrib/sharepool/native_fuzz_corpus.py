#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Create deterministic seeds for the native sharepool fuzz target.

Public fixture keys and synthetic ancestor hashes match the bounded native
target. The corpus is a reproducible smoke campaign, not a substitute for a
coverage-guided fuzzing campaign. It never starts a node or contacts a miner.
"""

import argparse
from dataclasses import replace
import hashlib
from pathlib import Path
import random

from native_enforcement import (Envelope, Manifest, RULES_HASH, SHARE_BITS, Share,
    StateEntry, monetary_outputs, payouts_root, shares_root, state_root)
from test_framework.key import compute_xonly_pubkey
from test_framework.messages import CBlockHeader, uint256_from_compact


def seed_manifest():
    secret = (1).to_bytes(32, "big")
    public_key = compute_xonly_pubkey(secret)[0]
    genesis = int("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", 16)
    parent = Envelope(genesis, RULES_HASH, 1, 1, 3, public_key, b"\x00\x14" + b"a" * 20)
    current = replace(parent, height=2, native_parent=2)
    header = CBlockHeader()
    header.m_header_v2 = True
    header.nVersion = 0x20000000
    header.m_height = 2
    header.hashPrevBlock = 2
    header.hashMerkleRoot = 7
    header.m_txcount = 1
    header.nTime = 1601
    header.nBits = SHARE_BITS
    header.m_mm_rhs = current.root
    for nonce in range(256):
        header.nNonce = nonce
        if header.rehash() <= uint256_from_compact(SHARE_BITS):
            break
    else:
        raise RuntimeError("bounded public fixture proof failed")
    share = Share(header.serialize(), current, current.sign(secret))
    current = replace(current, shares_root=shares_root((share,)),
        state_root=state_root((StateEntry(2, share.proof_id),)),
        payouts_root=payouts_root(monetary_outputs((share,), reward=100003,
                                                  fallback_script=current.payout_script)))
    return Manifest(current, current.sign(secret), parent, (), (share,))


def cases(random_cases=256):
    manifest = seed_manifest()
    seed = manifest.serialize()
    yield seed
    yield manifest.envelope.serialize()
    policy = b"\x01" + (3).to_bytes(32, "little") + bytes([len(manifest.envelope.payout_script)]) + manifest.envelope.payout_script
    yield policy
    for offset in range(len(policy)):
        yield policy[:offset]
        altered = bytearray(policy)
        altered[offset] ^= 0xff
        yield bytes(altered)
    yield policy + b"\x00"
    # Truncations and individual byte mutations retain nearly valid structure.
    for length in range(len(seed)):
        yield seed[:length]
    for offset in range(len(seed)):
        altered = bytearray(seed)
        altered[offset] ^= 0xff
        yield bytes(altered)
    yield seed + b"\x00"
    for size in (1, 8, 34, 128, 512, 4096, 65536, 65537):
        yield bytes(size)
        yield b"\xff" * size
    # Specifically attempt nonminimal and excessive CompactSize vectors.
    envelope_size = len(seed_manifest().envelope.serialize())
    parent_start = envelope_size + 65
    parent_end = parent_start + len(seed_manifest().parent_envelope.serialize())
    yield seed[:165] + b"\xfd\x16\x00" + seed[166:]
    yield seed[:165] + b"\x23" + seed[166:]
    yield seed[:parent_end] + b"\xfd\x00\x00" + seed[parent_end + 1:]
    yield seed[:parent_end] + b"\x81" + seed[parent_end + 1:]
    yield seed[:parent_end + 1] + b"\x21" + seed[parent_end + 2:]
    rng = random.Random(0x53504e31)
    for _ in range(random_cases):
        yield bytes(rng.randrange(256) for _ in range(rng.randrange(4097)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New corpus directory")
    parser.add_argument("--random-cases", type=int, default=256)
    args = parser.parse_args()
    if not 0 <= args.random_cases <= 10000:
        parser.error("--random-cases must be between 0 and 10000")
    args.output.mkdir(parents=True, exist_ok=False)
    count = 0
    for raw in cases(args.random_cases):
        path = args.output / hashlib.sha256(raw).hexdigest()
        if not path.exists():
            path.write_bytes(raw)
            count += 1
    print(f"Created {count} distinct deterministic native fuzz seeds")


if __name__ == "__main__":
    main()
