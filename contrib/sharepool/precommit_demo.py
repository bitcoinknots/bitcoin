#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Synthetic header experiment: a snapshot must be committed before PoW.

This uses this checkout's test-framework CBlockHeader and BLAKE2b header-v2
hashing. It does not produce or validate a block, validate miner shares, agree
on a snapshot, connect peers, or pay miners. The records are opaque toy bytes;
a real protocol would first validate their meaning and agree on their set.

Sorting establishes a canonical order for an already selected set. It cannot
make peers with different sets agree. The root format here is experimental,
not a network protocol, and assigning the whole m_mm_rhs field would require
a namespace/composition convention to coexist with other sidechains.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "test" / "functional"))

from test_framework.messages import (  # noqa: E402
    CBlockHeader,
    uint256_from_compact,
)


DOMAIN = b"knots-sharepool/synthetic-snapshot/v1\x00"
MAX_RECORDS = 1024
MAX_RECORD_BYTES = 4096
SYNTHETIC_BITS = 0x207FFFFF
SYNTHETIC_CONTEXT = hashlib.sha256(b"synthetic chain and round; no live chain").digest()


def _digest(kind: bytes, payload: bytes = b"") -> bytes:
    return hashlib.sha256(DOMAIN + kind + payload).digest()


@dataclass(frozen=True, init=False)
class Snapshot:
    """An immutable, bounded selection of opaque records, not validated shares.

    Context is a 32-byte synthetic chain/round identifier. Record order is
    lexicographic on the raw bytes. Exact duplicate records are rejected;
    identifying semantic duplicates is deliberately outside this experiment.
    """

    context: bytes
    records: tuple[bytes, ...]

    def __init__(self, context: bytes, records: Iterable[bytes]):
        if not isinstance(context, (bytes, bytearray)) or len(context) != 32:
            raise ValueError("context must contain exactly 32 bytes")
        copied = []
        for record in records:
            if len(copied) == MAX_RECORDS:
                raise ValueError("too many opaque records")
            if not isinstance(record, (bytes, bytearray)):
                raise TypeError("each opaque record must be bytes or bytearray")
            if not 0 < len(record) <= MAX_RECORD_BYTES:
                raise ValueError("opaque record size is outside the experiment bounds")
            copied.append(bytes(record))
        canonical = tuple(sorted(copied))
        if len(set(canonical)) != len(canonical):
            raise ValueError("duplicate opaque record")
        object.__setattr__(self, "context", bytes(context))
        object.__setattr__(self, "records", canonical)

    @property
    def root(self) -> bytes:
        """Return a domain-separated root binding context and record count.

        Leaves: SHA256(domain || 0x00 || uint32_be(length) || record).
        Nodes:  SHA256(domain || 0x01 || left || right); duplicate an odd tail.
        Empty:  SHA256(domain || 0x02).
        Root:   SHA256(domain || 0x03 || context || uint64_be(count) || tree).

        The outer count removes odd-tail ambiguity between tree sizes.
        """
        level = [_digest(b"\x00", len(record).to_bytes(4, "big") + record)
                 for record in self.records]
        if not level:
            tree = _digest(b"\x02")
        else:
            while len(level) > 1:
                if len(level) % 2:
                    level.append(level[-1])
                level = [_digest(b"\x01", level[i] + level[i + 1])
                         for i in range(0, len(level), 2)]
            tree = level[0]
        return _digest(b"\x03", self.context + len(self.records).to_bytes(8, "big") + tree)


def make_header(snapshot: Snapshot) -> CBlockHeader:
    """Create a synthetic v2 header, with no corresponding transactions/chain."""
    header = CBlockHeader()
    header.m_header_v2 = True
    header.nVersion = 4
    header.hashPrevBlock = int.from_bytes(SYNTHETIC_CONTEXT, "little")
    header.hashMerkleRoot = int.from_bytes(hashlib.sha256(b"no real transactions").digest(), "little")
    header.nTime = 1_700_000_000
    header.nBits = SYNTHETIC_BITS
    header.m_height = 1
    header.m_txcount = 1
    # Deliberately public/zero: this does not exercise hidden-key pooling or
    # demonstrate any protection against withholding a discovered block.
    header.m_xor_key = 0
    # Preserve the digest's raw bytes in the field's uint256 serialization.
    header.m_mm_rhs = int.from_bytes(snapshot.root, "little")
    return header


def meets_synthetic_target(header: CBlockHeader) -> bool:
    """Freshly hash, including modified fields; this is only a target check."""
    target = uint256_from_compact(header.nBits)
    if not 0 < target < (1 << 256):
        raise ValueError("synthetic target must be a positive uint256")
    return header.rehash() <= target


def solve_header(header: CBlockHeader, max_attempts: int = 100_000) -> int:
    """Bounded nonce search; return attempts, without any chain validation."""
    if not 0 < max_attempts <= 100_000:
        raise ValueError("max_attempts must be between 1 and 100000")
    for attempt in range(1, max_attempts + 1):
        header.nNonce = attempt - 1
        if meets_synthetic_target(header):
            return attempt
    raise RuntimeError("synthetic search exhausted its nonce budget")


def run_demo() -> dict:
    records = [b"toy record A", b"toy record B", b"toy record C"]
    snapshot = Snapshot(SYNTHETIC_CONTEXT, records)
    header = make_header(snapshot)
    attempts = solve_header(header)
    original_hash = header.hash

    # A later record yields a NEW snapshot, never an update to the mined one.
    later_snapshot = Snapshot(snapshot.context, [*snapshot.records, b"toy record D arrived later"])
    changed = CBlockHeader(header)
    changed.m_mm_rhs = int.from_bytes(later_snapshot.root, "little")
    changed_meets_target = meets_synthetic_target(changed)

    return {
        "scope": "synthetic header only; no block/share validation, chain acceptance, networking, or payout",
        "hash_implementation": "this checkout's test_framework.messages.CBlockHeader (header v2)",
        "xor_key": "zero/public; hidden-key anti-withholding is not demonstrated",
        "snapshot_root_hex_raw": snapshot.root.hex(),
        "snapshot_record_count": len(snapshot.records),
        "synthetic_target_hex": f"{uint256_from_compact(header.nBits):064x}",
        "nonce": header.nNonce,
        "attempts": attempts,
        "original_hash": original_hash,
        "original_meets_synthetic_target": meets_synthetic_target(header),
        "later_snapshot_root_hex_raw": later_snapshot.root.hex(),
        "same_nonce_changed_root_hash": changed.hash,
        "hash_changed": changed.hash != original_hash,
        "changed_root_meets_synthetic_target": changed_meets_target,
        "lesson": "Changing the committed snapshot changes the hash, so recheck PoW. A changed hash can still meet this easy target by chance.",
    }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
