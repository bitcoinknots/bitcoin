#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real header-hash proofs for synthetic coinbase-only share fixtures.

Uses this checkout's primitives. This is NOT full block/transaction/script/UTXO
validation or a live node protocol. Tags are labels, not authenticated owners.
The caller chooses the approved target; no historical assignment is verified.
The zero-payout evidence jobs are not settlement-bearing reward-mining jobs.
"""

from dataclasses import dataclass
from io import BytesIO

from precommit_demo import CBlockHeader, uint256_from_compact  # Sets framework path.
from work_accounting import CreditedRecord, expected_work
from test_framework.blocktools import create_coinbase, script_BIP34_coinbase_height
from test_framework.messages import CBlock, CTransaction, tagged_hash
from test_framework.script import CScript, CScriptInvalidError, OP_TRUE

DEFAULT_BITS = 0x207FFFFF
BASE_BITS = 0x200FFFFF
FIXTURE_TIME = 1_700_000_000
MAGIC = b"SPF1"


class _ExactReader(BytesIO):
    def read(self, size=-1):
        if size < 0 or size > len(self.getbuffer()) - self.tell():
            raise ValueError("truncated fixture")
        return super().read(size)


def _decode(cls, payload):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= 4096:
        raise ValueError("fixture payload must be 1..4096 bytes")
    stream, value = _ExactReader(payload), cls()
    try:
        value.deserialize(stream)
        if stream.tell() != len(payload) or value.serialize() != payload:
            raise ValueError("noncanonical fixture or trailing bytes")
    except (IndexError, OverflowError, TypeError) as error:
        raise ValueError("malformed fixture") from error
    return value


@dataclass(frozen=True)
class ShareProof:
    header: bytes
    coinbase: bytes
    declared_tag: bytes
    pool_id: bytes

    def __post_init__(self):
        if any(type(value) is not bytes for value in
               (self.header, self.coinbase, self.declared_tag, self.pool_id)):
            raise TypeError("proof fields must be immutable bytes")

    @property
    def share_id(self) -> bytes:
        """Header hash in serialized uint256 byte order; does not verify PoW."""
        return _decode(CBlockHeader, self.header).rehash().to_bytes(32, "little")


def _context(tag, parent_hash, height, pool_id):
    if any(type(value) is not bytes or not 1 <= len(value) <= 32 for value in (tag, pool_id)):
        raise ValueError("tag and pool ID must contain 1..32 bytes")
    if type(parent_hash) is not int or not 0 <= parent_hash < (1 << 256):
        raise ValueError("parent must be a uint256")
    if type(height) is not int or not 1 <= height < (1 << 31):
        raise ValueError("height must be a positive int32")


def _target(bits):
    if type(bits) is not int or not 0 < bits < (1 << 32) or bits & 0x00800000:
        raise ValueError("invalid approved compact target")
    target = uint256_from_compact(bits)
    expected_work(target)  # Checks a positive uint256 target.
    return target


def _script(height, tag, pool_id):
    return bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([MAGIC, tag, pool_id]))


def _commitment(parent, height, pool_id, bits):
    payload = parent.to_bytes(32, "little") + height.to_bytes(4, "little")
    payload += bytes([len(pool_id)]) + pool_id + bits.to_bytes(4, "little")
    return int.from_bytes(tagged_hash("Sharepool synthetic approved work", payload), "little")


def _merkle_root(coinbase):
    block = CBlock()
    block.vtx = [coinbase]
    return block.calc_merkle_root()


def make_share(tag: bytes, parent_hash: int, height: int, nonce_seed: int = 0,
               pool_id: bytes = b"pool-A", share_bits: int = DEFAULT_BITS) -> ShareProof:
    """Mine at most 100000 real hashes; distinct seeds select distinct jobs."""
    _context(tag, parent_hash, height, pool_id)
    target = _target(share_bits)
    if type(nonce_seed) is not int or not 0 <= nonce_seed < (1 << 128):
        raise ValueError("nonce_seed must be a uint128")
    coinbase = create_coinbase(height, nValue=0)
    coinbase.vin[0].scriptSig = _script(height, tag, pool_id)
    coinbase.rehash()
    header = CBlockHeader()
    header.m_header_v2 = True
    header.hashPrevBlock, header.m_height = parent_hash, height
    header.hashMerkleRoot, header.m_txcount = _merkle_root(coinbase), 1
    # A share keeps the base-chain nBits; its easier acceptance target is
    # separately approved and committed, never substituted into nBits.
    header.nTime, header.nBits, header.m_extranonce = FIXTURE_TIME, BASE_BITS, nonce_seed
    header.m_mm_rhs = _commitment(parent_hash, height, pool_id, share_bits)
    for nonce in range(100_000):
        header.nNonce = nonce
        if header.rehash() <= target:
            return ShareProof(header.serialize(), coinbase.serialize(), tag, pool_id)
    raise RuntimeError("synthetic share nonce budget exhausted")


def verify_share(share: ShareProof, expected_parent: int, expected_height: int,
                 expected_pool: bytes, allowed_bits: int = DEFAULT_BITS) -> CreditedRecord:
    """Check this fixture's binding and PoW, not general Bitcoin consensus."""
    _context(share.declared_tag, expected_parent, expected_height, expected_pool)
    target = _target(allowed_bits)
    header, coinbase = _decode(CBlockHeader, share.header), _decode(CTransaction, share.coinbase)
    if share.pool_id != expected_pool or header.hashPrevBlock != expected_parent or header.m_height != expected_height:
        raise ValueError("wrong pool, parent, or height")
    if not header.m_header_v2 or header.nBits != BASE_BITS or header.m_txcount != 1:
        raise ValueError("wrong header format, base-chain target, or transaction count")
    if any((header.m_xor_key, header.m_xor_key_mask_clear_bits, header.m_flags,
            header.m_time_offset, header.m_nonce2, header.m_nonce3)):
        raise ValueError("unsupported synthetic header fields or hidden XOR key")
    if header.nVersion != 4 or header.nTime != FIXTURE_TIME:
        raise ValueError("unsupported synthetic version or time")
    if header.m_mm_rhs != _commitment(expected_parent, expected_height, expected_pool, allowed_bits):
        raise ValueError("approved-work commitment mismatch")
    if (len(coinbase.vin) != 1 or len(coinbase.vout) != 1 or coinbase.version != 2
            or coinbase.nLockTime != 0 or not coinbase.wit.is_null()):
        raise ValueError("wrong synthetic coinbase shape")
    txin, txout = coinbase.vin[0], coinbase.vout[0]
    if (txin.prevout.hash != 0 or txin.prevout.n != 0xFFFFFFFF or txin.nSequence != 0xFFFFFFFF
            or txout.nValue != 0 or txout.scriptPubKey != bytes(CScript([OP_TRUE]))):
        raise ValueError("wrong synthetic coinbase input or output")
    prefix = bytes(script_BIP34_coinbase_height(expected_height))
    if not txin.scriptSig.startswith(prefix):
        raise ValueError("wrong coinbase height")
    try:
        fields = list(CScript(txin.scriptSig[len(prefix):]))
    except CScriptInvalidError as error:
        raise ValueError("malformed coinbase tag fields") from error
    if fields != [MAGIC, share.declared_tag, expected_pool] or txin.scriptSig != _script(expected_height, share.declared_tag, expected_pool):
        raise ValueError("coinbase tag/pool differs from declaration or is noncanonical")
    if header.hashMerkleRoot != _merkle_root(coinbase):
        raise ValueError("coinbase is not bound to the header Merkle root")
    if header.rehash() > target:
        raise ValueError("share does not meet the approved target")
    return CreditedRecord(header.sha256.to_bytes(32, "little"), fields[1], expected_work(target))
