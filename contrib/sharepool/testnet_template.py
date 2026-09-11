#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded Testnet4 GBT-to-Sia adapter for hardware integration tests.

This constructs real Knots header-v2 candidates, including all GBT transactions.
It does not implement script/UTXO validation, settlement consensus, RPC, device
control, or block broadcasting. A caller must authenticate its node and verify
the Testnet4 genesis before obtaining GBT, then use native proposal validation.
Only the unmasked Sia ASIC profile with fixed consensus time is supported.
"""

from dataclasses import dataclass
from io import BytesIO
import hashlib

from precommit_demo import CBlockHeader, uint256_from_compact  # Framework path.
from test_framework.blocktools import get_legacy_sigopcount_tx, script_BIP34_coinbase_height
from test_framework.messages import (
    CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,
    blake2b_header_hash_components, hash256, ser_compact_size,
)
from test_framework.script import CScript

MAX_BYTES = 4_000_000
MAX_MONEY = 21_000_000 * 100_000_000
TESTNET4_ACTIVATION = 150_308
SUPPORTED_RULES = frozenset(("!segwit", "!blake2b"))


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid " + name)
    return value


def _bytes(value, low, high, name):
    if type(value) is not bytes or not low <= len(value) <= high:
        raise ValueError("invalid " + name)
    return value


def _hex(value, low, high, name):
    if (type(value) is not str or len(value) % 2 or
            not low * 2 <= len(value) <= high * 2):
        raise ValueError("invalid " + name)
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("invalid " + name) from error
    if result.hex() != value.lower():
        raise ValueError("noncanonical " + name)
    return result


class _Reader(BytesIO):
    def read(self, size=-1):
        if size < 0 or size > len(self.getbuffer()) - self.tell():
            raise ValueError("truncated transaction/header")
        return super().read(size)


def _decode(kind, raw):
    _bytes(raw, 1, MAX_BYTES, "serialized object")
    obj, stream = kind(), _Reader(raw)
    try:
        obj.deserialize(stream)
        if stream.tell() != len(raw) or obj.serialize() != raw:
            raise ValueError("noncanonical transaction/header")
    except (IndexError, OverflowError, TypeError) as error:
        raise ValueError("malformed transaction/header") from error
    return obj


def _search_normalized(raw):
    h = _decode(CBlockHeader, raw)
    h.nNonce = h.m_nonce2 = h.m_nonce3 = h.m_time_offset = h.m_extranonce = 0
    return h.serialize()


@dataclass(frozen=True)
class TestnetTemplate:
    header_bytes: bytes
    coinbase: bytes
    transactions: tuple
    commitment: bytes
    weight_limit: int
    size_limit: int

    @property
    def header(self):
        """Return a copy; callers cannot mutate the saved job."""
        return _decode(CBlockHeader, self.header_bytes)

    @property
    def job_id(self):
        return hashlib.sha256(b"sharepool/testnet4/sia-job/v1\0" + self.header_bytes).hexdigest()

    @property
    def coinbase_without_witness(self):
        return _decode(CTransaction, self.coinbase).serialize_without_witness()

    def block(self, header_bytes=None):
        raw = self.header_bytes if header_bytes is None else header_bytes
        if _search_normalized(raw) != self.header_bytes:
            raise ValueError("proof changes fixed template fields")
        return raw + ser_compact_size(1 + len(self.transactions)) + self.coinbase + b"".join(self.transactions)


@dataclass(frozen=True)
class SiaProof:
    header: bytes
    work: bytes
    hash: bytes  # BLAKE2b digest / conventional displayed hash order.
    block: bytes

    @property
    def hash_int(self):
        return int.from_bytes(self.hash, "big")

    @property
    def display_hash(self):
        return self.hash.hex()


def build_template(gbt, payouts, commitment, tag, headline=None, *, chain="testnet4"):
    """Build one immutable test job; payouts are (script bytes, satoshis).

    Every advertised transaction is retained and its txid/wtxid/weight checked.
    All available reward must be allocated explicitly. Coinbase extranonce is
    fixed: Sia extranonce changes only m_extranonce in the Bitcoin header.
    The `chain` argument is a caller-verified RPC result, not network detection.
    """
    if chain != "testnet4" or type(gbt) is not dict:
        raise ValueError("only authenticated Testnet4 templates are supported")
    rules = gbt.get("rules")
    if (type(rules) is not list or any(type(rule) is not str for rule in rules)
            or "!blake2b" not in rules or "!segwit" not in rules
            or any(rule.startswith("!") and rule not in SUPPORTED_RULES for rule in rules)
            or "signet_challenge" in gbt):
        raise ValueError("unsupported GBT consensus rules")
    version = _integer(gbt.get("version"), 0, 0xffffffff, "version")
    if not version & 0x80000000:
        raise ValueError("header-v2 version required")
    required = _integer(gbt.get("vbrequired", 0), 0, 0xffffffff, "required version bits")
    if version & required != required:
        raise ValueError("missing required version bits")
    for name in ("header_flags", "h1_flags", "time_offset", "xor_key_mask_clear_bits"):
        if name in gbt and _integer(gbt[name], 0, 0xffffffff, name) != 0:
            raise ValueError("unsupported GBT " + name)
    if "xor_key" in gbt and _hex(gbt["xor_key"], 16, 16, "XOR key") != bytes(16):
        raise ValueError("masked work is unsupported")
    for name in ("mm_rhs", "merge_mining_rhs"):
        if name in gbt and _hex(gbt[name], 32, 32, name) != bytes(32):
            raise ValueError("existing merge-mining commitment requires composition")
    if "header_version" in gbt and gbt["header_version"] != 2:
        raise ValueError("unsupported header version")
    _bytes(commitment, 32, 32, "settlement commitment")
    _bytes(tag, 1, 32, "miner tag")
    height = _integer(gbt.get("height"), TESTNET4_ACTIVATION + 1, 0x7fffffff, "post-activation height")
    now = _integer(gbt.get("curtime"), 0, 0xffffffff, "current time")
    mintime = _integer(gbt.get("mintime"), 0, 0xffffffff, "minimum time")
    if now < mintime:
        raise ValueError("template time is below its minimum")
    bits = int.from_bytes(_hex(gbt.get("bits"), 4, 4, "nBits"), "big")
    target = uint256_from_compact(bits)
    if bits & 0x00800000 or target <= 0 or target >= 1 << 224:
        raise ValueError("invalid compact target")
    if "target" in gbt and int.from_bytes(_hex(gbt["target"], 32, 32, "target"), "big") != target:
        raise ValueError("GBT target disagrees with nBits")
    previous = int.from_bytes(_hex(gbt.get("previousblockhash"), 32, 32, "previous block hash"), "big")
    reward = _integer(gbt.get("coinbasevalue"), 0, MAX_MONEY, "coinbase value")
    weight_limit = _integer(gbt.get("weightlimit"), 1, MAX_BYTES, "weight limit")
    size_limit = _integer(gbt.get("sizelimit"), 1, MAX_BYTES, "size limit")
    sigop_limit = _integer(gbt.get("sigoplimit"), 1, 80000, "sigop limit")
    tx_entries = gbt.get("transactions")
    if type(tx_entries) is not list or len(tx_entries) > 65534:
        raise ValueError("transaction count limit")
    transactions, objects, txids, fee_total, payload_size, sigops = [], [], set(), 0, 0, 0
    for index, entry in enumerate(tx_entries, 1):
        if type(entry) is not dict:
            raise ValueError("invalid GBT transaction")
        raw = _hex(entry.get("data"), 1, MAX_BYTES, "transaction data")
        payload_size += len(raw)
        if payload_size > MAX_BYTES:
            raise ValueError("GBT transaction byte limit")
        tx = _decode(CTransaction, raw)
        if not tx.vin or not tx.vout or not tx.is_valid():
            raise ValueError("invalid transaction shape or output value")
        if any(v.prevout.hash == 0 and v.prevout.n == 0xffffffff for v in tx.vin):
            raise ValueError("GBT contains a coinbase transaction")
        if len({(v.prevout.hash, v.prevout.n) for v in tx.vin}) != len(tx.vin):
            raise ValueError("transaction has duplicate inputs")
        txid = hash256(tx.serialize_without_witness())[::-1].hex()
        if txid in txids or entry.get("txid") != txid or entry.get("hash") != tx.getwtxid():
            raise ValueError("duplicate or inconsistent GBT transaction hashes")
        txids.add(txid)
        if _integer(entry.get("weight"), 1, MAX_BYTES, "transaction weight") != tx.get_weight():
            raise ValueError("incorrect transaction weight")
        depends = entry.get("depends", [])
        if (type(depends) is not list
                or any(type(dep) is not int or not 1 <= dep < index for dep in depends)
                or len(set(depends)) != len(depends)):
            raise ValueError("invalid transaction dependencies")
        fee_total += _integer(entry.get("fee"), 0, MAX_MONEY, "transaction fee")
        sigops += _integer(entry.get("sigops"), 0, 80000, "transaction sigops")
        transactions.append(raw)
        objects.append(tx)
    halvings = height // 210000
    subsidy = (50 * 100_000_000) >> halvings if halvings < 64 else 0
    if fee_total + subsidy != reward:
        raise ValueError("coinbase reward differs from subsidy plus advertised fees")
    if type(payouts) not in (tuple, list) or not 1 <= len(payouts) <= 64:
        raise ValueError("payout count limit")
    outputs, scripts, total = [], set(), 0
    for payout in payouts:
        if type(payout) not in (tuple, list) or len(payout) != 2:
            raise ValueError("invalid payout")
        script, amount = payout
        _bytes(script, 1, 10000, "payout script")
        _integer(amount, 1, MAX_MONEY, "payout amount")
        if script in scripts or script[0] == 0x6a:
            raise ValueError("duplicate or unspendable payout script")
        scripts.add(script)
        total += amount
        outputs.append(CTxOut(amount, CScript(script)))
    if total != reward:
        raise ValueError("payouts must exactly allocate the coinbase value")
    script_sig = bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([tag]))
    aux = gbt.get("coinbaseaux", {})
    if type(aux) is not dict or any(type(key) is not str for key in aux):
        raise ValueError("invalid coinbase auxiliary data")
    for key in sorted(aux):
        script_sig += _hex(aux[key], 0, 100, "coinbase auxiliary data")
    if headline is not None:
        script_sig += bytes(CScript([_bytes(headline, 1, 64, "headline")]))
    if not 2 <= len(script_sig) <= 100:
        raise ValueError("coinbase scriptSig exceeds consensus bounds")
    cb = CTransaction()
    cb.vin = [CTxIn(COutPoint(0, 0xffffffff), CScript(script_sig), 0xffffffff)]
    cb.vout = outputs
    witness = any(not tx.wit.is_null() for tx in objects) or "default_witness_commitment" in gbt
    if witness:
        witness_root = CBlock.get_merkle_root([bytes(32)] + [hash256(tx.serialize()) for tx in objects])
        witness_script = bytes.fromhex("6a24aa21a9ed") + hash256(witness_root.to_bytes(32, "little") + bytes(32))
        if "default_witness_commitment" in gbt and _hex(gbt["default_witness_commitment"], 38, 38, "witness commitment") != witness_script:
            raise ValueError("witness commitment disagrees with full transaction data")
        cb.vout.append(CTxOut(0, CScript(witness_script)))
        cb.wit.vtxinwit = [CTxInWitness()]
        cb.wit.vtxinwit[0].scriptWitness.stack = [bytes(32)]
    h = CBlockHeader()
    h.m_header_v2, h.nVersion = True, version & 0x7fffffff
    h.hashPrevBlock, h.m_height, h.nTime, h.nBits = previous, height, now, bits
    h.m_txcount = 1 + len(objects)
    h.m_mm_rhs = int.from_bytes(commitment, "little")
    h.hashMerkleRoot = CBlock.get_merkle_root([hash256(cb.serialize_without_witness())] + [hash256(tx.serialize_without_witness()) for tx in objects])
    job = TestnetTemplate(h.serialize(), cb.serialize(), tuple(transactions), commitment, weight_limit, size_limit)
    count_size = len(ser_compact_size(h.m_txcount))
    weight = 4 * (len(job.header_bytes) + count_size) + cb.get_weight() + sum(tx.get_weight() for tx in objects)
    if weight > weight_limit or len(job.block()) > size_limit:
        raise ValueError("assembled candidate exceeds GBT size/weight limit")
    if sigops + get_legacy_sigopcount_tx(cb) * 4 > sigop_limit:
        raise ValueError("assembled candidate exceeds GBT sigop limit")
    return job


def sia_notify(job, prefix, clean=True):
    """Return mining.notify params; advertise prefix in mining.subscribe."""
    _bytes(prefix, 4, 4, "connection extranonce prefix")
    if type(clean) is not bool:
        raise ValueError("invalid clean jobs flag")
    h = job.header
    components = blake2b_header_hash_components(h)
    coinb1 = bytes(3) + components["h2"] + bytes(4)
    ntime = bytes(4) + h.nTime.to_bytes(4, "little")
    return [job.job_id, bytes(components["asic_input"][:32]).hex(), coinb1.hex(), "", [],
            format(h.nVersion, "08x"), format(h.nBits, "08x"), ntime.hex(), clean]


def _sia_u64(value, name):
    if type(value) is not str or len(value) not in (8, 16):
        raise ValueError("Sia " + name + " must have 8 or 16 hex characters")
    raw = _hex(value, len(value) // 2, len(value) // 2, "Sia " + name)
    return int.from_bytes(raw, "little" if len(raw) == 8 else "big")


def proof_from_sia(job, prefix, extranonce2, ntime, nonce):
    """Reconstruct and cross-check exact hardware work; no target acceptance.

    Difficulty policy and duplicate/stale admission belong to the caller. This
    function always compares the hardware hash with the full native header hash.
    """
    _bytes(prefix, 4, 4, "connection extranonce prefix")
    _bytes(extranonce2, 8, 8, "miner extranonce")
    time_value, nonce_value = _sia_u64(ntime, "time"), _sia_u64(nonce, "nonce")
    notify = sia_notify(job, prefix)
    root = hashlib.blake2b(bytes(1) + bytes.fromhex(notify[2]) + prefix + extranonce2, digest_size=32).digest()
    work = bytes.fromhex(notify[1]) + nonce_value.to_bytes(8, "little") + time_value.to_bytes(8, "little") + root
    work_hash = hashlib.blake2b(work, digest_size=32).digest()
    h = job.header
    h.nNonce, h.m_nonce2 = nonce_value & 0xffffffff, nonce_value >> 32
    h.m_time_offset, h.m_nonce3 = time_value & 0xffffffff, time_value >> 32
    h.m_extranonce = int.from_bytes(bytes(4) + prefix + extranonce2, "little")
    raw = h.serialize()
    if h.rehash() != int.from_bytes(work_hash, "big"):
        raise ValueError("hardware hash does not match reconstructed Knots header")
    return SiaProof(raw, work, work_hash, job.block(raw))
