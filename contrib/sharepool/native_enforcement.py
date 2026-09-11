#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent wire/fixture builder for the regtest-only native SPN1 profile.

Uses public functional-test Schnorr keys, never production key handling. Native
consensus remains authoritative. Parsing checks canonical wire encoding, not
native ancestor context, signatures, proof eligibility, or transaction validity.
"""

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.key import compute_xonly_pubkey, sign_schnorr, verify_schnorr
from test_framework.messages import CBlockHeader, CTxOut, hash256, ser_uint256, uint256_from_compact
from test_framework.script import CScript, OP_RETURN


SHARE_BITS = 0x207fffff
MAX_SHARE_AGE = 3
MAX_SHARES = 32
MAX_STATE = 128
MAX_MANIFEST = 65536
CHUNK_BYTES = 72
RULES_HASH = int.from_bytes(hash256(b"SharePool/rules/v1\0" +
    struct.pack("<III", SHARE_BITS, MAX_SHARE_AGE, MAX_SHARES)), "little")


def compact_size(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError("invalid CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def vector(raw):
    return compact_size(len(raw)) + raw


def h256(domain, payload):
    return int.from_bytes(hash256(domain + payload), "little")


def merkle_root(leaves):
    level = [ser_uint256(value) for value in leaves]
    if not level:
        return 0
    while len(level) > 1:
        level = [hash256(level[index] + level[min(index + 1, len(level) - 1)])
                 for index in range(0, len(level), 2)]
    return int.from_bytes(level[0], "little")


class Reader:
    def __init__(self, raw):
        if type(raw) is not bytes:
            raise ValueError("wire bytes required")
        self.stream = BytesIO(raw)

    def take(self, size):
        result = self.stream.read(size)
        if len(result) != size:
            raise ValueError("truncated native settlement payload")
        return result

    def uint(self, size):
        return int.from_bytes(self.take(size), "little")

    def size(self, maximum):
        prefix = self.uint(1)
        if prefix < 253:
            result = prefix
        else:
            result = self.uint({253: 2, 254: 4, 255: 8}[prefix])
            if result < {253: 253, 254: 65536, 255: 1 << 32}[prefix]:
                raise ValueError("noncanonical CompactSize")
        if result > maximum:
            raise ValueError("native settlement vector exceeds bound")
        return result

    def variable(self, maximum):
        return self.take(self.size(maximum))


@dataclass(frozen=True)
class Envelope:
    genesis: int
    rules: int
    height: int
    native_parent: int
    pool: int
    public_key: bytes
    payout_script: bytes
    shares_root: int = 0
    state_root: int = 0
    payouts_root: int = 0
    version: int = 1

    def serialize(self):
        if len(self.public_key) != 32 or not 0 <= self.height <= 0xffffffff:
            raise ValueError("invalid envelope key or height")
        return (bytes([self.version]) + ser_uint256(self.genesis) + ser_uint256(self.rules) +
                struct.pack("<I", self.height) + ser_uint256(self.native_parent) +
                ser_uint256(self.pool) + self.public_key + vector(self.payout_script) +
                ser_uint256(self.shares_root) + ser_uint256(self.state_root) + ser_uint256(self.payouts_root))

    @classmethod
    def read(cls, reader):
        version, genesis, rules = reader.uint(1), reader.uint(32), reader.uint(32)
        height, parent, pool = reader.uint(4), reader.uint(32), reader.uint(32)
        public, script = reader.take(32), reader.variable(34)
        return cls(genesis, rules, height, parent, pool, public, script,
                   reader.uint(32), reader.uint(32), reader.uint(32), version)

    @property
    def root(self):
        return h256(b"SharePool/envelope/v1\0", self.serialize())

    @property
    def owner_message(self):
        raw = (ser_uint256(self.genesis) + ser_uint256(self.rules) + struct.pack("<I", self.height) +
               ser_uint256(self.native_parent) + ser_uint256(self.pool) + self.public_key + vector(self.payout_script))
        return hash256(b"SharePool/owner/v1\0" + raw)

    def sign(self, secret):
        if compute_xonly_pubkey(secret)[0] != self.public_key:
            raise ValueError("fixture secret does not own envelope")
        return sign_schnorr(secret, self.owner_message)


@dataclass(frozen=True)
class StateEntry:
    origin_height: int
    proof_id: int

    def serialize(self):
        return struct.pack("<I", self.origin_height) + ser_uint256(self.proof_id)

    @classmethod
    def read(cls, reader):
        return cls(reader.uint(4), reader.uint(32))


def state_root(entries):
    return merkle_root([h256(b"SharePool/state/v1\0", entry.serialize()) for entry in entries])


@dataclass(frozen=True)
class Share:
    header_bytes: bytes
    envelope: Envelope
    owner_signature: bytes

    @property
    def header(self):
        reader = BytesIO(self.header_bytes)
        result = CBlockHeader()
        result.deserialize(reader)
        if reader.read() or result.serialize() != self.header_bytes:
            raise ValueError("noncanonical share header")
        return result

    @property
    def proof_id(self):
        return self.header.rehash()

    def serialize(self):
        if len(self.owner_signature) != 64:
            raise ValueError("Schnorr authorization must contain 64 bytes")
        return self.header_bytes + self.envelope.serialize() + self.owner_signature

    @classmethod
    def read(cls, reader):
        version = reader.take(4)
        size = 164 if int.from_bytes(version, "little") & 0x80000000 else 80
        return cls(version + reader.take(size - 4), Envelope.read(reader), reader.take(64))


def shares_root(shares):
    return merkle_root([h256(b"SharePool/share/v1\0", share.serialize()) for share in shares])


def payouts_root(outputs):
    return h256(b"SharePool/payouts/v1\0", compact_size(len(outputs)) +
                b"".join(output.serialize() for output in outputs))


def monetary_outputs(shares, *, reward, fallback_script):
    if type(reward) is not int or not 0 <= reward <= 21_000_000 * 100_000_000:
        raise ValueError("invalid reward")
    weights = {}
    for share in shares:
        script = share.envelope.payout_script
        weights[script] = weights.get(script, 0) + 1
    if not weights:
        weights[fallback_script] = 1
    total = sum(weights.values())
    amounts = {script: reward * count // total for script, count in weights.items()}
    priority = sorted(weights, key=lambda script: (-(reward * weights[script] % total), script))
    for script in priority[:reward - sum(amounts.values())]:
        amounts[script] += 1
    return [CTxOut(amount, CScript(script)) for script, amount in sorted(amounts.items())]


def derive_state(parent_state, shares, height):
    result = [entry for entry in parent_state if entry.origin_height >= height - MAX_SHARE_AGE]
    result.extend(StateEntry(share.envelope.height, share.proof_id) for share in shares)
    return tuple(sorted(result, key=lambda entry: entry.proof_id))


@dataclass(frozen=True)
class Manifest:
    envelope: Envelope
    owner_signature: bytes
    parent_envelope: object = None
    parent_state: tuple = ()
    shares: tuple = ()

    def serialize(self):
        if len(self.owner_signature) != 64:
            raise ValueError("Schnorr authorization must contain 64 bytes")
        raw = (self.envelope.serialize() + self.owner_signature + bytes([int(self.parent_envelope is not None)]) +
               (self.parent_envelope.serialize() if self.parent_envelope is not None else b"") +
               compact_size(len(self.parent_state)) + b"".join(entry.serialize() for entry in self.parent_state) +
               compact_size(len(self.shares)) + b"".join(share.serialize() for share in self.shares))
        if len(raw) > MAX_MANIFEST:
            raise ValueError("manifest exceeds native profile bound")
        return raw

    @classmethod
    def deserialize(cls, raw):
        if len(raw) > MAX_MANIFEST:
            raise ValueError("manifest exceeds native profile bound")
        reader = Reader(raw)
        envelope, signature, has_parent = Envelope.read(reader), reader.take(64), reader.uint(1)
        if has_parent not in (0, 1):
            raise ValueError("noncanonical parent discriminator")
        parent = Envelope.read(reader) if has_parent else None
        state = tuple(StateEntry.read(reader) for unused in range(reader.size(MAX_STATE)))
        shares = tuple(Share.read(reader) for unused in range(reader.size(MAX_SHARES)))
        result = cls(envelope, signature, parent, state, shares)
        if reader.stream.read() or result.serialize() != raw:
            raise ValueError("trailing or noncanonical manifest bytes")
        if not has_parent and state:
            raise ValueError("activation manifest must have empty parent state")
        for values in (state, shares):
            identities = [item.proof_id for item in values]
            if identities != sorted(set(identities)):
                raise ValueError("unsorted or duplicate proof IDs")
        return result

    frombytes = deserialize

    @property
    def post_state(self):
        return derive_state(self.parent_state, self.shares, self.envelope.height)


def carrier_outputs(manifest):
    raw = manifest.serialize() if isinstance(manifest, Manifest) else bytes(manifest)
    if not raw or len(raw) > MAX_MANIFEST:
        raise ValueError("invalid carrier payload size")
    count = (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES
    return [CTxOut(0, CScript([OP_RETURN, b"SPN1" + struct.pack("<HH", index, count) +
                               raw[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]]))
            for index in range(count)]


def is_payout_script(script):
    return ((len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac") or
            (len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87") or
            (len(script) == 22 and script[:2] == b"\x00\x14") or
            (len(script) == 34 and script[:2] in (b"\x00\x20", b"\x51\x20")))


def parse_coinbase(coinbase):
    """Return (Manifest, monetary_outputs), enforcing canonical carrier layout."""
    money, chunks, witness = [], [], False
    for index, output in enumerate(coinbase.vout):
        script = bytes(output.scriptPubKey)
        if is_payout_script(script) and not chunks and not witness:
            money.append(output)
            continue
        if script.startswith(bytes.fromhex("6a24aa21a9ed")) and index == len(coinbase.vout) - 1 and chunks:
            if output.nValue != 0 or len(script) != 38:
                raise ValueError("invalid witness carrier")
            witness = True
            continue
        try:
            operations = list(CScript(script))
        except Exception:
            raise ValueError("invalid manifest carrier script") from None
        if (output.nValue != 0 or len(operations) != 2 or operations[0] != OP_RETURN or
                type(operations[1]) is not bytes or not operations[1].startswith(b"SPN1") or
                len(operations[1]) < 9 or len(script) > 83 or
                bytes(CScript([OP_RETURN, operations[1]])) != script):
            raise ValueError("invalid manifest carrier")
        data = operations[1]
        chunk_index, count = struct.unpack("<HH", data[4:8])
        payload = data[8:]
        if chunk_index != len(chunks) or not 1 <= count <= (MAX_MANIFEST + 71) // 72:
            raise ValueError("invalid manifest chunk index/count")
        if chunks and count != chunks[0][0]:
            raise ValueError("inconsistent manifest chunk counts")
        if chunk_index >= count or not 1 <= len(payload) <= 72 or (chunk_index != count - 1 and len(payload) != 72):
            raise ValueError("invalid manifest chunk length")
        chunks.append((count, payload))
    if not money or not chunks or chunks[0][0] != len(chunks):
        raise ValueError("incomplete monetary/carrier output layout")
    scripts = [bytes(output.scriptPubKey) for output in money]
    if scripts != sorted(set(scripts)):
        raise ValueError("noncanonical monetary output order")
    return Manifest.deserialize(b"".join(payload for unused, payload in chunks)), tuple(money)


def build_manifest(*, genesis, height, native_parent, pool, secret, payout_script,
                   reward, shares=(), parent_envelope=None, parent_state=()):
    shares = tuple(sorted(shares, key=lambda share: share.proof_id))
    if len(shares) > MAX_SHARES or len(parent_state) > MAX_STATE:
        raise ValueError("profile evidence limit")
    public = compute_xonly_pubkey(secret)[0]
    outputs = monetary_outputs(shares, reward=reward, fallback_script=payout_script)
    env = Envelope(genesis, RULES_HASH, height, native_parent, pool, public, payout_script,
                   shares_root(shares), state_root(derive_state(parent_state, shares, height)), payouts_root(outputs))
    return Manifest(env, env.sign(secret), parent_envelope, tuple(parent_state), shares), outputs


def apply_to_coinbase(block, manifest, outputs, *, witness=False):
    """Bind an existing candidate to complete SPN1 outputs before solving PoW."""
    block.vtx[0].vout = list(outputs) + carrier_outputs(manifest)
    block.vtx[0].rehash()
    block.m_mm_rhs = manifest.envelope.root
    block.m_txcount = len(block.vtx)
    if witness:
        add_witness_commitment(block)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()
    return block


def candidate(*, genesis, native_parent, height, ntime, pool, secret, payout_script,
              shares=(), parent_manifest=None, parent_state=None, fees=0, transactions=(), witness=False):
    coinbase = create_coinbase(height, fees=fees)
    manifest, outputs = build_manifest(genesis=genesis, height=height, native_parent=native_parent,
        pool=pool, secret=secret, payout_script=payout_script, reward=coinbase.vout[0].nValue,
        shares=shares, parent_envelope=parent_manifest.envelope if parent_manifest else None,
        parent_state=(parent_manifest.post_state if parent_manifest and parent_state is None else (parent_state or ())))
    block = create_block(native_parent, coinbase, ntime, version=0x20000000,
                         height=height, header_v2=True, txlist=transactions)
    apply_to_coinbase(block, manifest, outputs, witness=witness)
    return block, manifest


def solve_share(block, manifest, *, start_nonce=0, valid=True):
    header = CBlockHeader(block)
    target = uint256_from_compact(SHARE_BITS)
    for nonce in range(start_nonce, start_nonce + 100000):
        header.nNonce = nonce & 0xffffffff
        header.m_nonce2 = nonce >> 32
        identity = header.rehash()
        if (identity <= target) == valid:
            return Share(header.serialize(), manifest.envelope, manifest.owner_signature)
    raise ValueError("fixture share nonce search exhausted")


def winner_share(block, manifest):
    return Share(CBlockHeader(block).serialize(), manifest.envelope, manifest.owner_signature)
