#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Canonical flat-hash snapshots for opt-in native regtest profiles.

This codec does not select consensus validity. Full native RPC validation is
required before mining. The only Merkle construction used by candidate() is the
ordinary Bitcoin transaction commitment, never the settlement commitment.
"""
from dataclasses import dataclass, replace
import hashlib
import struct
import weakref
from io import BytesIO
from typing import NamedTuple

from native_enforcement import (Envelope as _Envelope, Reader as _Reader,
    Share as _Share, StateEntry, SHARE_BITS, MAX_SHARE_AGE, compact_size, vector,
    h256, monetary_outputs, derive_state, is_payout_script, compute_xonly_pubkey,
    verify_schnorr, sign_schnorr, create_coinbase, create_block, add_witness_commitment)
from native_mining_gate import parse_block, immutable_header, template_id, _preflight_block
from native_signer import NativeSigner, SignerError, REGTEST_GENESIS
from test_framework.messages import CBlock, CBlockHeader, CTransaction, CTxOut, hash256, ser_uint256, uint256_from_compact
from test_framework.script import CScript

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_TEMPLATE_BYTES = 4_000_000
MAX_DEPENDENCY_DEPTH = 64
MAX_DEPENDENCY_BYTES = 64 * 1024 * 1024
MAX_DEPENDENCY_SHARES = MAX_DEPENDENCY_BYTES // 512
MAX_COMPACT_SHARES = MAX_SNAPSHOT_BYTES // 512
SHARE_TARGET_SHIFT = 10
MAX_EXPANDED_TEMPLATE_BYTES = 512 * 1024 * 1024
MAX_TEMPLATE_TX_REFERENCES = 2_000_000
MAX_ORIGIN_CHECKS = 2048
RULES_HASH = h256(b"SharePool/rules/v4\0", struct.pack("<IIIIIIIIII", SHARE_BITS, SHARE_TARGET_SHIFT,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS))
LEDGER_VERSION = 5
TIDES_VERSION = 6
COMPACT_TIDES_VERSION = 7
VARIABLE_TIDES_VERSION = 8
MIN_SHARE_WORK_BITS, MAX_SHARE_WORK_BITS = 0, 255
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_SETTLEMENT_BYTES = 1024 * 1024
MAX_CERTIFICATE_BYTES = 4 * 1024 * 1024
LEDGER_RULES_HASH = h256(b"SharePool/rules/v5\0", struct.pack("<IIIIIIIIIIIII", SHARE_BITS, SHARE_TARGET_SHIFT,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
    MAX_LEDGER_BYTES, MAX_SETTLEMENT_BYTES, MAX_CERTIFICATE_BYTES))
TIDES_RULES_HASH = h256(b"SharePool/rules/v6\0", struct.pack("<13I", SHARE_BITS, SHARE_TARGET_SHIFT,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
    MAX_CERTIFICATE_BYTES, 8, 2))
COMPACT_TIDES_RULES_HASH = h256(b"SharePool/rules/v7\0", struct.pack("<15I", SHARE_BITS, SHARE_TARGET_SHIFT,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
    MAX_CERTIFICATE_BYTES, 8, 2, 1, MAX_DEPENDENCY_SHARES))
VARIABLE_TIDES_RULES_HASH = h256(b"SharePool/rules/v8\0", struct.pack("<15I", MIN_SHARE_WORK_BITS, MAX_SHARE_WORK_BITS,
    MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
    MAX_CERTIFICATE_BYTES, 8, 2, 1, MAX_DEPENDENCY_SHARES))


def is_compact_tides_profile(version):
    return version in (COMPACT_TIDES_VERSION, VARIABLE_TIDES_VERSION)


def is_tides_profile(version):
    return version == TIDES_VERSION or is_compact_tides_profile(version)


def rules_hash(version=4):
    if version == 4:
        return RULES_HASH
    if version == LEDGER_VERSION:
        return LEDGER_RULES_HASH
    if version == TIDES_VERSION:
        return TIDES_RULES_HASH
    if version == COMPACT_TIDES_VERSION:
        return COMPACT_TIDES_RULES_HASH
    if version == VARIABLE_TIDES_VERSION:
        return VARIABLE_TIDES_RULES_HASH
    raise ValueError("unsupported hash-only profile")


def _domain(name, version):
    return f"SharePool/{name}/v{version}\0".encode("ascii")


def snapshot_hash(raw):
    """Historical raw-preimage selection, including malformed v4/v5 inputs."""
    if type(raw) is not bytes:
        raise ValueError("snapshot hash requires exact bytes")
    return h256(_domain("snapshot", LEDGER_VERSION if raw[:1] == b"\x05" else 4), raw)


def profile_snapshot_hash(raw, version):
    """TIDES profiles hash every preimage in their domain, before decoding."""
    rules_hash(version)
    if type(raw) is not bytes:
        raise ValueError("snapshot hash requires exact bytes")
    return h256(_domain("snapshot", version), raw) if is_tides_profile(version) else snapshot_hash(raw)


PHYSICAL_FIELDS = ("nNonce", "m_nonce2", "m_nonce3", "m_extranonce", "m_time_offset")


class Reader(_Reader):
    def __init__(self, raw):
        super().__init__(raw)
        self.length = len(raw)

    def count(self, minimum_bytes):
        """No vector allocation or iteration beyond the actual bounded input."""
        count = self.size(MAX_SNAPSHOT_BYTES // minimum_bytes)
        if count > (self.length - self.stream.tell()) // minimum_bytes:
            raise ValueError("snapshot vector exceeds remaining bytes")
        return count


@dataclass(frozen=True)
class EnvelopeV2(_Envelope):
    version: int = 4
    share_work_bits: int = 0

    def serialize(self):
        integers = (self.genesis, self.rules, self.native_parent, self.pool,
                    self.shares_root, self.state_root, self.payouts_root)
        if (any(type(value) is not int or not 0 <= value < 1 << 256 for value in integers) or
                self.version not in (4, LEDGER_VERSION, TIDES_VERSION, COMPACT_TIDES_VERSION, VARIABLE_TIDES_VERSION) or self.rules != rules_hash(self.version) or self.pool == 0 or
                type(self.height) is not int or not 0 < self.height <= 0xffffffff or
                type(self.public_key) is not bytes or len(self.public_key) != 32 or
                type(self.payout_script) is not bytes or not is_payout_script(self.payout_script) or
                type(self.share_work_bits) is not int or not MIN_SHARE_WORK_BITS <= self.share_work_bits <= MAX_SHARE_WORK_BITS or
                (self.version != VARIABLE_TIDES_VERSION and self.share_work_bits != 0) or
                any((self.shares_root, self.state_root, self.payouts_root))):
            raise ValueError("invalid v4 envelope or nonzero reserved roots")
        raw = super().serialize()
        # Preserve every legacy byte; v8 adds its assignment after the script,
        # immediately before the three reserved roots.
        return raw[:-96] + bytes((self.share_work_bits,)) + raw[-96:] if self.version == VARIABLE_TIDES_VERSION else raw

    @classmethod
    def read(cls, reader):
        version, genesis, rules = reader.uint(1), reader.uint(32), reader.uint(32)
        height, parent, pool = reader.uint(4), reader.uint(32), reader.uint(32)
        public, script = reader.take(32), reader.variable(34)
        work_bits = reader.uint(1) if version == VARIABLE_TIDES_VERSION else 0
        return cls(genesis, rules, height, parent, pool, public, script,
                   reader.uint(32), reader.uint(32), reader.uint(32), version, work_bits)

    @property
    def root(self):
        raise ValueError("v4 header commits to the complete snapshot, not its envelope")

    @property
    def owner_message(self):
        raise ValueError("v4 authorization requires the exact snapshot and job")


@dataclass(frozen=True)
class Share(_Share):
    @property
    def header_facts(self):
        """Immutable facts about exact canonical bytes, owned by this proof.

        Headers returned by ``header`` remain independent mutable objects. The
        memo never retains one, and replacing the bytes invalidates the memo.
        Mutable byte buffers are parsed afresh rather than used as cache keys.
        Canonical decoding fills this fixed-size memo before cache accounting.
        """
        raw = self.header_bytes
        cached = getattr(self, "_header_facts", None)
        if type(raw) is bytes and cached is not None and cached[0] is raw:
            return cached[1]
        header = self.header
        identity = header.rehash()
        search = (struct.pack("<III", header.nNonce, header.m_nonce2, header.m_nonce3) +
                  header.m_extranonce.to_bytes(16, "little") + struct.pack("<I", header.m_time_offset))
        for name in PHYSICAL_FIELDS:
            setattr(header, name, 0)
        normalized = header.serialize()
        facts = _HeaderFacts(identity, int.from_bytes(hashlib.sha256(normalized).digest(), "big"),
            normalized, search, header.nBits, header.m_height, header.hashPrevBlock)
        if type(raw) is bytes:
            object.__setattr__(self, "_header_facts", (raw, facts))
        return facts

    @property
    def proof_id(self):
        return self.header_facts.proof_id

    @classmethod
    def read(cls, reader):
        version = reader.take(4)
        if not int.from_bytes(version, "little") & 0x80000000:
            raise ValueError("v2 native share header required")
        return cls(version + reader.take(160), EnvelopeV2.read(reader), reader.take(64))


class _HeaderFacts(NamedTuple):
    proof_id: int
    template_id: int
    immutable_header: bytes
    search_fields: bytes
    native_bits: int
    height: int
    native_parent: int


def parse_share(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 1024:
        raise ValueError("share exceeds byte bound")
    reader = Reader(raw)
    result = Share.read(reader)
    if reader.stream.read() or result.serialize() != raw:
        raise ValueError("noncanonical share")
    result.header  # Require exact canonical native serialization.
    return result


def normalize_template(block_or_bytes):
    raw = block_or_bytes if type(block_or_bytes) is bytes else block_or_bytes.serialize()
    block = parse_block(raw)
    if not block.m_header_v2:
        raise ValueError("v2 native template required")
    for name in PHYSICAL_FIELDS:
        setattr(block, name, 0)
    return block.serialize()


@dataclass(frozen=True)
class TemplateRecord:
    template_id: int
    data: bytes

    @classmethod
    def from_block(cls, block_or_bytes):
        raw = normalize_template(block_or_bytes)
        return cls(int(template_id(parse_block(raw)), 16), raw)

    def serialize(self):
        if (type(self.template_id) is not int or not 0 <= self.template_id < 1 << 256 or
                type(self.data) is not bytes or not 1 <= len(self.data) <= MAX_TEMPLATE_BYTES or
                normalize_template(self.data) != self.data):
            raise ValueError("invalid normalized template record")
        block = parse_block(self.data)
        if (int(template_id(block), 16) != self.template_id or block.m_txcount != len(block.vtx) or
                block.hashMerkleRoot != block.calc_merkle_root()):
            raise ValueError("template body does not match its native header")
        return ser_uint256(self.template_id) + vector(self.data)

    @classmethod
    def read(cls, reader):
        result = cls(reader.uint(32), reader.variable(MAX_TEMPLATE_BYTES))
        result.serialize()
        return result


class _TransactionBytes:
    __slots__ = ("raw", "wtxid", "txid", "__weakref__")
    def __init__(self, raw, wtxid):
        header = CBlockHeader()
        header.m_header_v2, header.m_txcount = True, 1
        _preflight_block(header.serialize() + b"\x01" + raw)
        stream, tx = BytesIO(raw), CTransaction()
        tx.deserialize(stream)
        if stream.read() or tx.serialize_with_witness() != raw:
            raise ValueError("noncanonical table transaction")
        object.__setattr__(self, "raw", raw)
        object.__setattr__(self, "wtxid", wtxid)
        object.__setattr__(self, "txid", hash256(tx.serialize_without_witness()))

    def __setattr__(self, name, value):
        raise AttributeError("shared transaction bytes are immutable")

    def __deepcopy__(self, memo):
        return self


_TRANSACTION_BYTES = weakref.WeakValueDictionary()


def _transaction(raw):
    if type(raw) is not bytes:
        raise ValueError("transaction table requires immutable bytes")
    identity = hash256(raw)
    previous = _TRANSACTION_BYTES.get(identity)
    if previous is not None:
        if previous.raw != raw:
            raise ValueError("transaction hash collision")
        return previous
    value = _TransactionBytes(raw, identity)
    _TRANSACTION_BYTES[identity] = value
    return value


class CompactTemplateRecord:
    """Full template represented by immutable shared transaction bytes."""
    __slots__ = ("template_id", "header_bytes", "transactions", "expanded_bytes")
    def __init__(self, identity, header_bytes, transactions):
        transactions = tuple(transactions)
        if (type(identity) is not int or not 0 <= identity < 1 << 256 or type(header_bytes) is not bytes or
                any(type(tx) is not _TransactionBytes for tx in transactions)):
            raise ValueError("compact template requires immutable canonical fields")
        header = CBlockHeader()
        stream = BytesIO(header_bytes)
        header.deserialize(stream)
        if (stream.read() or header.serialize() != header_bytes or not header.m_header_v2 or
                any(getattr(header, name) for name in PHYSICAL_FIELDS) or
                header.m_txcount != len(transactions) or not transactions or
                int(template_id(header), 16) != identity):
            raise ValueError("compact template header or identity")
        if header.hashMerkleRoot != CBlock.get_merkle_root([tx.txid for tx in transactions]):
            raise ValueError("compact template transaction root")
        size = len(header_bytes) + len(compact_size(len(transactions))) + sum(len(tx.raw) for tx in transactions)
        if size > MAX_TEMPLATE_BYTES:
            raise ValueError("template byte bound")
        object.__setattr__(self, "template_id", identity)
        object.__setattr__(self, "header_bytes", header_bytes)
        object.__setattr__(self, "transactions", tuple(transactions))
        object.__setattr__(self, "expanded_bytes", size)

    def __setattr__(self, name, value):
        raise AttributeError("compact template records are immutable")

    def __deepcopy__(self, memo):
        return self

    @classmethod
    def from_record(cls, record):
        if isinstance(record, cls):
            return record
        record.serialize() # Preserve canonical full-body checks for external records.
        block = parse_block(record.data)
        return cls(record.template_id, CBlockHeader(block).serialize(),
                   tuple(_transaction(tx.serialize_with_witness()) for tx in block.vtx))

    @property
    def data(self):
        return self.header_bytes + compact_size(len(self.transactions)) + b"".join(tx.raw for tx in self.transactions)

    def serialize(self):
        return ser_uint256(self.template_id) + vector(self.data)


@dataclass(frozen=True)
class LedgerCredit:
    admitted_height: int
    origin_height: int
    proof_id: int
    pool: int
    native_bits: int
    payout_script: bytes

    @property
    def order(self):
        return self.admitted_height, self.proof_id

    def serialize(self):
        if (any(type(v) is not int or not 0 < v <= 0xffffffff for v in
                (self.admitted_height, self.origin_height, self.native_bits)) or
                self.origin_height > self.admitted_height or
                any(type(v) is not int or not 0 <= v < 1 << 256 for v in (self.proof_id, self.pool)) or
                not self.pool or type(self.payout_script) is not bytes or not is_payout_script(self.payout_script)):
            raise ValueError("invalid confirmed credit")
        share_target(self.native_bits)
        return (struct.pack("<II", self.admitted_height, self.origin_height) + ser_uint256(self.proof_id) +
                ser_uint256(self.pool) + struct.pack("<I", self.native_bits) + vector(self.payout_script))

    @classmethod
    def read(cls, reader):
        return cls(reader.uint(4), reader.uint(4), reader.uint(32), reader.uint(32), reader.uint(4), reader.variable(34))


@dataclass(frozen=True)
class OriginCertificate:
    origin_height: int
    native_parent: int
    identity: int
    snapshot_hash: int

    def serialize(self):
        if (type(self.origin_height) is not int or not 0 < self.origin_height <= 0xffffffff or
                any(type(v) is not int or not 0 <= v < 1 << 256 for v in
                    (self.native_parent, self.identity, self.snapshot_hash))):
            raise ValueError("invalid confirmed origin certificate")
        return (struct.pack("<I", self.origin_height) + ser_uint256(self.native_parent) +
                ser_uint256(self.identity) + ser_uint256(self.snapshot_hash))

    @classmethod
    def read(cls, reader):
        return cls(reader.uint(4), reader.uint(32), reader.uint(32), reader.uint(32))


def origin_certificate(record):
    record = CompactTemplateRecord.from_record(record)
    header = CBlockHeader()
    header.deserialize(BytesIO(record.header_bytes))
    identity = h256(b"SharePool/origin-certificate/v5\0", record.header_bytes +
        compact_size(len(record.transactions)) + b"".join(tx.wtxid for tx in record.transactions))
    return OriginCertificate(header.m_height, header.hashPrevBlock, identity, header.m_mm_rhs)


def apply_ledger_state(snapshot, parent):
    """Construction helper only. Native validation authenticates parent and proofs.

    Selection depends only on the actual parent: fresh receipts cannot change the
    current payout. Unselected confirmed credits remain payable without expiry.
    """
    if snapshot.envelope.version != LEDGER_VERSION:
        raise ValueError("confirmed ledger requires v5")
    if parent is not None and (parent.envelope.version != LEDGER_VERSION or
            parent.envelope.height + 1 != snapshot.envelope.height):
        raise ValueError("ledger parent profile or height")
    height, pool = snapshot.envelope.height, snapshot.envelope.pool
    prior = parent.pending if parent is not None else ()
    selected, carried, size, full = [], [], 0, False
    for credit in prior:
        if credit.pool != pool:
            carried.append(credit)
            continue
        cost = len(credit.serialize())
        if full or len(compact_size(len(selected) + 1)) + size + cost > MAX_SETTLEMENT_BYTES:
            full = True
            carried.append(credit)
        else:
            selected.append(credit)
            size += cost
    minimum = max(1, height - MAX_SHARE_AGE)
    state = [entry for entry in (parent.post_state if parent else ()) if entry.origin_height >= minimum]
    seen = {entry.proof_id for entry in (parent.post_state if parent else ())} | {c.proof_id for c in prior}
    certificates = {cert.identity: cert for cert in (parent.certificates if parent else ()) if cert.origin_height >= minimum}
    records = {record.template_id: record for record in snapshot.templates}
    for share in snapshot.shares:
        if share.proof_id in seen:
            raise ValueError("duplicate admitted proof")
        seen.add(share.proof_id)
        state.append(StateEntry(share.envelope.height, share.proof_id))
        carried.append(LedgerCredit(height, share.envelope.height, share.proof_id,
            share.envelope.pool, share.header.nBits, share.envelope.payout_script))
        record = records.get(int(template_id(share.header), 16))
        if record is None:
            raise ValueError("admitted origin template missing")
        certificate = origin_certificate(record)
        certificates[certificate.identity] = certificate
    pending = tuple(sorted(carried, key=lambda credit: credit.order))
    certs = tuple(sorted(certificates.values(), key=lambda cert: ser_uint256(cert.identity)))
    if (len(compact_size(len(pending))) + sum(len(c.serialize()) for c in pending) > MAX_LEDGER_BYTES or
            len(compact_size(len(certs))) + sum(len(c.serialize()) for c in certs) > MAX_CERTIFICATE_BYTES):
        raise ValueError("confirmed ledger capacity; carry provisional work to a later admission")
    return replace(snapshot, pending=pending, settled=tuple(selected), certificates=certs,
                   post_state=tuple(sorted(state, key=lambda entry: entry.proof_id)))


def apply_tides_state(snapshot, parent):
    """Derive the TIDES admission checkpoint; native validation remains mandatory.

    This only constructs recent anti-replay state, origin certificates and the
    chained flat history hash. It does not derive rewards from historical work.
    Original job pool and payout script remain immutable; no address registry or
    ownership assertion is introduced.
    """
    if not is_tides_profile(snapshot.envelope.version):
        raise ValueError("TIDES history requires v6, v7 or v8")
    if parent is not None and (parent.envelope.version != snapshot.envelope.version or
            parent.envelope.height + 1 != snapshot.envelope.height or
            parent.envelope.genesis != snapshot.envelope.genesis or parent.envelope.rules != snapshot.envelope.rules or
            not parent.history_head or parent.pending or parent.settled):
        raise ValueError("TIDES parent profile or height")
    if snapshot.pending or snapshot.settled:
        raise ValueError("TIDES cannot carry v5 pending or settled credits")
    height = snapshot.envelope.height
    minimum = max(1, height - MAX_SHARE_AGE)
    if parent is not None:
        parent.serialize()
        parent_minimum = max(1, parent.envelope.height - MAX_SHARE_AGE)
        if (any(not parent_minimum <= entry.origin_height <= parent.envelope.height for entry in parent.post_state) or
                any(not parent_minimum <= cert.origin_height <= parent.envelope.height or not cert.identity or not cert.snapshot_hash
                    for cert in parent.certificates)):
            raise ValueError("TIDES parent admission or certificate age")
    state = [entry for entry in (parent.post_state if parent else ()) if entry.origin_height >= minimum]
    seen = {entry.proof_id for entry in (parent.post_state if parent else ())}
    certificates = {cert.identity: cert for cert in (parent.certificates if parent else ()) if cert.origin_height >= minimum}
    records = {record.template_id: record for record in snapshot.templates}
    if len(records) != len(snapshot.templates):
        raise ValueError("TIDES duplicate template")
    records = {identity: CompactTemplateRecord.from_record(record) for identity, record in records.items()}
    origin_certificates = {}
    admissions = []
    for share in sorted(snapshot.shares, key=lambda value: value.proof_id):
        facts = share.header_facts
        if (share.envelope.version != snapshot.envelope.version or
                not minimum <= share.envelope.height <= height or facts.height != share.envelope.height):
            raise ValueError("TIDES admission profile or age")
        if share.proof_id == 0 and snapshot.envelope.version != VARIABLE_TIDES_VERSION:
            raise ValueError("legacy TIDES admission cannot use a zero proof identity")
        proof_target(share)
        if share.proof_id in seen:
            raise ValueError("duplicate admitted proof")
        seen.add(share.proof_id)
        state.append(StateEntry(share.envelope.height, share.proof_id))
        credit = LedgerCredit(height, share.envelope.height, share.proof_id,
            share.envelope.pool, facts.native_bits, share.envelope.payout_script).serialize()
        # These are v8 history admission bytes, not a change to the v5 ledger.
        # The assignment comes from each immutable origin, never the new job.
        admissions.append(credit + (bytes((share.envelope.share_work_bits,))
            if snapshot.envelope.version == VARIABLE_TIDES_VERSION else b""))
        record = records.get(facts.template_id)
        if record is None:
            raise ValueError("admitted origin template missing")
        if record.header_bytes != facts.immutable_header:
            raise ValueError("TIDES admission template differs from proof")
        if record.template_id not in origin_certificates:
            origin_certificates[record.template_id] = origin_certificate(record)
        certificate = origin_certificates[record.template_id]
        certificates[certificate.identity] = certificate
    certs = tuple(sorted(certificates.values(), key=lambda cert: ser_uint256(cert.identity)))
    if len(compact_size(len(certs))) + sum(len(cert.serialize()) for cert in certs) > MAX_CERTIFICATE_BYTES:
        raise ValueError("TIDES certificate capacity; carry provisional work to a later admission")
    history = (ser_uint256(snapshot.envelope.genesis) + ser_uint256(snapshot.envelope.native_parent) +
               struct.pack("<I", height) + ser_uint256(parent.history_head if parent else 0) +
               compact_size(len(admissions)) + b"".join(admissions))
    return replace(snapshot, certificates=certs, history_head=h256(_domain("history", snapshot.envelope.version), history),
                   post_state=tuple(sorted(state, key=lambda entry: entry.proof_id)))


def materialize_compact_state(snapshot, *, parent_snapshot, activation_height=1, on_snapshot=None, capture=None,
                              state_cache=None, signature_cache=None):
    """Reconstruct omitted state using at most three actual native ancestors.

    The callback must authenticate the requested native block hash and height,
    and its sidechain opening; gate callers do that with exact raw headers.
    This bounded helper verifies owner signatures and recent admission state.
    Native scripts, proof of work and chain validity remain mandatory. A capture
    resolver may reuse operation-owned encodings of its immutable inputs only;
    external mutable snapshots must always be captured afresh. An optional
    bounded state cache exposes get/put for exact (activation, profile, raw
    prefix) keys. Hits replace only deterministic signature/state replay; all
    native ancestry reads, byte/proof charges and observers still run first.
    A separate signature memo may retain only exact successful BIP340 checks,
    without retaining alternate jobs' potentially large derived state arrays.
    """
    if (type(activation_height) is not int or not 1 <= activation_height <= 0x7fffffff or
            not is_compact_tides_profile(snapshot.envelope.version) or snapshot.envelope.height < activation_height):
        raise ValueError("compact state profile or activation mismatch")
    capture = capture or (lambda value: value.capture())
    sequence, seen, total, proofs = [capture(snapshot)], set(), 0, 0
    snapshot = sequence[0].snapshot
    first = max(activation_height, snapshot.envelope.height - MAX_SHARE_AGE)
    while sequence[-1].snapshot.envelope.height > first:
        child = sequence[-1].snapshot
        previous = parent_snapshot(child.envelope.native_parent, child.envelope.height - 1)
        if previous is None:
            raise ValueError("missing compact native ancestry snapshot")
        previous_encoding = capture(previous)
        previous = previous_encoding.snapshot
        if (previous.envelope.version != snapshot.envelope.version or
                previous.envelope.height + 1 != child.envelope.height or
                previous.envelope.genesis != snapshot.envelope.genesis or
                previous.envelope.rules != snapshot.envelope.rules):
            raise ValueError("compact native ancestry binding mismatch")
        sequence.append(previous_encoding)
    sequence.reverse()
    # Charge the complete authenticated suffix before consulting cached state.
    # In particular, a warm hit cannot hide lost evidence or observer refusal.
    for encoding in sequence:
        value, raw, identity = encoding.snapshot, encoding.raw, encoding.hash
        if identity not in seen:
            seen.add(identity)
            total += len(raw)
            proofs += len(value.shares)
            if total > MAX_DEPENDENCY_BYTES or proofs > MAX_DEPENDENCY_SHARES:
                raise ValueError("compact ancestry exceeds dependency budget")
            if on_snapshot is not None:
                on_snapshot(value, raw)

    raw_sequence = tuple(encoding.raw for encoding in sequence)
    def key(length):
        return activation_height, snapshot.envelope.version, raw_sequence[:length]

    parent, start, penultimate = None, 0, None
    if state_cache is not None:
        for length in range(len(sequence), 0, -1):
            cached = state_cache.get(key(length))
            if cached is None:
                continue
            if len(cached.post_state) > MAX_SNAPSHOT_BYTES // 36:
                raise ValueError("derived compact state count exceeds original bound")
            if length == len(sequence):
                if cached.history_head != snapshot.history_head:
                    raise ValueError("compact history head differs from native ancestry")
                return cached
            # Prefixes store the computed head, not the ancestor's committed
            # head. Only the latter feeds the next history link. Exact prefix
            # keys also bind the left boundary: a shifted age window must miss.
            parent = replace(cached, history_head=sequence[length - 1].snapshot.history_head)
            start = length
            break

    for index in range(start, len(sequence)):
        encoding = sequence[index]
        value = encoding.snapshot
        verify = verify_schnorr if signature_cache is None else signature_cache.verify
        if not verify(value.envelope.public_key, value.owner_signature, encoding.owner_message):
            raise ValueError("compact native ancestry owner authorization")
        derived = apply_tides_state(replace(value, post_state=(), certificates=()), parent)
        if len(derived.post_state) > MAX_SNAPSHOT_BYTES // 36:
            raise ValueError("derived compact state count exceeds original bound")
        if index == len(sequence) - 1:
            if derived.history_head != value.history_head:
                raise ValueError("compact history head differs from native ancestry")
            if state_cache is not None:
                # Retain at most two candidate states, and publish neither on a
                # failed target. The shared parent prefix benefits other jobs
                # without retaining each intermediate admission-state tuple.
                if penultimate is not None:
                    state_cache.put(*penultimate)
                state_cache.put(key(len(sequence)), derived)
            return derived
        if state_cache is not None and index == len(sequence) - 2:
            penultimate = key(index + 1), derived
        # Earlier history is outside this suffix. Its on-chain head remains
        # committed by the authenticated ancestor, while transient state is new.
        parent = replace(derived, history_head=value.history_head)
    raise ValueError("missing compact target")


def credit_outputs(credits, reward, fallback_script):
    weights = {}
    for credit in credits:
        weights[credit.payout_script] = weights.get(credit.payout_script, 0) + share_work(credit.native_bits)
    return weighted_outputs(weights, reward, fallback_script)


def _compact_share_jobs(records, shares):
    """Derive one exact owner descriptor per used template, in template order.

    The dictionary is only compression. Native validation still authenticates
    each descriptor against its exact signed origin snapshot and full job body.
    """
    if len(shares) > MAX_COMPACT_SHARES:
        raise ValueError("compact share count exceeds original work bound")
    by_id = {record.template_id: index for index, record in enumerate(records)}
    jobs, encoded, envelopes = {}, [], {}
    for share in shares:
        facts = share.header_facts
        index = by_id.get(facts.template_id)
        if index is None or records[index].header_bytes != facts.immutable_header:
            raise ValueError("compact proof does not match an exact declared template")
        if type(share.owner_signature) is not bytes or len(share.owner_signature) != 64:
            raise ValueError("compact job authorization must contain 64 bytes")
        # Exact EnvelopeV2 fields are frozen and validation requires their byte
        # fields to be immutable. Share one serialization only in this operation.
        key = id(share.envelope)
        if type(share.envelope) is EnvelopeV2 and key in envelopes:
            envelope = envelopes[key]
        else:
            envelope = share.envelope.serialize()
            if type(share.envelope) is EnvelopeV2:
                envelopes[key] = envelope
        descriptor = envelope, share.owner_signature
        if index in jobs and jobs[index] != descriptor:
            raise ValueError("inconsistent compact job owner descriptor")
        jobs[index] = descriptor
        encoded.append((index, facts.search_fields))
    ordered = sorted(jobs)
    indexes = {template: index for index, template in enumerate(ordered)}
    descriptors = tuple(compact_size(index) + b"".join(jobs[index]) for index in ordered)
    proofs = tuple(compact_size(indexes[template]) + search for template, search in encoded)
    return descriptors, proofs


@dataclass(frozen=True)
class Snapshot:
    envelope: EnvelopeV2
    owner_signature: bytes
    templates: tuple = ()
    shares: tuple = ()
    post_state: tuple = ()
    payouts: tuple = ()
    job_commitment: int = 0
    pending: tuple = ()
    settled: tuple = ()
    certificates: tuple = ()
    history_head: int = 0

    def serialize(self):
        if not isinstance(self.envelope, EnvelopeV2) or any(not isinstance(share.envelope, EnvelopeV2) for share in self.shares):
            raise ValueError("snapshot and proof origins require hash-only envelopes")
        if any(share.envelope.version != self.envelope.version for share in self.shares):
            raise ValueError("proof profile differs from settlement")
        if self.envelope.version == 4 and (self.pending or self.settled or self.certificates):
            raise ValueError("v4 cannot carry confirmed ledger state")
        if type(self.history_head) is not int or not 0 <= self.history_head < 1 << 256:
            raise ValueError("history head must be an unsigned 256-bit integer")
        if not is_tides_profile(self.envelope.version) and self.history_head:
            raise ValueError("legacy snapshots cannot carry a TIDES history head")
        if is_tides_profile(self.envelope.version) and (self.pending or self.settled):
            raise ValueError("TIDES cannot carry v5 pending or settled credits")
        if type(self.owner_signature) is not bytes or len(self.owner_signature) != 64:
            raise ValueError("owner authorization must contain 64 bytes")
        if type(self.job_commitment) is not int or not 0 <= self.job_commitment < 1 << 256:
            raise ValueError("job commitment must be an unsigned 256-bit integer")
        template_ids = [ser_uint256(record.template_id) for record in self.templates]
        if template_ids != sorted(set(template_ids)):
            raise ValueError("templates must use unique serialized-uint256 byte order")
        for values in ((self.shares,) if is_compact_tides_profile(self.envelope.version) else (self.shares, self.post_state)):
            ids = [item.proof_id for item in values]
            if ids != sorted(set(ids)):
                raise ValueError("proofs and state must use unique numeric proof order")
        scripts = [bytes(output.scriptPubKey) for output in self.payouts]
        if (scripts != sorted(set(scripts)) or (not scripts and not is_tides_profile(self.envelope.version)) or
                any(not is_payout_script(script) for script in scripts)):
            raise ValueError("payouts must use unique script-byte order")
        if any(type(output.nValue) is not int or not 0 <= output.nValue <= 21_000_000 * 100_000_000 for output in self.payouts):
            raise ValueError("payout amount outside money range")
        records = tuple(CompactTemplateRecord.from_record(record) for record in self.templates)
        if (sum(record.expanded_bytes for record in records) > MAX_EXPANDED_TEMPLATE_BYTES or
                sum(len(record.transactions) for record in records) > MAX_TEMPLATE_TX_REFERENCES):
            raise ValueError("expanded template budget")
        table = {tx.wtxid: tx for record in records for tx in record.transactions}
        ordered = sorted(table)
        indexes = {identity: index for index, identity in enumerate(ordered)}
        result = bytearray(self.envelope.serialize() + self.owner_signature + ser_uint256(self.job_commitment))
        def append(raw):
            if len(result) + len(raw) > MAX_SNAPSHOT_BYTES:
                raise ValueError("snapshot exceeds byte bound")
            result.extend(raw)
        append(compact_size(len(ordered)))
        for identity in ordered:
            append(vector(table[identity].raw))
        append(compact_size(len(records)))
        for record in records:
            append(ser_uint256(record.template_id) + record.header_bytes + compact_size(len(record.transactions)))
            for tx in record.transactions:
                append(compact_size(indexes[tx.wtxid]))
        if is_compact_tides_profile(self.envelope.version):
            descriptors, proofs = _compact_share_jobs(records, self.shares)
            append(compact_size(len(descriptors)))
            for descriptor in descriptors:
                append(descriptor)
            append(compact_size(len(proofs)))
            for proof in proofs:
                append(proof)
            # Transient state and certificates are not wire evidence, even if
            # supplied by a caller. Materialization replaces and bounds them.
            collections = (self.payouts,)
        else:
            collections = (self.shares, self.post_state, self.payouts)
        if self.envelope.version == LEDGER_VERSION:
            for credits, budget in ((self.pending, MAX_LEDGER_BYTES), (self.settled, MAX_SETTLEMENT_BYTES)):
                keys = [credit.order for credit in credits]
                if keys != sorted(set(keys)) or len(compact_size(len(credits))) + sum(len(c.serialize()) for c in credits) > budget:
                    raise ValueError("credit order or byte budget")
            collections += (self.pending, self.settled)
        if self.envelope.version in (LEDGER_VERSION, TIDES_VERSION):
            identities = [ser_uint256(cert.identity) for cert in self.certificates]
            if identities != sorted(set(identities)) or len(compact_size(len(self.certificates))) + sum(len(c.serialize()) for c in self.certificates) > MAX_CERTIFICATE_BYTES:
                raise ValueError("certificate order or byte budget")
            if not is_compact_tides_profile(self.envelope.version):
                collections += (self.certificates,)
        for values in collections:
            append(compact_size(len(values)))
            for item in values:
                append(item.serialize())
        if is_tides_profile(self.envelope.version):
            append(ser_uint256(self.history_head))
        return bytes(result)

    @classmethod
    def deserialize(cls, raw):
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot exceeds byte bound")
        reader = Reader(raw)
        envelope, signature, job = EnvelopeV2.read(reader), reader.take(64), reader.uint(32)
        transactions = []
        for _ in range(reader.count(11)):
            tx = _transaction(reader.variable(MAX_TEMPLATE_BYTES))
            if transactions and transactions[-1].wtxid >= tx.wtxid:
                raise ValueError("transaction table order")
            transactions.append(tx)
        templates, used, references, expanded = [], set(), 0, 0
        for _ in range(reader.count(198)):
            identity, header = reader.uint(32), reader.take(164)
            count = reader.count(1)
            if references + count > MAX_TEMPLATE_TX_REFERENCES:
                raise ValueError("template reference budget")
            references += count
            selected = []
            body_size = len(header) + len(compact_size(count))
            for _ in range(count):
                index = reader.size(len(transactions))
                if index >= len(transactions):
                    raise ValueError("transaction table index")
                tx = transactions[index]
                body_size += len(tx.raw)
                if body_size > MAX_TEMPLATE_BYTES:
                    raise ValueError("expanded template byte bound")
                selected.append(tx)
                used.add(index)
            expanded += body_size
            if expanded > MAX_EXPANDED_TEMPLATE_BYTES:
                raise ValueError("expanded snapshot budget")
            templates.append(CompactTemplateRecord(identity, header, selected))
        if len(used) != len(transactions):
            raise ValueError("unused transaction table entry")
        templates = tuple(templates)
        if is_compact_tides_profile(envelope.version):
            jobs, used_jobs = [], set()
            for _ in range(reader.count(349)):
                index = reader.size(len(templates))
                if index >= len(templates) or jobs and jobs[-1][0] >= index:
                    raise ValueError("compact job template index or order")
                job_envelope, job_signature = EnvelopeV2.read(reader), reader.take(64)
                if job_envelope.version != envelope.version:
                    raise ValueError("compact job profile mismatch")
                jobs.append((index, job_envelope, job_signature))
            count = reader.count(33)
            if count > MAX_COMPACT_SHARES:
                raise ValueError("compact share count exceeds original work bound")
            decoded_shares = []
            for _ in range(count):
                job_index = reader.size(len(jobs))
                if job_index >= len(jobs):
                    raise ValueError("compact proof job index")
                index, job_envelope, job_signature = jobs[job_index]
                header = CBlockHeader()
                header.deserialize(BytesIO(templates[index].header_bytes))
                header.nNonce, header.m_nonce2, header.m_nonce3 = reader.uint(4), reader.uint(4), reader.uint(4)
                header.m_extranonce, header.m_time_offset = reader.uint(16), reader.uint(4)
                decoded_shares.append(Share(header.serialize(), job_envelope, job_signature))
                used_jobs.add(job_index)
            if len(used_jobs) != len(jobs):
                raise ValueError("unused compact job descriptor")
            shares, state = tuple(decoded_shares), ()
        else:
            shares = tuple(Share.read(reader) for _ in range(reader.count(512)))
            state = tuple(StateEntry.read(reader) for _ in range(reader.count(36)))
        payouts = tuple(CTxOut(reader.uint(8), CScript(reader.variable(34))) for _ in range(reader.count(31)))
        pending, settled, certificates, history_head = (), (), (), 0
        if envelope.version == LEDGER_VERSION:
            pending = tuple(LedgerCredit.read(reader) for _ in range(reader.count(99)))
            settled = tuple(LedgerCredit.read(reader) for _ in range(reader.count(99)))
        if envelope.version in (LEDGER_VERSION, TIDES_VERSION):
            certificates = tuple(OriginCertificate.read(reader) for _ in range(reader.count(100)))
        if is_tides_profile(envelope.version):
            history_head = reader.uint(32)
        result = cls(envelope, signature, templates, shares, state, payouts, job, pending, settled, certificates, history_head)
        if reader.stream.read() or result.serialize() != raw:
            raise ValueError("trailing or noncanonical snapshot bytes")
        return result

    frombytes = deserialize

    def capture(self):
        """Capture the current canonical bytes for reuse within one operation.

        Snapshot.payouts may contain mutable CTxOut objects, so this never caches
        by Snapshot identity. A later call observes and validates their edits.
        """
        return SnapshotEncoding(self)

    @property
    def contents_hash(self):
        return h256(_domain("contents", self.envelope.version), replace(self, owner_signature=bytes(64)).serialize())

    @property
    def signing_payload(self):
        return self.envelope.serialize() + ser_uint256(self.job_commitment) + ser_uint256(self.contents_hash)

    @property
    def owner_message(self):
        return hash256(_domain("owner", self.envelope.version) + self.signing_payload)

    @property
    def hash(self):
        return profile_snapshot_hash(self.serialize(), self.envelope.version)

    @property
    def hash_hex(self):
        return f"{self.hash:064x}"


@dataclass(frozen=True)
class _CapturedOutput:
    nValue: int
    scriptPubKey: bytes

    def serialize(self):
        return struct.pack("<q", self.nValue) + vector(self.scriptPubKey)


class SnapshotEncoding:
    """An immutable canonical byte capture, with a detached read-only view.

    Hashes authenticate these bytes only. This object is not a validation cache
    or proof of native validity. Its lifetime and retention belong to the caller.
    """
    __slots__ = ("raw", "hash", "contents_hash", "signing_payload", "owner_message", "_snapshot")

    def __init__(self, snapshot):
        raw = snapshot.serialize()
        reader = Reader(raw)
        envelope = EnvelopeV2.read(reader)
        boundary = reader.stream.tell()
        reader.take(64)
        job = reader.take(32)
        # Only the authorization bytes are zeroed for the contents hash. Stream
        # the exact preimage instead of copying a potentially 16 MiB snapshot.
        digest = hashlib.sha256(_domain("contents", envelope.version))
        view = memoryview(raw)
        digest.update(view[:boundary])
        digest.update(bytes(64))
        digest.update(view[boundary + 64:])
        contents = int.from_bytes(hashlib.sha256(digest.digest()).digest(), "little")
        payload = raw[:boundary] + job + ser_uint256(contents)
        for name, value in (("raw", raw), ("hash", profile_snapshot_hash(raw, envelope.version)),
                ("contents_hash", contents), ("signing_payload", payload),
                ("owner_message", hash256(_domain("owner", envelope.version) + payload)), ("_snapshot", None)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("snapshot encodings are immutable")

    @property
    def snapshot(self):
        if self._snapshot is None:
            decoded = Snapshot.deserialize(self.raw)
            # All other decoded records contain only immutable bytes, integers,
            # tuples and frozen records. Never retain an external CTxOut here.
            detached = replace(decoded, payouts=tuple(_CapturedOutput(output.nValue, bytes(output.scriptPubKey))
                for output in decoded.payouts))
            object.__setattr__(self, "_snapshot", detached)
        return self._snapshot


def job_hash(block):
    normalized = parse_block(normalize_template(block))
    normalized.m_mm_rhs = 0
    return h256(b"SharePool/job/v4\0", normalized.serialize())


def share_target(native_bits, version=4, share_work_bits=None):
    rules_hash(version)
    if version == VARIABLE_TIDES_VERSION:
        if type(share_work_bits) is not int or not MIN_SHARE_WORK_BITS <= share_work_bits <= MAX_SHARE_WORK_BITS:
            raise ValueError("v8 requires an explicit assigned work exponent")
    elif share_work_bits is not None and (type(share_work_bits) is not int or share_work_bits != 0):
        raise ValueError("legacy profiles cannot carry assigned work")
    if type(native_bits) is not int or not 0 < native_bits <= 0xffffffff or native_bits & 0x00800000:
        raise ValueError("invalid native target")
    exponent = native_bits >> 24
    mantissa = native_bits & 0x007fffff
    target = mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))
    size = (target.bit_length() + 7) // 8
    compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    compact |= size << 24
    if not 0 < target < 1 << 256 or compact != native_bits:
        raise ValueError("noncanonical native target")
    if version == VARIABLE_TIDES_VERSION:
        return (1 << (256 - share_work_bits)) - 1
    if is_tides_profile(version):
        desired = max(1, ((1 << 256) // (target + 1)) >> SHARE_TARGET_SHIFT)
        work = 1 << (desired.bit_length() - 1)
        return (1 << 256) // work - 1
    return min(target << SHARE_TARGET_SHIFT, uint256_from_compact(SHARE_BITS))


def share_work(native_bits, version=4, share_work_bits=None):
    return (1 << 256) // (share_target(native_bits, version, share_work_bits) + 1)


def proof_target(share):
    """Assigned target from the proof's origin, not the current mining job."""
    return share_target(share.header_facts.native_bits, share.envelope.version, share.envelope.share_work_bits)


def proof_work(share):
    return share_work(share.header_facts.native_bits, share.envelope.version, share.envelope.share_work_bits)


def work_outputs(shares, reward, fallback_script):
    weights = {}
    for share in shares:
        script = share.envelope.payout_script
        weights[script] = weights.get(script, 0) + proof_work(share)
    return weighted_outputs(weights, reward, fallback_script)


def weighted_outputs(weights, reward, fallback_script):
    weights = dict(weights)
    if not weights:
        weights[fallback_script] = 1
    total = sum(weights.values())
    values = [(script, *divmod(reward * weight, total)) for script, weight in weights.items()]
    values.sort(key=lambda value: (-value[2], value[0]))
    extra = reward - sum(value[1] for value in values)
    return tuple(CTxOut(amount + (index < extra), CScript(script))
                 for script, amount, index in sorted((script, amount, index)
                     for index, (script, amount, _) in enumerate(values)))


def attest(block, snapshot, *, secret=None, sign_owner=None):
    snapshot = replace(snapshot, job_commitment=job_hash(block), owner_signature=bytes(64))
    signature = sign_schnorr(secret, snapshot.owner_message) if secret is not None else sign_owner(snapshot)
    if type(signature) is not bytes or len(signature) != 64 or not verify_schnorr(snapshot.envelope.public_key, signature, snapshot.owner_message):
        raise ValueError("owner signer returned invalid hash-only job authorization")
    snapshot = replace(snapshot, owner_signature=signature)
    block.m_mm_rhs = snapshot.hash
    block.rehash()
    return snapshot


class HashSigner(NativeSigner):
    """Native private-key adapter signs a policy-bound exact-job statement."""
    def sign_owner(self, snapshot):
        if not isinstance(snapshot, Snapshot):
            raise SignerError("hash-only signer requires a complete snapshot")
        envelope = snapshot.envelope
        if (envelope.genesis != REGTEST_GENESIS or envelope.pool != self.pool or
                envelope.payout_script != self.payout_script or envelope.public_key != self.public_key or
                not 0 < envelope.height < 0x7fffffff or envelope.native_parent == 0 or not snapshot.job_commitment):
            raise SignerError("snapshot violates local hash-only signer policy")
        try:
            payload = snapshot.signing_payload
        except ValueError as error:
            raise SignerError(str(error)) from None
        signature = self._invoke("sign-job", payload, 64)
        if not verify_schnorr(self.public_key, signature, snapshot.owner_message):
            raise SignerError("local hash-only signer signature failed verification")
        return signature


def build_snapshot(*, genesis, height, native_parent, pool, payout_script, reward,
                   secret=None, public_key=None, sign_owner=None, templates=(), shares=(), parent_state=(),
                   version=4, parent_snapshot=None, share_work_bits=0):
    if secret is not None:
        if public_key is not None or sign_owner is not None:
            raise ValueError("choose a fixture secret or external signer")
        public_key = compute_xonly_pubkey(secret)[0]
    elif type(public_key) is not bytes or len(public_key) != 32 or not callable(sign_owner):
        raise ValueError("external signer requires public key and sign_owner")
    shares = tuple(sorted(shares, key=lambda share: share.proof_id))
    records = tuple(CompactTemplateRecord.from_record(record if isinstance(record, (TemplateRecord, CompactTemplateRecord)) else TemplateRecord.from_block(record)) for record in templates)
    records = tuple(sorted(records, key=lambda record: ser_uint256(record.template_id)))
    envelope = EnvelopeV2(genesis, rules_hash(version), height, native_parent, pool, public_key, payout_script,
                          version=version, share_work_bits=share_work_bits)
    signature = bytes(64)
    # A v6 proposal does not claim an allocation from its own admissions. Only
    # native history-aware construction derives the actual reward and payouts.
    payouts = ((CTxOut(0, CScript(payout_script)),) if is_tides_profile(version) else
               work_outputs(shares, reward=reward, fallback_script=payout_script))
    result = Snapshot(envelope, signature, records, shares, derive_state(parent_state, shares, height), payouts)
    if version == LEDGER_VERSION:
        result = apply_ledger_state(result, parent_snapshot)
        result = replace(result, payouts=credit_outputs(result.settled, reward, payout_script))
    elif is_tides_profile(version):
        result = apply_tides_state(result, parent_snapshot)
    result.serialize()
    return result


def candidate(*, genesis, native_parent, height, ntime, pool, payout_script,
              secret=None, public_key=None, sign_owner=None, templates=(), shares=(),
              parent_snapshot=None, parent_state=None, fees=0, transactions=(), witness=False, reward=None, native_bits=SHARE_BITS, version=4):
    if is_tides_profile(version):
        raise ValueError("TIDES jobs require the native history-aware builder")
    coinbase = create_coinbase(height, fees=fees)
    snapshot = build_snapshot(genesis=genesis, height=height, native_parent=native_parent,
        pool=pool, payout_script=payout_script, reward=coinbase.vout[0].nValue if reward is None else reward,
        secret=secret, public_key=public_key, sign_owner=sign_owner, templates=templates, shares=shares,
        parent_state=(parent_snapshot.post_state if parent_snapshot is not None and parent_state is None else (parent_state or ())),
        version=version, parent_snapshot=parent_snapshot)
    coinbase.vout = list(snapshot.payouts)
    coinbase.rehash()
    block = create_block(native_parent, coinbase, ntime, version=0x20000000,
                         height=height, header_v2=True, txlist=transactions)
    block.nBits = native_bits
    if witness:
        add_witness_commitment(block)
    block.m_txcount = len(block.vtx)
    block.hashMerkleRoot = block.calc_merkle_root()
    snapshot = attest(block, snapshot, secret=secret, sign_owner=sign_owner)
    return block, snapshot


def solve_share(block, snapshot, *, start_nonce=0, valid=True):
    header = CBlockHeader(block)
    target = share_target(header.nBits, snapshot.envelope.version, snapshot.envelope.share_work_bits)
    for nonce in range(start_nonce, start_nonce + 100000):
        header.nNonce, header.m_nonce2 = nonce & 0xffffffff, nonce >> 32
        if (header.rehash() <= target) == valid:
            return Share(header.serialize(), snapshot.envelope, snapshot.owner_signature)
    raise ValueError("fixture share nonce search exhausted")


def winner_share(block, snapshot):
    return Share(CBlockHeader(block).serialize(), snapshot.envelope, snapshot.owner_signature)
