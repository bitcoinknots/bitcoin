#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Authenticated miner registry experiment, not production cryptography.

Uses this checkout's real secp256k1 ECDSA test implementation, which is slow,
does not protect secrets, and is unsafe for production keys. Changes authorize
exact predecessor roots. Gossip does not select a canonical registry branch:
the parent ledger must anchor history and validators must replay its changes.
Tags and keys are unique within one snapshot, not proof of separate operators.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))
from test_framework.key import ECKey, ECPubKey, ORDER  # noqa: E402


NETWORK_ID = b"sharepool-live-v1"
MAX_ENTRIES = 1024
MAX_TAG_BYTES = 64
MAX_SCRIPT_BYTES = 10000
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_SEQUENCE = (1 << 63) - 1


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _bytes(value, name, minimum, maximum):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    if not minimum <= len(value) <= maximum:
        raise ValueError(f"{name} length outside registry bounds")
    return bytes(value)


def _sequence(value):
    if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
        raise ValueError("sequence must be a bounded nonnegative integer")
    return value


def _fields(obj, fields):
    if type(obj) is not dict or set(obj) != set(fields):
        raise ValueError("noncanonical object fields")


def _hex(value, name, minimum, maximum):
    if type(value) is not str or not minimum * 2 <= len(value) <= maximum * 2:
        raise ValueError(f"invalid {name} hex length")
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"invalid {name} hex") from error
    if result.hex() != value:
        raise ValueError(f"noncanonical {name} hex")
    return _bytes(result, name, minimum, maximum)


def _public(raw):
    raw = _bytes(raw, "signing key", 33, 33)
    key = ECPubKey()
    try:
        key.set(raw)
        if not key.is_valid or not key.is_compressed or key.get_bytes() != raw:
            raise ValueError("invalid compressed secp256k1 public key")
    except (AssertionError, IndexError, TypeError, OverflowError) as error:
        raise ValueError("invalid compressed secp256k1 public key") from error
    return key


def private_key(seed):
    """Deterministic public fixture secret; NEVER use for real funds or miners."""
    if type(seed) is not int or not 0 <= seed < (1 << 256):
        raise ValueError("fixture seed must be a uint256 integer")
    scalar = 1 + int.from_bytes(hashlib.sha256(NETWORK_ID + b"/fixture-key/" +
                                              seed.to_bytes(32, "big")).digest(), "big") % (ORDER - 1)
    key = ECKey()
    key.set(scalar.to_bytes(32, "big"), compressed=True)
    return key


def public_key(key):
    if not isinstance(key, ECKey) or not key.is_valid or not key.is_compressed:
        raise ValueError("a valid compressed fixture ECKey is required")
    return key.get_pubkey().get_bytes()


def miner_id_for_key(key):
    """Identity derives from the first signing key and survives authorized rotation."""
    raw = _public(key).get_bytes()
    return hashlib.sha256(NETWORK_ID + b"\x00miner-id\x00" + raw).digest()


def _signature_digest(payload):
    payload = _bytes(payload, "signed payload", 1, MAX_REGISTRY_BYTES)
    return hashlib.sha256(NETWORK_ID + b"\x00signature\x00" + payload).digest()


def sign(key, payload):
    public_key(key)
    return key.sign_ecdsa(_signature_digest(payload), low_s=True, rfc6979=True)


def verify(public, payload, signature):
    try:
        signature = _bytes(signature, "signature", 8, 72)
        return _public(public).verify_ecdsa(signature, _signature_digest(payload), low_s=True)
    except (ValueError, TypeError, IndexError, AssertionError, OverflowError):
        return False


@dataclass(frozen=True)
class RegistryEntry:
    miner_id: bytes
    tag: bytes
    signing_key: bytes
    payout_script: bytes

    def __post_init__(self):
        for name, minimum, maximum in (("miner_id", 32, 32), ("tag", 1, MAX_TAG_BYTES),
                                       ("signing_key", 33, 33), ("payout_script", 1, MAX_SCRIPT_BYTES)):
            object.__setattr__(self, name, _bytes(getattr(self, name), name, minimum, maximum))
        _public(self.signing_key)

    def to_object(self):
        return {name: getattr(self, name).hex()
                for name in ("miner_id", "tag", "signing_key", "payout_script")}

    @classmethod
    def from_object(cls, obj):
        _fields(obj, ("miner_id", "tag", "signing_key", "payout_script"))
        return cls(_hex(obj["miner_id"], "miner_id", 32, 32),
                   _hex(obj["tag"], "tag", 1, MAX_TAG_BYTES),
                   _hex(obj["signing_key"], "signing_key", 33, 33),
                   _hex(obj["payout_script"], "payout_script", 1, MAX_SCRIPT_BYTES))


@dataclass(frozen=True)
class RegistrySnapshot:
    sequence: int
    previous_root: bytes
    entries: tuple
    network_id: bytes = NETWORK_ID
    pool_id: bytes = b"pool-A"

    def __post_init__(self):
        _sequence(self.sequence)
        for name, minimum, maximum in (("previous_root", 32, 32), ("network_id", 1, 64),
                                       ("pool_id", 1, 64)):
            object.__setattr__(self, name, _bytes(getattr(self, name), name, minimum, maximum))
        # Check the count before materializing arbitrarily long iterables.
        entries = []
        for entry in self.entries:
            if len(entries) >= MAX_ENTRIES:
                raise ValueError("too many registry entries")
            if type(entry) is not RegistryEntry:
                raise TypeError("registry entries must be immutable RegistryEntry values")
            entries.append(entry)
        for field in ("miner_id", "tag", "signing_key"):
            if len({getattr(entry, field) for entry in entries}) != len(entries):
                raise ValueError(f"duplicate registry {field}")
        object.__setattr__(self, "entries", tuple(sorted(entries, key=lambda item: item.miner_id)))
        if len(_canonical(self.to_object())) > MAX_REGISTRY_BYTES:
            raise ValueError("registry serialization exceeds size limit")

    @property
    def root(self):
        return hashlib.sha256(NETWORK_ID + b"\x00registry-snapshot\x00" +
                              _canonical(self.to_object())).digest()

    def entry(self, miner_id):
        miner_id = _bytes(miner_id, "miner ID", 32, 32)
        for entry in self.entries:
            if entry.miner_id == miner_id:
                return entry
        raise ValueError("unknown registry miner")

    def to_object(self):
        return {"sequence": self.sequence, "previous_root": self.previous_root.hex(),
                "network_id": self.network_id.hex(), "pool_id": self.pool_id.hex(),
                "entries": [entry.to_object() for entry in self.entries]}

    @classmethod
    def from_object(cls, obj):
        _fields(obj, ("sequence", "previous_root", "network_id", "pool_id", "entries"))
        if type(obj["entries"]) is not list or len(obj["entries"]) > MAX_ENTRIES:
            raise ValueError("invalid registry entry list")
        result = cls(obj["sequence"], _hex(obj["previous_root"], "previous_root", 32, 32),
                     tuple(RegistryEntry.from_object(entry) for entry in obj["entries"]),
                     _hex(obj["network_id"], "network_id", 1, 64),
                     _hex(obj["pool_id"], "pool_id", 1, 64))
        if result.to_object() != obj:
            raise ValueError("registry wire entries must use canonical miner order")
        return result


def empty_registry(network_id=NETWORK_ID, pool_id=b"pool-A"):
    return RegistrySnapshot(0, bytes(32), (), network_id, pool_id)


@dataclass(frozen=True)
class RegistryChange:
    operation: str
    sequence: int
    previous_root: bytes
    entry: RegistryEntry
    old_signature: bytes = b""
    new_signature: bytes = b""
    network_id: bytes = NETWORK_ID
    pool_id: bytes = b"pool-A"

    def __post_init__(self):
        if type(self.operation) is not str or self.operation not in ("register", "update"):
            raise ValueError("unknown registry operation")
        _sequence(self.sequence)
        if type(self.entry) is not RegistryEntry:
            raise TypeError("change must contain an immutable RegistryEntry")
        for name, minimum, maximum in (("previous_root", 32, 32), ("network_id", 1, 64),
                                       ("pool_id", 1, 64), ("old_signature", 0, 72),
                                       ("new_signature", 0, 72)):
            object.__setattr__(self, name, _bytes(getattr(self, name), name, minimum, maximum))

    @property
    def payload(self):
        return _canonical({"type": "registry-change", "operation": self.operation,
                           "sequence": self.sequence, "previous_root": self.previous_root.hex(),
                           "network_id": self.network_id.hex(), "pool_id": self.pool_id.hex(),
                           "entry": self.entry.to_object()})

    def to_object(self):
        result = json.loads(self.payload)
        result["old_signature"] = self.old_signature.hex()
        result["new_signature"] = self.new_signature.hex()
        return result

    @classmethod
    def from_object(cls, obj):
        _fields(obj, ("type", "operation", "sequence", "previous_root", "network_id", "pool_id",
                      "entry", "old_signature", "new_signature"))
        if obj["type"] != "registry-change":
            raise ValueError("wrong registry change type")
        return cls(obj["operation"], obj["sequence"],
                   _hex(obj["previous_root"], "previous_root", 32, 32),
                   RegistryEntry.from_object(obj["entry"]),
                   _hex(obj["old_signature"], "old_signature", 0, 72),
                   _hex(obj["new_signature"], "new_signature", 0, 72),
                   _hex(obj["network_id"], "network_id", 1, 64),
                   _hex(obj["pool_id"], "pool_id", 1, 64))


def register(snapshot, key, tag, payout_script):
    public = public_key(key)
    entry = RegistryEntry(miner_id_for_key(public), tag, public, payout_script)
    unsigned = RegistryChange("register", snapshot.sequence + 1, snapshot.root, entry,
                              network_id=snapshot.network_id, pool_id=snapshot.pool_id)
    return RegistryChange("register", unsigned.sequence, unsigned.previous_root, entry,
                          new_signature=sign(key, unsigned.payload),
                          network_id=snapshot.network_id, pool_id=snapshot.pool_id)


def update(snapshot, miner_id, old_key, new_key, payout_script):
    previous = snapshot.entry(miner_id)
    entry = RegistryEntry(previous.miner_id, previous.tag, public_key(new_key), payout_script)
    unsigned = RegistryChange("update", snapshot.sequence + 1, snapshot.root, entry,
                              network_id=snapshot.network_id, pool_id=snapshot.pool_id)
    return RegistryChange("update", unsigned.sequence, unsigned.previous_root, entry,
                          sign(old_key, unsigned.payload), sign(new_key, unsigned.payload),
                          snapshot.network_id, snapshot.pool_id)


def apply_change(snapshot, change):
    if type(snapshot) is not RegistrySnapshot or type(change) is not RegistryChange:
        raise TypeError("expected immutable registry snapshot and change")
    if (change.network_id != snapshot.network_id or change.pool_id != snapshot.pool_id or
            change.previous_root != snapshot.root or change.sequence != snapshot.sequence + 1):
        raise ValueError("registry change context or predecessor mismatch")
    if not verify(change.entry.signing_key, change.payload, change.new_signature):
        raise ValueError("new signing key has not authorized the change")
    if change.operation == "register":
        if change.old_signature or change.entry.miner_id != miner_id_for_key(change.entry.signing_key):
            raise ValueError("registration identity must derive from its signing key")
        entries = (*snapshot.entries, change.entry)
    else:
        previous = snapshot.entry(change.entry.miner_id)
        if change.entry.tag != previous.tag:
            raise ValueError("registered miner tag cannot change")
        if not verify(previous.signing_key, change.payload, change.old_signature):
            raise ValueError("previous signing key has not authorized the update")
        entries = tuple(change.entry if entry.miner_id == previous.miner_id else entry
                        for entry in snapshot.entries)
    return RegistrySnapshot(change.sequence, snapshot.root, entries, snapshot.network_id, snapshot.pool_id)
