#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded canonical decoding, independent of evidence or native validity.

Callers must obtain and authenticate the actual evidence bytes on every use.
This cache cannot establish availability, native approval, ancestry or payment.
It is owned by the same sole thread/process as the mining gate.
"""
from collections import OrderedDict
from dataclasses import replace
import sys

from hash_snapshot import Snapshot, MAX_SNAPSHOT_BYTES, rules_hash
from test_framework.messages import CTxOut
from test_framework.script import CScript


# Includes an OrderedDict node, entry tuple/counters and spare table capacity.
# Object graphs below are charged separately. This bounds estimated retained
# entries, not process RSS, transient decoding, or caller-owned return values.
ENTRY_OVERHEAD = 512


def _retained_size(*roots):
    """Count decoded Python fields and containers once per object identity.

    Roots only contain objects produced by the canonical snapshot decoder.
    Transaction payloads shared by several template records count once within
    an entry; sharing between entries is deliberately charged in each entry.
    """
    seen, pending, total = set(), list(roots), 0
    while pending:
        value = pending.pop()
        identity = id(value)
        if identity in seen:
            continue
        seen.add(identity)
        total += sys.getsizeof(value)
        if isinstance(value, (bytes, str, int, float, type(None))):
            continue
        if isinstance(value, (tuple, list)):
            pending.extend(value)
            continue
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        fields = getattr(value, "__dict__", None)
        if fields is not None:
            pending.append(fields)
        for cls in type(value).__mro__:
            slots = cls.__dict__.get("__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            pending.extend(getattr(value, name) for name in slots
                           if name not in ("__dict__", "__weakref__") and hasattr(value, name))
    return total


def _copy_payouts(snapshot):
    # CTxOut is mutable even though Snapshot and its other decoded fields are
    # immutable. Never expose the cached outputs through a returned snapshot.
    return replace(snapshot, payouts=tuple(CTxOut(value.nValue, CScript(bytes(value.scriptPubKey)))
                                          for value in snapshot.payouts))


class SnapshotDecodeCache:
    def __init__(self, max_bytes=8 * 1024 * 1024, max_shares=8192, max_entries=32):
        if any(type(value) is not int or value < 0 for value in (max_bytes, max_shares, max_entries)):
            raise ValueError("invalid snapshot decode cache budget")
        self.max_bytes, self.max_shares, self.max_entries = max_bytes, max_shares, max_entries
        self._entries = OrderedDict()
        self._bytes = self._shares = self._hits = self._misses = self._oversized = 0

    def decode(self, raw, version):
        """Return canonical content with isolated payouts; never a verdict.

        Exact immutable bytes are part of the key. Even a caller that supplies
        another profile's canonical bytes cannot reuse a previous decode.
        Available oversized inputs are decoded and returned without retention.
        """
        if type(version) is not int:
            raise ValueError("invalid snapshot decode profile")
        rules_hash(version)
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot decode input exceeds byte bound")
        key = version, raw
        entry = self._entries.get(key)
        if entry is not None:
            self._entries.move_to_end(key)
            self._hits += 1
            return _copy_payouts(entry[0])
        self._misses += 1
        snapshot = Snapshot.deserialize(raw)
        if snapshot.envelope.version != version:
            raise ValueError("snapshot profile differs from gate policy")
        shares = len(snapshot.shares)
        charge = ENTRY_OVERHEAD + _retained_size(key, snapshot)
        if not self.max_entries or charge > self.max_bytes or shares > self.max_shares:
            self._oversized += 1
            return snapshot
        while self._entries and (len(self._entries) >= self.max_entries or
                self._bytes + charge > self.max_bytes or self._shares + shares > self.max_shares):
            _, (_, removed_bytes, removed_shares) = self._entries.popitem(last=False)
            self._bytes -= removed_bytes
            self._shares -= removed_shares
        self._entries[key] = snapshot, charge, shares
        self._bytes += charge
        self._shares += shares
        return _copy_payouts(snapshot)

    def clear(self):
        self._entries.clear()
        self._bytes = self._shares = self._hits = self._misses = self._oversized = 0

    def stats(self):
        return {"entries": len(self._entries), "bytes": self._bytes, "shares": self._shares,
                "hits": self._hits, "misses": self._misses, "oversized": self._oversized}
