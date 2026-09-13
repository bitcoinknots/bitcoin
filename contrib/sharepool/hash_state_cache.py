#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded memo of successful compact-state calculations, never native validity.

The materializer must freshly read and authenticate every requested ancestor,
capture exact bytes, check bindings, charge resources and notify observers before
looking up this cache. Entries cannot establish availability or native approval.
Owned by the same sole thread/process as the gate; nothing is persisted.
"""
from collections import OrderedDict
from dataclasses import fields
import sys

from hash_snapshot import (COMPACT_TIDES_VERSION, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES,
    CompactTemplateRecord, EnvelopeV2, OriginCertificate, Share, Snapshot,
    StateEntry, _CapturedOutput, _HeaderFacts, _TransactionBytes)


# Spare OrderedDict capacity, node, entry tuple and accounting integers. Shared
# object graphs are counted once per entry and conservatively again across
# entries. This bounds estimated retained Python objects, not RSS or temporary
# materialization allocations, nor references a caller keeps after eviction.
ENTRY_OVERHEAD = 512
_RECORDS = (EnvelopeV2, OriginCertificate, Share, Snapshot, StateEntry, _CapturedOutput)


class _Oversized(Exception):
    pass


def _key(key):
    if (type(key) is not tuple or len(key) != 3 or type(key[0]) is not int or
            not 1 <= key[0] <= 0x7fffffff or type(key[1]) is not int or
            key[1] != COMPACT_TIDES_VERSION or type(key[2]) is not tuple or
            not 1 <= len(key[2]) <= MAX_SHARE_AGE + 1 or
            any(type(raw) is not bytes or not 1 <= len(raw) <= MAX_SNAPSHOT_BYTES for raw in key[2])):
        raise ValueError("invalid compact state cache key")
    return key


def _immutable_charge(key, snapshot, limit):
    """Validate known immutable records and count their entire retained graph.

    Iterate tuple members without allocating a second full reference vector.
    Stop accounting once the retention budget is exhausted. Canonical proof
    decoding already fills its fixed header memo; we require that invariant so
    later proof access cannot grow a retained cache entry.
    """
    seen, total = set(), ENTRY_OVERHEAD

    def visit(value):
        nonlocal total
        if id(value) in seen:
            return
        seen.add(id(value))
        total += sys.getsizeof(value)
        if total > limit:
            raise _Oversized
        kind = type(value)
        if kind in (bytes, str, int, type(None)):
            return
        if kind in (tuple, _HeaderFacts):
            for child in value:
                visit(child)
            return
        if kind in _RECORDS:
            members = vars(value)
            expected = {field.name for field in fields(value)}
            if kind is Share:
                expected.add("_header_facts")
                memo = members.get("_header_facts")
                if (type(memo) is not tuple or len(memo) != 2 or memo[0] is not value.header_bytes or
                        type(memo[1]) is not _HeaderFacts):
                    raise ValueError("compact state cache requires complete immutable proof metadata")
            if set(members) != expected:
                raise ValueError("compact state cache record has unexpected fields")
            # This is an internal dictionary belonging to a frozen record,
            # never a mutable container accepted as a field value.
            total += sys.getsizeof(members)
            if total > limit:
                raise _Oversized
            for name, child in members.items():
                visit(name)
                visit(child)
            return
        if kind in (CompactTemplateRecord, _TransactionBytes):
            for name in kind.__slots__:
                if name != "__weakref__":
                    visit(getattr(value, name))
            return
        raise ValueError("compact state cache requires immutable canonical records")

    visit(key)
    visit(snapshot)
    return total


class CompactStateCache:
    def __init__(self, max_bytes=8 * 1024 * 1024, max_shares=8192, max_entries=4):
        if any(type(value) is not int or value < 0 for value in (max_bytes, max_shares, max_entries)):
            raise ValueError("invalid compact state cache budget")
        self.max_bytes, self.max_shares, self.max_entries = max_bytes, max_shares, max_entries
        self._entries = OrderedDict()
        self._bytes = self._shares = self._hits = self._misses = self._oversized = 0

    def get(self, key):
        entry = self._entries.get(_key(key))
        if entry is None:
            self._misses += 1
            return None
        self._entries.move_to_end(key)
        self._hits += 1
        return entry[0]

    def put(self, key, derived):
        """Retain a successful materializer result if it fits; return retention.

        Only the materializer calls this after its history and authorization
        checks. This container does not attest those checks on a caller's behalf.
        Derived state comes from detached captures, including immutable payouts.
        """
        _key(key)
        if (type(derived) is not Snapshot or derived.envelope.version != key[1] or
                derived.envelope.height < key[0] or derived.pending or derived.settled):
            raise ValueError("compact state cache result profile mismatch")
        shares = len(derived.shares) + len(derived.post_state)
        if not self.max_entries or shares > self.max_shares:
            self._oversized += 1
            return False
        try:
            charge = _immutable_charge(key, derived, self.max_bytes)
        except _Oversized:
            self._oversized += 1
            return False
        old = self._entries.pop(key, None)
        if old is not None:
            self._bytes -= old[1]
            self._shares -= old[2]
        while self._entries and (len(self._entries) >= self.max_entries or
                self._bytes + charge > self.max_bytes or self._shares + shares > self.max_shares):
            _, (_, removed_bytes, removed_shares) = self._entries.popitem(last=False)
            self._bytes -= removed_bytes
            self._shares -= removed_shares
        self._entries[key] = derived, charge, shares
        self._bytes += charge
        self._shares += shares
        return True

    def clear(self):
        self._entries.clear()
        self._bytes = self._shares = self._hits = self._misses = self._oversized = 0

    def stats(self):
        return {"entries": len(self._entries), "bytes": self._bytes, "shares": self._shares,
                "hits": self._hits, "misses": self._misses, "oversized": self._oversized}
