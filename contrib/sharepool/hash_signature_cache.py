#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded successful BIP340 checks over exact immutable public inputs.

This memo proves only that a signature verifies for its exact key and message.
It cannot establish data availability, ancestry, accounting or native validity.
Entries are local to the gate owner and never persisted as evidence.
"""
from collections import OrderedDict
import sys

from native_enforcement import verify_schnorr


# Conservatively charge an ordered-map node, entry and spare table capacity.
# The key tuple and each fixed-length bytes object are charged separately.
ENTRY_OVERHEAD = 512


class SignatureVerifyCache:
    def __init__(self, max_bytes=1024 * 1024, max_entries=1024):
        if any(type(value) is not int or value < 0 for value in (max_bytes, max_entries)):
            raise ValueError("invalid signature verification cache budget")
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self._entries = OrderedDict()
        self._bytes = self._hits = self._misses = self._failures = self._oversized = 0

    def verify(self, public_key, signature, message):
        if any(type(value) is not bytes or len(value) != size for value, size in
               ((public_key, 32), (signature, 64), (message, 32))):
            raise ValueError("signature cache requires exact immutable BIP340 inputs")
        key = public_key, signature, message
        if key in self._entries:
            self._entries.move_to_end(key)
            self._hits += 1
            return True
        self._misses += 1
        if not verify_schnorr(*key):
            self._failures += 1
            return False
        charge = ENTRY_OVERHEAD + sys.getsizeof(key) + sum(sys.getsizeof(value) for value in key)
        if not self.max_entries or charge > self.max_bytes:
            self._oversized += 1
            return True
        while self._entries and (len(self._entries) >= self.max_entries or self._bytes + charge > self.max_bytes):
            _, removed = self._entries.popitem(last=False)
            self._bytes -= removed
        self._entries[key] = charge
        self._bytes += charge
        return True

    def clear(self):
        self._entries.clear()
        self._bytes = self._hits = self._misses = self._failures = self._oversized = 0

    def stats(self):
        return {"entries": len(self._entries), "bytes": self._bytes, "hits": self._hits,
                "misses": self._misses, "failures": self._failures, "oversized": self._oversized}
