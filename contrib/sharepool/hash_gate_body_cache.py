#!/usr/bin/env python3
"""Bounded immutable template decoding, independent of native validity.

Every use starts with freshly authenticated evidence bytes. A full witness-body
digest keys only canonical body decoding, never proof or chain verdicts.
"""
from collections import OrderedDict
import hashlib
from hash_gate_cache import ENTRY_OVERHEAD, _retained_size
from hash_snapshot import (CompactTemplateRecord, MAX_TEMPLATE_BYTES, _transaction,
                           rules_hash)
from native_mining_gate import parse_block, template_id
from test_framework.messages import CBlockHeader


class OriginBodyCache:
    """Optional decoded bodies, charged by retained object size rather than RSS.

    The returned record contains immutable header and transaction bytes. No
    caller-owned block, transaction, payout, signature or approval is retained.
    Oversized entries are returned without retention; disabling the cache
    changes performance only.
    """
    def __init__(self, max_bytes=8 * 1024 * 1024, max_entries=32):
        if any(type(value) is not int or value < 0 for value in (max_bytes, max_entries)):
            raise ValueError("invalid origin body cache budget")
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self._entries = OrderedDict()
        self._bytes = self._hits = self._misses = self._oversized = 0

    def capture(self, raw, version):
        if type(version) is not int:
            raise ValueError("invalid origin body profile")
        rules_hash(version)
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_TEMPLATE_BYTES:
            raise ValueError("origin body input exceeds byte bound")
        key = version, len(raw), hashlib.sha256(raw).digest()
        saved = self._entries.get(key)
        if saved is not None:
            self._entries.move_to_end(key)
            self._hits += 1
            return saved[0]
        self._misses += 1
        block = parse_block(raw)
        # CompactTemplateRecord enforces normalized v2 header/search fields,
        # exact transaction count and Merkle root, and the expanded byte bound.
        # parse_block enforces canonical full serialization, including witness.
        record = CompactTemplateRecord(int(template_id(block), 16), CBlockHeader(block).serialize(),
            tuple(_transaction(tx.serialize_with_witness()) for tx in block.vtx))
        charge = ENTRY_OVERHEAD + _retained_size(key, record)
        if not self.max_entries or charge > self.max_bytes:
            self._oversized += 1
            return record
        while self._entries and (len(self._entries) >= self.max_entries or self._bytes + charge > self.max_bytes):
            _, (_, removed) = self._entries.popitem(last=False)
            self._bytes -= removed
        self._entries[key] = record, charge
        self._bytes += charge
        return record

    def clear(self):
        self._entries.clear()
        self._bytes = self._hits = self._misses = self._oversized = 0

    def stats(self):
        return {"entries": len(self._entries), "bytes": self._bytes, "hits": self._hits,
                "misses": self._misses, "oversized": self._oversized}
