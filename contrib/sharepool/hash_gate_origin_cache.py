#!/usr/bin/env python3
"""Bounded immutable facts from complete origin bytes, never native validity.

Every lookup hashes the supplied full body, including witness. Callers must
still obtain/authenticate current evidence, compare the exact origin binding,
and ask the native node to validate each received proof.
"""
from collections import OrderedDict
import hashlib
from typing import NamedTuple

from hash_gate_cache import ENTRY_OVERHEAD, _retained_size
from hash_snapshot import MAX_TEMPLATE_BYTES, job_hash, rules_hash
from native_mining_gate import immutable_header, parse_block


class OriginFacts(NamedTuple):
    header: bytes
    job_commitment: int


class OriginFactsCache:
    """Retain no body, snapshot, signature, mutable block or approval verdict.

    Byte accounting estimates retained Python objects, not process RSS or
    transient parsing memory. Set max_entries=0 to compare without retention.
    """
    def __init__(self, max_bytes=1024 * 1024, max_entries=1024):
        if any(type(value) is not int or value < 0 for value in (max_bytes, max_entries)):
            raise ValueError("invalid origin facts cache budget")
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self._entries = OrderedDict()
        self._bytes = self._hits = self._misses = self._oversized = 0

    def describe(self, raw, version):
        if type(version) is not int:
            raise ValueError("invalid origin facts profile")
        rules_hash(version)
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_TEMPLATE_BYTES:
            raise ValueError("origin facts input exceeds byte bound")
        # The entire immutable body is hashed afresh. TemplateId alone omits
        # witness variations; a header-only key could authenticate another job.
        key = version, len(raw), hashlib.sha256(raw).digest()
        saved = self._entries.get(key)
        if saved is not None:
            self._entries.move_to_end(key)
            self._hits += 1
            return saved[0]
        self._misses += 1
        block = parse_block(raw)
        facts = OriginFacts(immutable_header(block), job_hash(block))
        charge = ENTRY_OVERHEAD + _retained_size(key, facts)
        if not self.max_entries or charge > self.max_bytes:
            self._oversized += 1
            return facts
        while self._entries and (len(self._entries) >= self.max_entries or self._bytes + charge > self.max_bytes):
            _, (_, removed) = self._entries.popitem(last=False)
            self._bytes -= removed
        self._entries[key] = facts, charge
        self._bytes += charge
        return facts

    def clear(self):
        self._entries.clear()
        self._bytes = self._hits = self._misses = self._oversized = 0

    def stats(self):
        return {"entries": len(self._entries), "bytes": self._bytes, "hits": self._hits,
                "misses": self._misses, "oversized": self._oversized}
