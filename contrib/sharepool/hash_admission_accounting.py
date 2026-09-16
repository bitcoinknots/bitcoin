#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded v8 wire upper bounds with transactional scalar/hash-only deltas.

This is a local resource estimate, not evidence, native validity or a durable
reservation. The owner rebuilds it on a new tip or unrelated journal revision.
Fresh canonical provenance is still required for each proof. Preview is pure;
commit follows the durable ACK. A stale/foreign delta cannot mutate state.

All CompactSize lengths/indexes reserve nine bytes, so inserting a record cannot
silently enlarge prior indexes. This may underutilize a tight budget: the gate
can fall back to an exact bounded quote and rebuild after its durable commit.
Metadata limits cover charged retained Python objects, not RSS or temporary
canonical captures supplied by the caller. No snapshot, template, transaction,
script, envelope, signature or native verdict is retained by this accountant.
"""
from dataclasses import dataclass
import hashlib

from hash_admission_budget import AdmissionResources, MAX_COUNTER
from hash_gate_cache import _retained_size
from hash_snapshot import (CompactTemplateRecord, Snapshot, SnapshotEncoding,
    Share, VARIABLE_TIDES_VERSION, MAX_DEPENDENCY_BYTES, MAX_SNAPSHOT_BYTES,
    MAX_TEMPLATE_BYTES, compact_size)


ENTRY_OVERHEAD = 256
CATEGORIES = ("transactions", "templates", "jobs", "proofs", "recipients", "origins", "dependencies")


class MetadataCapacity(ValueError):
    """Local accountant capacity; exact fallback may still admit the proof."""
    local_policy = True
    consensus_invalid = False

    def __init__(self):
        super().__init__("local-admission-accounting-capacity")


def _integer(name, value, minimum=0, maximum=MAX_COUNTER):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid compact admission accountant " + name)


def _capture(value):
    if type(value) is Snapshot:
        value = value.capture()
    if type(value) is not SnapshotEncoding:
        raise ValueError("canonical captured snapshot required")
    return value


@dataclass(frozen=True)
class AccountingDelta:
    resources: AdmissionResources
    duplicate: bool
    offered_origin_height: int
    min_pending_origin_height: object
    proof_count: int
    _owner: object
    _generation: int
    _additions: tuple
    _totals: tuple
    _metadata_bytes: int
    _metadata_entries: int


class _Preview:
    def __init__(self, owner):
        self.owner = owner
        self.added = {name: {} for name in CATEGORIES}
        self.totals = dict(owner._totals)
        self.bytes, self.entries = owner._metadata_bytes, owner._metadata_entries

    def known(self, category, key):
        return self.added[category].get(key, self.owner._maps[category].get(key))

    def add(self, category, key, value):
        previous = self.known(category, key)
        if previous is not None:
            if previous != value:
                raise ValueError("conflicting compact admission " + category + " identity")
            return False
        charge = ENTRY_OVERHEAD + _retained_size(key, value)
        if self.entries + 1 > self.owner.max_entries or self.bytes + charge > self.owner.max_metadata_bytes:
            raise MetadataCapacity()
        self.added[category][key] = value
        self.entries += 1
        self.bytes += charge
        return True

    def record(self, record, *, root):
        if type(record) is not CompactTemplateRecord:
            raise ValueError("immutable compact template record required")
        if not 1 <= record.expanded_bytes <= MAX_TEMPLATE_BYTES:
            raise ValueError("compact template byte bound")
        digest = hashlib.sha256(record.header_bytes + compact_size(len(record.transactions)))
        for tx in record.transactions:
            digest.update(tx.raw)  # Includes complete witness bytes.
        body = digest.digest()
        if self.add("origins", body, record.expanded_bytes):
            self.totals["origins"] += 1
        self.totals["largest"] = max(self.totals["largest"], record.expanded_bytes)
        if not root:
            return
        value = body, len(record.transactions), record.expanded_bytes
        if not self.add("templates", record.template_id, value):
            return
        self.totals["wire"] += 32 + 164 + 9 + 9 * len(record.transactions)
        self.totals["expanded"] += record.expanded_bytes
        self.totals["references"] += len(record.transactions)
        self.totals["root_templates"] += 1
        for tx in record.transactions:
            identity = hashlib.sha256(tx.raw).digest()
            if self.add("transactions", identity, len(tx.raw)):
                self.totals["wire"] += 9 + len(tx.raw)

    def dependencies(self, values, *, excluded=None):
        if type(values) is not tuple or len(values) > self.owner.max_entries:
            raise MetadataCapacity()
        supplied_bytes = 0
        for value in values:
            value = _capture(value)
            supplied_bytes += len(value.raw)
            if supplied_bytes > MAX_DEPENDENCY_BYTES:
                raise MetadataCapacity()
            if value.hash == excluded:
                continue
            previous = self.known("dependencies", value.hash)
            if previous is not None:
                if previous[0] != len(value.raw):
                    raise ValueError("conflicting dependency snapshot length")
                continue
            snapshot = value.snapshot
            if snapshot.envelope.version != VARIABLE_TIDES_VERSION:
                raise ValueError("compact admission requires v8 dependencies")
            facts = len(value.raw), len(snapshot.shares)
            self.add("dependencies", value.hash, facts)
            self.totals["dependency_bytes"] += facts[0]
            self.totals["dependency_shares"] += facts[1]
            for record in snapshot.templates:
                self.record(record, root=False)

    def proof(self, proof, record):
        if type(proof) is not Share or proof.envelope.version != VARIABLE_TIDES_VERSION:
            raise ValueError("v8 canonical proof required")
        encoded = proof.serialize()
        if not 1 <= len(encoded) <= 1024:
            raise ValueError("compact admission proof byte bound")
        facts = proof.header_facts
        if (type(record) is not CompactTemplateRecord or facts.template_id != record.template_id or
                facts.immutable_header != record.header_bytes or len(facts.search_fields) != 32 or
                proof.envelope.height != facts.height or proof.envelope.native_parent != facts.native_parent):
            raise ValueError("proof differs from its compact origin")
        identity = hashlib.sha256(encoded).digest(), proof.envelope.height
        if not self.add("proofs", proof.proof_id, identity):
            return False
        self.record(record, root=True)
        envelope = proof.envelope.serialize()
        descriptor = hashlib.sha256(envelope + proof.owner_signature).digest(), 9 + len(envelope) + 64
        if self.add("jobs", record.template_id, descriptor):
            self.totals["wire"] += descriptor[1]
        self.totals["wire"] += 9 + len(facts.search_fields)
        self.totals["proofs"] += 1
        oldest = self.totals["oldest"]
        self.totals["oldest"] = proof.envelope.height if oldest is None else min(oldest, proof.envelope.height)
        if proof.envelope.pool == self.owner._pool:
            script = proof.envelope.payout_script
            output_upper = 8 + 9 + len(script)
            if self.add("recipients", hashlib.sha256(script).digest(), output_upper):
                self.totals["recipient_count"] += 1
                self.totals["recipient_bytes"] += output_upper
        return True

    def resources(self):
        t = self.totals
        wire = t["wire"] + t["recipient_bytes"]
        return AdmissionResources(snapshot_bytes=wire,
            dependency_bytes=wire + t["dependency_bytes"], proofs=t["proofs"],
            dependency_shares=t["proofs"] + t["dependency_shares"], origins=t["origins"] + 1,
            expanded_template_bytes=t["expanded"], template_references=t["references"],
            largest_template_bytes=t["largest"], dependency_depth=t["depth"] + 1,
            certificate_bytes=t["certificate_bytes"] + 9 + 100 * t["root_templates"],
            recipient_count=t["recipient_count"], recipient_bytes=t["recipient_bytes"])

    def delta(self, *, duplicate, offered_height):
        return AccountingDelta(self.resources(), duplicate, offered_height, self.totals["oldest"],
            self.totals["proofs"], self.owner._token, self.owner._generation,
            tuple((category, key, value) for category in CATEGORIES for key, value in self.added[category].items()),
            tuple(self.totals.items()), self.bytes, self.entries)


class CompactAdmissionAccountant:
    """Owned by one gate; retain only bounded hash identities and scalar facts.

    ``depth`` is the deepest supplied root dependency edge count, excluding the
    one future mining edge reserved here. ``certificate_bytes`` is the initial
    known parent certificate reservation; new root origins add 100 bytes each.
    Historical payout reservation comes from the context-bound native RPC.
    Only the constructor excludes its proposed root from dependency totals;
    that old root can become a real origin dependency in a later preview.
    """
    def __init__(self, snapshot, *, historical_recipient_count, historical_recipient_bytes,
                 dependencies=(), depth=0, certificate_bytes=0,
                 max_metadata_bytes=16 * 1024 * 1024, max_entries=65536):
        _integer("metadata bytes", max_metadata_bytes, 1024, 256 * 1024 * 1024)
        _integer("metadata entries", max_entries, 1, 1_000_000)
        _integer("depth", depth)
        _integer("certificate bytes", certificate_bytes)
        _integer("historical recipients", historical_recipient_count, 1, MAX_SNAPSHOT_BYTES // 31)
        _integer("historical recipient bytes", historical_recipient_bytes, 1, MAX_SNAPSHOT_BYTES)
        if not 31 * historical_recipient_count <= historical_recipient_bytes <= 43 * historical_recipient_count:
            raise ValueError("invalid native historical recipient reservation")
        captured = _capture(snapshot)
        snapshot = captured.snapshot
        if snapshot.envelope.version != VARIABLE_TIDES_VERSION:
            raise ValueError("compact admission accounting requires v8")
        self.max_metadata_bytes, self.max_entries = max_metadata_bytes, max_entries
        self._pool = snapshot.envelope.pool
        self._token, self._generation = object(), 0
        self._maps = {name: {} for name in CATEGORIES}
        self._metadata_bytes = self._metadata_entries = 0
        self._totals = dict(wire=len(snapshot.envelope.serialize()) + 64 + 32 + 5 * 9 + 32,
            recipient_count=historical_recipient_count, recipient_bytes=historical_recipient_bytes,
            dependency_bytes=0, dependency_shares=0, proofs=0, origins=0,
            expanded=0, references=0, root_templates=0, largest=0, depth=depth,
            certificate_bytes=certificate_bytes, oldest=None)
        pending = _Preview(self)
        pending.dependencies(dependencies, excluded=captured.hash)
        records = {record.template_id: record for record in snapshot.templates}
        for record in snapshot.templates:
            pending.record(record, root=True)
        for proof in snapshot.shares:
            pending.proof(proof, records[proof.header_facts.template_id])
        self.commit(pending.delta(duplicate=False, offered_height=snapshot.envelope.height))

    @property
    def resources(self):
        return _Preview(self).resources()

    @property
    def min_pending_origin_height(self):
        return self._totals["oldest"]

    @property
    def proof_count(self):
        return self._totals["proofs"]

    @property
    def pending_proof_ids(self):
        return frozenset(self._maps["proofs"])

    def contains_proof(self, identity):
        _integer("proof identity", identity, maximum=(1 << 256) - 1)
        return identity in self._maps["proofs"]

    def preview_delta(self, proof, record, *, dependencies=(), depth=0):
        _integer("depth", depth)
        pending = _Preview(self)
        fresh = pending.proof(proof, record)
        if fresh:
            pending.dependencies(dependencies)
            pending.totals["depth"] = max(pending.totals["depth"], depth)
        return pending.delta(duplicate=not fresh, offered_height=proof.envelope.height)

    def commit(self, delta):
        """Apply one preview after its durable ACK; never call on a refusal.

        Foreign/stale deltas fail before mutation. If an exceptional allocation
        failure occurs during commit, discard the accountant and rebuild from
        the journal; the already durable receipt remains acknowledged.
        """
        if (type(delta) is not AccountingDelta or delta._owner is not self._token or
                delta._generation != self._generation):
            raise ValueError("foreign or stale compact admission delta")
        if delta.duplicate:
            if delta._additions or dict(delta._totals) != self._totals:
                raise ValueError("duplicate compact admission delta changes accounting")
            return
        for category, key, value in delta._additions:
            if key in self._maps[category]:
                raise ValueError("compact admission delta no longer extends its base")
        for category, key, value in delta._additions:
            self._maps[category][key] = value
        self._totals = dict(delta._totals)
        self._metadata_bytes, self._metadata_entries = delta._metadata_bytes, delta._metadata_entries
        self._generation += 1

    def stats(self):
        return {"metadata_bytes": self._metadata_bytes, "metadata_entries": self._metadata_entries,
                "generation": self._generation, **{name: len(values) for name, values in self._maps.items()}}
