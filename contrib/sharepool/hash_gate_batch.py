#!/usr/bin/env python3
"""Deterministic local settlement batching; native consensus stays authoritative."""
from collections import OrderedDict
from io import BytesIO

from hash_snapshot import (MAX_SNAPSHOT_BYTES, MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_DEPTH,
                           MAX_ORIGIN_CHECKS, MAX_SHARE_AGE, CompactTemplateRecord,
                           LEDGER_VERSION, TIDES_VERSION, COMPACT_TIDES_VERSION, MAX_DEPENDENCY_SHARES,
                           origin_certificate, materialize_compact_state)
from test_framework.messages import CBlockHeader


NATIVE_STATE_CACHE_ENTRIES = 4


class BatchLimit(ValueError):
    pass


def check_graph(snapshot, *, lookup, parent_snapshot, snapshot_budget=MAX_SNAPSHOT_BYTES,
                on_snapshot=None, mining_job=False, trusted_parent=None,
                root_origin=None, root_depth=0, activation_height=1, state_cache=None):
    """Check the same unique snapshot/depth/origin resource dimensions locally.

    Current settlement depth is zero; every full origin adds one. Parent paid
    state is fetched but not recursively revalidated, matching the native walk.
    This preflight establishes resource fit, never scripts or consensus validity.
    on_snapshot receives each bounded canonical opening once, including parent
    paid-state openings. Callers must discard collected data if this walk fails.
    New jobs reserve their own future origin edge and native origin check;
    historical graph validation leaves that reservation disabled.
    TIDES certificates come only from the top actual native parent; v7 derives
    these from its bounded authenticated suffix and counts those openings too.
    A historical
    root_origin can supply its current settlement parent explicitly; even a
    certified origin still retains its own exact opening for authentication.
    """
    if type(activation_height) is not int or not 1 <= activation_height <= 0x7fffffff:
        raise ValueError("invalid settlement activation height")
    snapshots, encodings, owned, origins, depths, visiting, parents = {}, {}, {}, {}, {}, set(), {}
    total, proof_count = 0, 0
    depth_limit = MAX_DEPENDENCY_DEPTH - int(mining_job)
    origin_limit = MAX_ORIGIN_CHECKS - int(mining_job)
    if depth_limit < 0 or origin_limit < 0:
        raise BatchLimit("mining job reservation exceeds resource budget")

    def capture(value):
        # Only detached immutable objects created by this operation can reuse
        # metadata by identity. Fresh caller objects are always serialized.
        previous = owned.get(id(value))
        if previous is not None and previous.snapshot is value:
            return previous
        try:
            return value.capture()
        except ValueError as error:
            if "bound" in str(error) or "budget" in str(error):
                raise BatchLimit(str(error)) from None
            raise

    def account(value, raw=None, expected=None):
        nonlocal total, proof_count
        if value is None:
            raise ValueError("missing snapshot dependency")
        encoded = capture(value)
        identity = encoded.hash
        if expected is not None and identity != expected:
            raise ValueError("snapshot lookup returned another commitment")
        if raw is not None and raw != encoded.raw:
            raise ValueError("snapshot callback bytes differ from canonical capture")
        if identity in encodings and encodings[identity].raw != encoded.raw:
            raise ValueError("snapshot commitment has conflicting canonical bytes")
        if identity not in snapshots:
            value = encoded.snapshot
            total += len(encoded.raw)
            if value.envelope.version == COMPACT_TIDES_VERSION:
                proof_count += len(value.shares)
                if proof_count > MAX_DEPENDENCY_SHARES:
                    raise BatchLimit("dependency share count")
            if total > MAX_DEPENDENCY_BYTES:
                raise BatchLimit("dependency bytes")
            snapshots[identity], encodings[identity] = value, encoded
            owned[id(value)] = encoded
            if on_snapshot is not None:
                on_snapshot(identity, encoded.raw)
        return identity

    # Freeze the supplied proposal before any external lookup callback runs.
    # Captured state is detached from mutable CTxOut caller objects; v7 omitted
    # arrays cannot enter this wire-only map.
    root_encoding = capture(snapshot)
    if len(root_encoding.raw) > snapshot_budget:
        raise BatchLimit("snapshot bytes")
    owned[id(root_encoding.snapshot)] = root_encoding
    root_identity = account(root_encoding.snapshot, root_encoding.raw)
    snapshot = snapshots[root_identity]

    def load(identity):
        if identity not in snapshots:
            account(lookup(identity), expected=identity)
        return snapshots[identity]

    def load_raw_parent(parent):
        if parent not in parents:
            value = parent_snapshot(*parent)
            if value is not None and value.envelope.height != parent[1]:
                raise ValueError("native parent snapshot has wrong height")
            parents[parent] = account(value)
        return snapshots[parents[parent]]

    # Alternative jobs may share a large native admission window. Caching
    # each derived tuple would multiply that state by the job count despite
    # small wire bytes. Keep at most four parent states: a provisional graph
    # may mention many branches before native ancestry validation rejects it.
    # Origin states are verified and released before descending the graph.
    native_states = OrderedDict()
    def hydrate(identity, *, native_parent=False):
        value = snapshots[identity]
        if identity in native_states:
            native_states.move_to_end(identity)
            return native_states[identity]
        if value.envelope.version == COMPACT_TIDES_VERSION:
            value = materialize_compact_state(value, activation_height=activation_height,
                parent_snapshot=lambda identity, height: load_raw_parent((identity, height)),
                on_snapshot=lambda opening, raw: account(opening, raw), capture=capture,
                state_cache=state_cache)
            if native_parent:
                native_states[identity] = value
                while len(native_states) > NATIVE_STATE_CACHE_ENTRIES:
                    native_states.popitem(last=False)
        return value

    def load_parent(parent):
        load_raw_parent(parent)
        return hydrate(parents[parent], native_parent=True)

    certificates = {}
    if snapshot.envelope.version in (LEDGER_VERSION, TIDES_VERSION, COMPACT_TIDES_VERSION):
        trusted_identity = None
        if trusted_parent is None and root_origin is None and snapshot.envelope.height > activation_height:
            parent = snapshot.envelope.native_parent, snapshot.envelope.height - 1
            load_raw_parent(parent)
            trusted_identity = parents[parent]
            trusted_parent = snapshots[trusted_identity]
        if trusted_parent is not None and trusted_parent.envelope.height >= activation_height:
            if trusted_parent.envelope.version != snapshot.envelope.version:
                raise ValueError("certificate parent profile mismatch")
            if trusted_identity is None:
                trusted_identity = account(trusted_parent)
                trusted_parent = snapshots[trusted_identity]
            if snapshot.envelope.version == COMPACT_TIDES_VERSION:
                trusted_parent = hydrate(trusted_identity, native_parent=True)
            oldest = max(activation_height, trusted_parent.envelope.height + 1 - MAX_SHARE_AGE)
            certificates = {cert.identity: cert for cert in trusted_parent.certificates if cert.origin_height >= oldest}

    def origin_entry(record):
        record = CompactTemplateRecord.from_record(record)
        # Exact immutable body identity without expanding shared transaction
        # payloads again at every incoming DAG edge.
        body_id = (record.header_bytes, tuple(tx.wtxid for tx in record.transactions))
        if body_id not in origins:
            if len(origins) >= origin_limit:
                raise BatchLimit("origin count")
            origin = CBlockHeader()
            origin.deserialize(BytesIO(record.header_bytes))
            certificate = origin_certificate(record) if certificates else None
            certified = certificate is not None and certificates.get(certificate.identity) == certificate
            origins[body_id] = origin.m_mm_rhs, certified
        return origins[body_id]

    def walk(identity, depth):
        if depth > depth_limit:
            raise BatchLimit("dependency depth")
        if identity in visiting:
            raise ValueError("snapshot dependency cycle")
        if identity in depths:
            if depth + depths[identity] > depth_limit:
                raise BatchLimit("dependency depth")
            return depths[identity]
        value = load(identity)
        if identity != root_identity or root_origin is not None:
            hydrate(identity)  # Validate and release alternate-job state now.
        visiting.add(identity)
        if value.envelope.height > activation_height:
            parent = (value.envelope.native_parent, value.envelope.height - 1)
            load_parent(parent)
        longest = 0
        for record in value.templates:
            opening, certified = origin_entry(record)
            if certified:
                if depth + 1 > depth_limit:
                    raise BatchLimit("dependency depth")
                load(opening)
                child_depth = 0
            else:
                child_depth = walk(opening, depth + 1)
            longest = max(longest, 1 + child_depth)
        visiting.remove(identity)
        depths[identity] = longest
        return longest

    try:
        raw, identity = root_encoding.raw, root_identity
        certified = False
        if root_origin is not None:
            opening, certified = origin_entry(root_origin)
            if opening != identity:
                raise ValueError("historical root opening mismatch")
        if root_depth > depth_limit:
            raise BatchLimit("dependency depth")
        if not certified:
            walk(identity, root_depth)
        return {"snapshot_bytes": len(raw), "dependency_bytes": total, "origins": len(origins) + int(mining_job), "dependency_shares": proof_count}
    finally:
        # The recursive closure otherwise retains its own bounded operation
        # maps until cyclic GC runs, including after a rejected prefix.
        walk = None
