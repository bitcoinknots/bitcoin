#!/usr/bin/env python3
"""Deterministic local settlement batching; native consensus stays authoritative."""
from io import BytesIO

from hash_snapshot import (MAX_SNAPSHOT_BYTES, MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_DEPTH,
                           MAX_ORIGIN_CHECKS, MAX_SHARE_AGE, CompactTemplateRecord,
                           LEDGER_VERSION, TIDES_VERSION, origin_certificate)
from test_framework.messages import CBlockHeader


class BatchLimit(ValueError):
    pass


def check_graph(snapshot, *, lookup, parent_snapshot, snapshot_budget=MAX_SNAPSHOT_BYTES,
                on_snapshot=None, mining_job=False, trusted_parent=None,
                root_origin=None, root_depth=0, activation_height=1):
    """Check the same unique snapshot/depth/origin resource dimensions locally.

    Current settlement depth is zero; every full origin adds one. Parent paid
    state is fetched but not recursively revalidated, matching the native walk.
    This preflight establishes resource fit, never scripts or consensus validity.
    on_snapshot receives each bounded canonical opening once, including parent
    paid-state openings. Callers must discard collected data if this walk fails.
    New jobs reserve their own future origin edge and native origin check;
    historical graph validation leaves that reservation disabled.
    v5/v6 use only certificates from the top actual native parent. A historical
    root_origin can supply its current settlement parent explicitly; even a
    certified origin still retains its own exact opening for authentication.
    """
    if type(activation_height) is not int or not 1 <= activation_height <= 0x7fffffff:
        raise ValueError("invalid settlement activation height")
    snapshots, origins, depths, visiting, parents = {}, {}, {}, set(), {}
    total = 0
    depth_limit = MAX_DEPENDENCY_DEPTH - int(mining_job)
    origin_limit = MAX_ORIGIN_CHECKS - int(mining_job)
    if depth_limit < 0 or origin_limit < 0:
        raise BatchLimit("mining job reservation exceeds resource budget")

    def encoded(value):
        try:
            return value.serialize()
        except ValueError as error:
            if "bound" in str(error) or "budget" in str(error):
                raise BatchLimit(str(error)) from None
            raise

    def account(value, raw=None, expected=None):
        nonlocal total
        if value is None:
            raise ValueError("missing snapshot dependency")
        identity = value.hash
        if expected is not None and identity != expected:
            raise ValueError("snapshot lookup returned another commitment")
        if identity not in snapshots:
            raw = encoded(value) if raw is None else raw
            total += len(raw)
            if total > MAX_DEPENDENCY_BYTES:
                raise BatchLimit("dependency bytes")
            snapshots[identity] = value
            if on_snapshot is not None:
                on_snapshot(identity, raw)
        return identity

    def load(identity):
        if identity not in snapshots:
            account(lookup(identity), expected=identity)
        return snapshots[identity]

    def load_parent(parent):
        if parent not in parents:
            parents[parent] = account(parent_snapshot(*parent))
        return snapshots[parents[parent]]

    certificates = {}
    if snapshot.envelope.version in (LEDGER_VERSION, TIDES_VERSION):
        if trusted_parent is None and root_origin is None and snapshot.envelope.height > activation_height:
            trusted_parent = load_parent((snapshot.envelope.native_parent, snapshot.envelope.height - 1))
        if trusted_parent is not None and trusted_parent.envelope.height >= activation_height:
            if trusted_parent.envelope.version != snapshot.envelope.version:
                raise ValueError("certificate parent profile mismatch")
            account(trusted_parent)
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

    raw = encoded(snapshot)
    if len(raw) > snapshot_budget:
        raise BatchLimit("snapshot bytes")
    identity = account(snapshot, raw)
    certified = False
    if root_origin is not None:
        opening, certified = origin_entry(root_origin)
        if opening != identity:
            raise ValueError("historical root opening mismatch")
    if root_depth > depth_limit:
        raise BatchLimit("dependency depth")
    if not certified:
        walk(identity, root_depth)
    return {"snapshot_bytes": len(raw), "dependency_bytes": total, "origins": len(origins) + int(mining_job)}
