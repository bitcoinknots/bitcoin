#!/usr/bin/env python3
"""Deterministic local settlement batching; native consensus stays authoritative."""
from hash_snapshot import (MAX_SNAPSHOT_BYTES, MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_DEPTH,
                           MAX_ORIGIN_CHECKS)
from native_mining_gate import parse_block
from test_framework.messages import hash256


class BatchLimit(ValueError):
    pass


def check_graph(snapshot, *, lookup, parent_snapshot, snapshot_budget=MAX_SNAPSHOT_BYTES):
    """Check the same unique snapshot/depth/origin resource dimensions locally.

    Current settlement depth is zero; every full origin adds one. Parent paid
    state is fetched but not recursively revalidated, matching the native walk.
    This preflight establishes resource fit, never scripts or consensus validity.
    """
    snapshots, origins, visited, visiting = {}, set(), set(), set()
    total = 0

    def encoded(value):
        try:
            return value.serialize()
        except ValueError as error:
            if "bound" in str(error) or "budget" in str(error):
                raise BatchLimit(str(error)) from None
            raise

    def account(value, raw=None):
        nonlocal total
        identity = value.hash
        if identity not in snapshots:
            raw = encoded(value) if raw is None else raw
            total += len(raw)
            if total > MAX_DEPENDENCY_BYTES:
                raise BatchLimit("dependency bytes")
            snapshots[identity] = value
        return value

    def walk(value, depth):
        if depth > MAX_DEPENDENCY_DEPTH:
            raise BatchLimit("dependency depth")
        identity = value.hash
        if identity in visiting:
            raise ValueError("snapshot dependency cycle")
        if (identity, depth) in visited:
            return
        visiting.add(identity)
        account(value)
        if value.envelope.height > 1:
            account(parent_snapshot(value.envelope.native_parent, value.envelope.height - 1))
        for record in value.templates:
            raw = record.data
            body_id = hash256(raw)
            origins.add(body_id)
            if len(origins) > MAX_ORIGIN_CHECKS:
                raise BatchLimit("origin count")
            origin = parse_block(raw)
            walk(lookup(origin.m_mm_rhs), depth + 1)
        visiting.remove(identity)
        visited.add((identity, depth))

    raw = encoded(snapshot)
    if len(raw) > snapshot_budget:
        raise BatchLimit("snapshot bytes")
    account(snapshot, raw)
    walk(snapshot, 0)
    return {"snapshot_bytes": len(raw), "dependency_bytes": total, "origins": len(origins)}
