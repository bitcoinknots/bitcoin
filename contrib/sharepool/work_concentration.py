#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact 10% arithmetic over supplied, already-credited records for one pool/window.

The caller supplies stable tag group IDs and credited work. This module does
not verify shares, tag ownership, target assignment, ledger completeness, or
pool/window membership. It selects no window and parses no network messages.
"""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CreditedRecord:
    share_id: bytes
    group_id: bytes
    credited_work: int


@dataclass(frozen=True)
class GroupWork:
    group_id: bytes
    credited_work: int


@dataclass(frozen=True)
class ConcentrationResult:
    record_count: int
    total_work: int
    groups: tuple[GroupWork, ...]  # Canonical lexicographic group-ID order.

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def offenders(self) -> tuple[GroupWork, ...]:
        return tuple(group for group in self.groups
                     if 10 * group.credited_work > self.total_work)

    @property
    def passes(self) -> bool:
        return self.total_work > 0 and not self.offenders


def expected_work(target: int) -> int:
    """Weight from a preassigned target, NOT the achieved hash.

    This conversion does not verify that the target was assigned before mining
    or that any share meets it. Callers must establish both independently.
    """
    if type(target) is not int or not 1 <= target < (1 << 256):
        raise ValueError("target must be an integer from 1 through 2**256 - 1")
    return (1 << 256) // (target + 1)


def evaluate(records: Iterable[CreditedRecord]) -> ConcentrationResult:
    """Evaluate every supplied group; empty input returns passes=False.

    Reject duplicate share IDs instead of silently counting or discarding them.
    Multiple jobs with the same stable group ID accumulate in the same group.
    """
    seen = set()
    totals = {}
    for record in records:
        for identity in (record.share_id, record.group_id):
            if not isinstance(identity, bytes) or not identity:
                raise ValueError("share and group IDs must be nonempty bytes")
        if type(record.credited_work) is not int or record.credited_work <= 0:
            raise ValueError("credited work must be a positive integer, excluding bool")
        if record.share_id in seen:
            raise ValueError("duplicate share ID")
        seen.add(record.share_id)
        totals[record.group_id] = totals.get(record.group_id, 0) + record.credited_work
    groups = tuple(GroupWork(identity, work) for identity, work in sorted(totals.items()))
    return ConcentrationResult(len(seen), sum(totals.values()), groups)
