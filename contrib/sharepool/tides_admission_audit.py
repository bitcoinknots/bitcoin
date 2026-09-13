#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent exact-rational oracle for admission-boundary policy analysis.

This is a bounded arithmetic/adversarial fixture, not proof, template or native
consensus validation. Work values represent already validated assigned work;
proof IDs used by the reproduction are deterministic synthetic hash ranks.

The cohort policy groups complete same-native-admission-height work per pool.
Its oldest cohort is clipped proportionally, then each recipient's complete
aggregate is rounded down once. This removes proof-rank influence for a fixed
admitted set. It does not authenticate global reception order, prevent omission
or withholding into later admission heights, or establish mining profitability.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, replace
from fractions import Fraction
import hashlib
import json


@dataclass(frozen=True)
class Admission:
    height: int
    proof_id: int
    pool: str
    recipient: str
    work: int


@dataclass(frozen=True)
class Allocation:
    requested: Fraction
    counted: Fraction
    weights: dict[str, Fraction]
    payouts: dict[str, int]
    residue: int
    boundary_height: int | None
    boundary_work: Fraction


def _checked(admissions, pool, window, reward):
    if type(admissions) is not tuple or not pool:
        raise ValueError("immutable complete admission set and pool required")
    if type(window) not in (int, Fraction) or window <= 0:
        raise ValueError("positive exact work window required")
    if type(reward) is not int or reward < 0:
        raise ValueError("nonnegative integral reward required")
    seen = set()
    for value in admissions:
        if (type(value) is not Admission or type(value.height) is not int or value.height <= 0 or
                type(value.proof_id) is not int or not 0 < value.proof_id < 1 << 256 or
                type(value.work) is not int or not 0 < value.work < 1 << 256 or
                not value.pool or not value.recipient or value.proof_id in seen):
            raise ValueError("invalid or duplicate admission")
        seen.add(value.proof_id)
    return tuple(value for value in admissions if value.pool == pool), Fraction(window)


def _result(window, remaining, weights, reward, boundary_height, boundary_work):
    counted = window - remaining
    if not counted:
        raise ValueError("empty history requires a separate bootstrap policy")
    weights = dict(sorted(weights.items()))
    payouts = {recipient: int(Fraction(reward) * work / counted) for recipient, work in weights.items()}
    payouts = {recipient: amount for recipient, amount in payouts.items() if amount}
    return Allocation(window, counted, weights, payouts, reward - sum(payouts.values()),
                      boundary_height, boundary_work)


def legacy_rank_allocate(admissions, *, pool, window, reward):
    """Reproduce the original v6 (admission height, numeric proof ID) boundary."""
    relevant, window = _checked(admissions, pool, window, reward)
    remaining, weights = window, defaultdict(Fraction)
    boundary_height, boundary_work = None, Fraction(0)
    for entry in sorted(relevant, key=lambda item: (item.height, item.proof_id), reverse=True):
        included = min(remaining, entry.work)
        weights[entry.recipient] += included
        boundary_height, boundary_work = entry.height, included
        remaining -= included
        if not remaining:
            break
    return _result(window, remaining, weights, reward, boundary_height, boundary_work)


def cohort_allocate(admissions, *, pool, window, reward):
    """Clip one complete oldest height proportionally with unbounded rationals.

    Callers must supply complete cohorts. Authenticating that completeness is a
    native history-reader obligation and cannot be inferred from this argument.
    """
    relevant, window = _checked(admissions, pool, window, reward)
    cohorts = defaultdict(list)
    for entry in relevant:
        cohorts[entry.height].append(entry)
    remaining, weights = window, defaultdict(Fraction)
    boundary_height, boundary_work = None, Fraction(0)
    for height in sorted(cohorts, reverse=True):
        cohort = cohorts[height]
        work = sum(value.work for value in cohort)
        included = min(remaining, work)
        scale = Fraction(included, work)
        for value in cohort:
            weights[value.recipient] += value.work * scale
        boundary_height, boundary_work = height, included
        remaining -= included
        if not remaining:
            break
    return _result(window, remaining, weights, reward, boundary_height, boundary_work)


def _encoded(value):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator}
    if isinstance(value, dict):
        return {key: _encoded(item) for key, item in value.items()}
    return value


def _summary(allocation):
    return {"weights": _encoded(allocation.weights), "payouts": allocation.payouts,
            "counted_work": _encoded(allocation.counted), "rounding_residue": allocation.residue}


def reproduce():
    """Run deterministic finite examples; no stochastic profitability claim."""
    def rank(label):
        return int.from_bytes(hashlib.blake2b(label.encode(), digest_size=32).digest(), "big")

    honest = tuple(Admission(1, rank(f"honest/{i}"), "A", "honest", 1) for i in range(100))
    produced = tuple(Admission(1, rank(f"operator/{i}"), "A", "operator", 1) for i in range(200))
    retained = tuple(sorted(produced, key=lambda entry: entry.proof_id, reverse=True)[:20])
    rank_options = dict(pool="A", window=16, reward=12_000)
    old_full = legacy_rank_allocate(honest + produced, **rank_options)
    old_retained = legacy_rank_allocate(honest + retained, **rank_options)
    grouped = cohort_allocate(honest + retained, **rank_options)
    # All top-window operator proofs are among its 20 retained proofs.
    assert old_full == old_retained
    assert grouped.payouts == {"honest": 10_000, "operator": 2_000}

    immediate = (Admission(1, 1, "A", "honest", 8), Admission(1, 2, "A", "operator", 8),
                 Admission(2, 3, "A", "honest", 8))
    delayed = (immediate[0], replace(immediate[1], height=3), immediate[2])
    timing_options = dict(pool="A", window=8, reward=100)
    early = cohort_allocate(immediate, **timing_options)
    late = cohort_allocate(delayed, **timing_options)
    assert early.payouts == {"honest": 100} and late.payouts == {"operator": 100}

    fractional = (Admission(1, 4, "A", "alice", 1), Admission(1, 5, "A", "bob", 1),
                  Admission(2, 6, "A", "alice", 1))
    combined = cohort_allocate(fractional, pool="A", window=2, reward=3)
    assert combined.payouts == {"alice": 2} and combined.residue == 1

    return {"schema": 1, "fixture": "independent-exact-admission-arithmetic", "result": "passed",
            "proof_rank_selection": {"honest_generated_work": 100, "operator_generated_work": 200,
                "operator_retained_work": 20, "window_work": 16,
                "legacy_full": _summary(old_full), "legacy_selected": _summary(old_retained),
                "proportional_selected": _summary(grouped)},
            "withholding_across_heights": {"immediate": _summary(early), "delayed": _summary(late)},
            "aggregate_before_floor": _summary(combined),
            "limits": ["Synthetic hash ranks and assigned work; no PoW or native validation.",
                "Proportional cohorts remove rank dependence only for the same complete admitted set.",
                "A producer can still omit a receipt or shift eligible work to a later native admission height.",
                "Examples do not estimate net mining profitability, long-run payout variance or global reception order."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(reproduce(), indent=2, sort_keys=True))
