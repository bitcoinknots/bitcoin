#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded design experiments; not a native codec, miner, or consensus change.

The trace generator couples blocks to the *same* random hash marks as shares.
Two independently written rolling-window calculators compare identical admitted
histories, while a live-cutoff comparator exposes the effect of confirmation lag.
Exact parity with the first comparator is not a production variance guarantee.
"""

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import statistics


DOMAIN = b"SharePool/design-only/accounting-scope/v1\x00"


def positive_integer(value):
    if type(value) is not int or value <= 0:
        raise ValueError("expected a positive integer")
    return value


def accounting_scope(chain_id, anchor_script):
    """Stable script identity. Labels, workers, template tags and keys are absent.

    Caller must supply a canonical script and separately establish its control;
    this model does not implement address decoding, signatures or registration.
    """
    if not isinstance(chain_id, bytes) or len(chain_id) != 32:
        raise ValueError("chain ID must be 32 bytes")
    if not isinstance(anchor_script, bytes) or not anchor_script:
        raise ValueError("anchor script must be nonempty bytes")
    return hashlib.sha256(DOMAIN + chain_id + len(anchor_script).to_bytes(4, "little") + anchor_script).digest()


class Membership:
    """Model of already-authorized, chain-anchored membership only.

    Existing identities cannot relabel their accounting scope. No membership
    exit is implemented: funding/release policy must be specified first.
    """

    def __init__(self):
        self.scopes = {}

    def register(self, payout_script, scope):
        if not isinstance(payout_script, bytes) or not payout_script:
            raise ValueError("invalid payout script")
        if not isinstance(scope, bytes) or len(scope) != 32:
            raise ValueError("invalid accounting scope")
        old = self.scopes.get(payout_script)
        if old is not None and old != scope:
            raise ValueError("membership migration needs an explicit release contract")
        self.scopes[payout_script] = scope

    def check_job(self, payout_script, declared_scope):
        if self.scopes.get(payout_script) != declared_scope:
            raise ValueError("job does not match anchored membership")


@dataclass(frozen=True)
class Credit:
    admitted_height: int
    proof_id: int
    scope: str
    owner: str
    work: int
    encoded_bytes: int


class BoundedCarry:
    """Exact pending-credit accounting with an illustrative byte budget.

    encoded_bytes includes a caller's complete per-record charge; framing is
    reserved outside capacity. This deliberately does not serialize native v5.
    Existing admitted work is never removed by admission or by other pools.
    """

    def __init__(self, capacity):
        self.capacity = positive_integer(capacity)
        self.pending = []
        self.admitted_ids = set()

    @property
    def used(self):
        return sum(credit.encoded_bytes for credit in self.pending)

    def admit_prefix(self, credits):
        credits = sorted(credits, key=lambda x: (x.admitted_height, x.proof_id))
        ids = set()
        for credit in credits:
            positive_integer(credit.work)
            positive_integer(credit.encoded_bytes)
            if credit.proof_id in self.admitted_ids or credit.proof_id in ids:
                raise ValueError("duplicate admission")
            ids.add(credit.proof_id)
        remaining = self.capacity - self.used
        count = 0
        for credit in credits:
            if credit.encoded_bytes > remaining:
                break
            remaining -= credit.encoded_bytes
            count += 1
        accepted, deferred = credits[:count], credits[count:]
        self.pending = sorted(self.pending + accepted, key=lambda x: (x.admitted_height, x.proof_id))
        self.admitted_ids.update(credit.proof_id for credit in accepted)
        return accepted, deferred

    def settle(self, scope, byte_budget, reward):
        """One-time v5-like weights, *not* the rolling policy below."""
        remaining = positive_integer(byte_budget)
        selected = []
        for credit in self.pending:
            if credit.scope != scope:
                continue
            if credit.encoded_bytes > remaining:
                break
            remaining -= credit.encoded_bytes
            selected.append(credit)
        if not selected:
            return [], {}
        weights = defaultdict(int)
        for credit in selected:
            weights[credit.owner] += credit.work
        paid = allocate_reward(weights, reward)
        selected_ids = {credit.proof_id for credit in selected}
        self.pending = [credit for credit in self.pending if credit.proof_id not in selected_ids]
        return selected, paid


@dataclass(frozen=True)
class Miner:
    owner: str
    scope: str
    hashrate_fraction: float
    share_work: int = 1


@dataclass(frozen=True)
class Event:
    event_id: int
    time: float
    owner: str
    scope: str
    work: int
    native_work: int
    is_block: bool
    proof_id: str


def coupled_trace(seed, intervals, miners, base_resolution=128, difficulty_changes=()):
    """Marked Poisson hash successes at the easiest share target, in wall time.

    A mark u is a native block when u < 1/native_work and a miner's share when
    u < 1/share_work. Native winners are therefore always accepted shares, not
    independent block coins. Hashrate is constant; a difficulty change changes
    block frequency rather than artificially keeping it constant.
    """
    positive_integer(intervals)
    positive_integer(base_resolution)
    if not miners or len({miner.owner for miner in miners}) != len(miners):
        raise ValueError("unique miners required")
    if any(not math.isfinite(miner.hashrate_fraction) or miner.hashrate_fraction <= 0 for miner in miners):
        raise ValueError("positive finite hashrate fractions required")
    if not math.isclose(sum(miner.hashrate_fraction for miner in miners), 1, rel_tol=0, abs_tol=1e-12):
        raise ValueError("hashrate fractions must total one")
    changes = list(difficulty_changes)
    if (changes != sorted(changes) or len({when for when, _ in changes}) != len(changes)
            or any(not math.isfinite(when) or when <= 0 for when, _ in changes)):
        raise ValueError("difficulty change times must increase and be positive")
    minimum_native = min([base_resolution] + [positive_integer(work) for _, work in changes])
    for miner in miners:
        if positive_integer(miner.share_work) > minimum_native:
            raise ValueError("share target must include the native target")
    rng = random.Random(seed)
    time, event_id, native_work, change_index = 0.0, 0, base_resolution, 0
    while True:
        time += rng.expovariate(base_resolution / 600)
        if time > intervals * 600:
            return
        while change_index < len(changes) and time >= changes[change_index][0]:
            native_work = changes[change_index][1]
            change_index += 1
        pick = rng.random()
        miner = miners[-1]
        for candidate in miners:
            pick -= candidate.hashrate_fraction
            if pick < 0:
                miner = candidate
                break
        mark = rng.random()
        event_id += 1
        if mark >= 1 / miner.share_work:
            continue
        proof_id = hashlib.sha256(f"{seed}:{event_id}:{miner.owner}".encode()).hexdigest()
        yield Event(event_id, time, miner.owner, miner.scope, miner.share_work,
                    native_work, mark < 1 / native_work, proof_id)


def rolling_weights(shares, window_work):
    """Newest work suffix, with an exactly clipped oldest boundary share."""
    remaining = positive_integer(window_work)
    weights = defaultdict(int)
    for share in reversed(shares):
        weight = min(remaining, share.work)
        weights[share.owner] += weight
        remaining -= weight
        if remaining == 0:
            break
    return dict(weights)


def reference_weights(shares, window_work):
    """Independent forward interval-overlap implementation of weighted PPLNS."""
    positive_integer(window_work)
    start = max(0, sum(share.work for share in shares) - window_work)
    position = 0
    weights = defaultdict(int)
    for share in shares:
        end = position + share.work
        overlap = max(0, end - max(start, position))
        if overlap:
            weights[share.owner] += overlap
        position = end
    return dict(weights)


def allocate_reward(weights, reward):
    """Integer satoshis, largest remainder, lexical owner tie-break; no fee."""
    if type(reward) is not int or reward < 0:
        raise ValueError("reward must be nonnegative integer satoshis")
    if not weights or any(type(work) is not int or work <= 0 for work in weights.values()):
        raise ValueError("positive work required")
    denominator = sum(weights.values())
    payouts = {owner: reward * work // denominator for owner, work in weights.items()}
    remainder = reward - sum(payouts.values())
    order = sorted(weights, key=lambda owner: (-(reward * weights[owner] % denominator), owner))
    for owner in order[:remainder]:
        payouts[owner] += 1
    return {owner: amount for owner, amount in sorted(payouts.items()) if amount}


def replay(events, window_blocks=8, admission_limit=None, reward=1_000_000):
    """Separate pool funding, no loss/expiry, actual-native-parent payout cutoff.

    At a winner, calculate payouts from the *previous* confirmed state. Admit a
    canonical prefix of eligible earlier events into this block, then queue the
    winning proof for a later block. The model assumes immediate delivery and
    one refreshed job per accepted proof. A queued proof is not an acknowledged
    guaranteed claim. No local receipt time is proposed as a consensus input.

    A full confirmed log is retained for a bounded experiment, intentionally not
    an implementation of a fixed-size rolling archive or production admission.
    """
    positive_integer(window_blocks)
    if admission_limit is not None:
        positive_integer(admission_limit)
    confirmed, live, pending = defaultdict(list), defaultdict(list), []
    totals = {name: defaultdict(int) for name in ("parent_cutoff", "same_cutoff_reference", "live_cutoff")}
    records, admissions, seen_ids = [], {}, set()
    height = 0
    for event in events:
        if event.proof_id in seen_ids:
            raise ValueError("duplicate proof in trace")
        seen_ids.add(event.proof_id)
        positive_integer(event.work)
        positive_integer(event.native_work)
        if event.work > event.native_work:
            raise ValueError("share target excludes native target")
        if event.is_block:
            height += 1
            window = window_blocks * event.native_work
            weights = {
                "parent_cutoff": rolling_weights(confirmed[event.scope], window),
                "same_cutoff_reference": reference_weights(confirmed[event.scope], window),
                "live_cutoff": reference_weights(live[event.scope], window),
            }
            payouts = {}
            fallback = []
            for name, share_weights in weights.items():
                if not share_weights:
                    # An explicit illustrative startup rule; not a solved policy.
                    share_weights = {event.owner: 1}
                    fallback.append(name)
                payouts[name] = allocate_reward(share_weights, reward)
                for owner, amount in payouts[name].items():
                    totals[name][owner] += amount
            # Same parent-assigned eligible batch; hash-ID order within each
            # native interval. Later local arrivals cannot reorder earlier ones.
            ordered = sorted(pending, key=lambda pair: (pair[0], pair[1].proof_id))
            count = len(ordered) if admission_limit is None else min(admission_limit, len(ordered))
            batch, pending = ordered[:count], ordered[count:]
            for _, share in batch:
                confirmed[share.scope].append(share)
                admissions[share.proof_id] = height
            records.append({
                "height": height, "scope": event.scope, "winner": event.owner,
                "winning_proof_id": event.proof_id, "payout_cutoff_height": height - 1,
                "payouts": payouts, "fallback_policies": fallback,
                "admitted_ids": [share.proof_id for _, share in batch],
                "deferred_count_before_winning_share": len(pending),
                "window_work": window,
            })
        # This winning proof cannot be in the job it has just solved.
        pending.append((height, event))
        live[event.scope].append(event)
    return {
        "totals": {name: dict(sorted(payout.items())) for name, payout in totals.items()},
        "blocks": records,
        "admission_heights": admissions,
        "unanchored_proof_ids": [share.proof_id for _, share in pending],
        "accepted_proofs": len(seen_ids),
        "anchored_proofs": len(admissions),
    }


def distribution(values):
    mean = statistics.fmean(values)
    variance = statistics.pvariance(values)
    return {"mean_satoshis": mean, "population_variance_satoshis_squared": variance,
            "relative_standard_deviation": math.sqrt(variance) / mean if mean else None,
            "zero_payout_trials": sum(value == 0 for value in values)}


def experiment(seed=7300, trials=64, intervals=64, base_resolution=128):
    if positive_integer(trials) > 512 or positive_integer(intervals) > 288:
        raise ValueError("bounded model: at most 512 trials and 288 nominal intervals")
    if not 4 <= positive_integer(base_resolution) <= 1024:
        raise ValueError("bounded model: base resolution must be in [4, 1024]")
    cases = []
    for name, difficulties, budget, retarget in (
        ("equal_target_complete_admission", (1, 1, 1, 1), None, False),
        ("unequal_targets_complete_admission", (1, 4, 2, 4), None, False),
        ("equal_target_capacity_backlog", (1, 1, 1, 1), base_resolution // 4, False),
        ("equal_target_native_difficulty_doubles", (1, 1, 1, 1), None, True),
    ):
        miners = tuple(Miner(owner, scope, fraction, difficulty) for owner, scope, fraction, difficulty in zip(
            ("alice", "bob", "carol", "dave"), ("A", "A", "B", "B"), (0.06, 0.14, 0.30, 0.50), difficulties))
        samples = {policy: {miner.owner: [] for miner in miners}
                   for policy in ("parent_cutoff", "same_cutoff_reference", "live_cutoff")}
        mismatches, differences, block_counts, backlogs, accepted, anchored, fallback_blocks = [], [], [], [], [], [], []
        for trial in range(trials):
            changes = ((intervals * 300, base_resolution * 2),) if retarget else ()
            result = replay(coupled_trace(seed + trial, intervals, miners, base_resolution, changes), admission_limit=budget)
            mismatches.append(sum(block["payouts"]["parent_cutoff"] != block["payouts"]["same_cutoff_reference"] for block in result["blocks"]))
            differences.append(sum(block["payouts"]["parent_cutoff"] != block["payouts"]["live_cutoff"] for block in result["blocks"]))
            block_counts.append(len(result["blocks"]))
            backlogs.append(len(result["unanchored_proof_ids"]))
            accepted.append(result["accepted_proofs"])
            anchored.append(result["anchored_proofs"])
            fallback_blocks.append(sum("parent_cutoff" in block["fallback_policies"] for block in result["blocks"]))
            for policy in samples:
                for owner in samples[policy]:
                    samples[policy][owner].append(result["totals"][policy].get(owner, 0))
        cases.append({
            "name": name, "miner_share_work": dict(zip((miner.owner for miner in miners), difficulties)),
            "admission_limit_per_native_block": budget,
            "native_difficulty_doubles_at_seconds": intervals * 300 if retarget else None,
            "same_cutoff_mismatched_block_payouts": sum(mismatches),
            "live_cutoff_different_block_payouts": sum(differences),
            "total_native_blocks": sum(block_counts), "total_accepted_proofs": sum(accepted),
            "total_anchored_proofs": sum(anchored), "total_unanchored_at_end": sum(backlogs),
            "max_unanchored_at_end": max(backlogs),
            "parent_cutoff_empty_window_blocks": sum(fallback_blocks),
            "payout_distributions": {policy: {owner: distribution(values) for owner, values in owners.items()}
                                     for policy, owners in samples.items()},
        })
    return {
        "kind": "design-only coupled marked-Poisson model; no native node or ASIC",
        "seed": seed, "independent_trials_per_case": trials,
        "wall_time_horizon_seconds_per_trial": intervals * 600,
        "initial_network_work_in_easiest_share_units": base_resolution,
        "rolling_network_work_units": 8, "reward_satoshis_per_block": 1_000_000,
        "funding": "separate pools A and B; no cross-pool reward redistribution",
        "ordering": "anchor interval then proof hash; live comparator uses submission order",
        "initial_history": "empty; no warmup; empty window pays winning identity as an illustrative rule",
        "limits": ["Synthetic constant hashrates, not real hash computation or network validation.",
                   "Immediate relay and job refresh; no stale blocks, withheld data, or reorgs.",
                   "Bounded full-history retention; neither 4 MiB state nor native 16 MiB snapshots are modeled.",
                   "No provisional-proof expiry; backlog is shown, not promised service.",
                   "Admission ordering assumes each earlier accepted event is available at job construction.",
                   "No proof of control, authorization, serialization, payout output-size limit, or fees.",
                   "Finite sample moments include startup; they are not a production variance guarantee.",
                   "Equal same-cutoff payouts test accounting, not equality with a live regular pool."],
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=7300)
    parser.add_argument("--trials", type=int, default=64)
    parser.add_argument("--intervals", type=int, default=64)
    parser.add_argument("--base-resolution", type=int, default=128)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = experiment(args.seed, args.trials, args.intervals, args.base_resolution)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
