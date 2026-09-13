#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Coupled v6 TIDES sampling experiment; CPU/stdlib, never a miner benchmark.

The easiest reference's PoW successes form a marked Poisson process. Integer
hash marks thin that SAME process into harder v6 shares and native pool blocks.
Outside-pool native blocks are an independent process from independent miners.
No independently tossed pool-block coin is used. All arithmetic determining
share work, window clipping and satoshi payouts is exact; event times and Monte
Carlo statistics use floating point. Constant targets and hashrates are modeled.

This does not execute native validation, model transactions, prove availability,
or predict a particular commercial pool. 'Regular pool' needs a stated share
target, payout policy and observation interval before variance is comparable.
"""

import argparse
from array import array
from bisect import bisect_right
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from fractions import Fraction
import json
import math
from pathlib import Path
import random
import statistics
import sys


HASH_SPACE = 1 << 256
CURRENT_SHIFT = 10
ILLUSTRATIVE_BITS = 0x17034219  # A fixed test input, not a current-network claim.
NATIVE_SECONDS = 600
WINDOW_BLOCKS = 8
MAX_SHARE_AGE = 3
REWARD = 312_500_000  # Explicit illustrative reward; no forecast of fees/subsidy.
MINER_WEIGHTS = (0.01, 0.001, 0.0001, 0.9889)


def native_target(bits):
    """Independent canonical compact decoder (not imported from the codec)."""
    if type(bits) is not int or not 0 < bits <= 0xffffffff or bits & 0x800000:
        raise ValueError("invalid compact target")
    size, word = bits >> 24, bits & 0x7fffff
    target = word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))
    if not 0 < target < HASH_SPACE:
        raise ValueError("target out of range")
    canonical_size = (target.bit_length() + 7) // 8
    canonical_word = (target << (8 * (3 - canonical_size)) if canonical_size <= 3
                      else target >> (8 * (canonical_size - 3)))
    if canonical_word & 0x800000:
        canonical_word >>= 8
        canonical_size += 1
    if bits != (canonical_size << 24) | canonical_word:
        raise ValueError("noncanonical compact target")
    return target


def assigned_work(bits=ILLUSTRATIVE_BITS, shift=CURRENT_SHIFT):
    if type(shift) is not int or not 0 <= shift <= 255:
        raise ValueError("shift must be an integer in [0, 255]")
    desired = max(1, (HASH_SPACE // (native_target(bits) + 1)) >> shift)
    return 1 << (desired.bit_length() - 1)


def shares_per_native(bits=ILLUSTRATIVE_BITS, shift=CURRENT_SHIFT):
    return Fraction(HASH_SPACE, (native_target(bits) + 1) * assigned_work(bits, shift))


def share_layout_bytes(script_size=22):
    """Exact fixed v6 Share fields; checked against native wire-codec tests.

    Neither the containing snapshot nor the template, certificates, transaction
    table, transport, indexes, repeated copies, or validation work is included.
    """
    if script_size not in (22, 34):
        raise ValueError("supported native witness-script lengths are 22 and 34")
    return {"native_header": 164, "version": 1, "genesis": 32, "rules": 32,
            "origin_height": 4, "native_parent": 32, "pool": 32, "signer": 32,
            "script_length": 1, "script": script_size, "reserved": 96,
            "signature": 64}


def stationary_allocation_rsd(miner_fraction, sample_window):
    """IID equal-work label sampling, including fractional oldest proof.

    Conditional on a full ordered window whose labels are IID. This is *not*
    a wall-time payout RSD: block luck and overlapping windows remain coupled.
    """
    if not 0 < miner_fraction <= 1 or sample_window <= 0:
        raise ValueError("positive miner fraction/window required")
    n = sample_window.numerator // sample_window.denominator
    remainder = sample_window - n
    effective = sample_window ** 2 / (n + remainder ** 2)
    return math.sqrt((1 - miner_fraction) / (miner_fraction * float(effective)))


def analytic_profile(bits, shift):
    k = shares_per_native(bits, shift)
    rate = float(k) / NATIVE_SECONDS
    return {"shift": shift, "native_bits_hex": f"{bits:08x}",
            "assigned_expected_hash_work": str(assigned_work(bits, shift)),
            "exact_proofs_per_expected_native_block": [str(k.numerator), str(k.denominator)],
            "proofs_per_expected_native_block": float(k),
            "full_window_proofs": float(WINDOW_BLOCKS * k),
            "network_proofs_per_second": rate,
            "minimum_unique_proof_bytes_per_day": rate * 86400 * sum(share_layout_bytes().values()),
            "p2tr_unique_proof_bytes_per_day": rate * 86400 * sum(share_layout_bytes(34).values()),
            "proof_only_bytes_per_expected_native_block": float(k) * 512,
            "stationary_allocation_rsd_sampling_only": {
                str(a): stationary_allocation_rsd(a, WINDOW_BLOCKS * k) for a in MINER_WEIGHTS[:3]},
            "one_native_template_validation_per_unique_job_example": {
                "all_shares_have_distinct_jobs_validations_per_second": rate,
                "all_shares_have_distinct_jobs_max_origins_2048_fraction_of_mean_load": 2048 / float(k),
                "note": "Operation counts, not measured native CPU time; cache/transactions change cost."}}


def target_shift_for_allocation_rsd(bits, miner_fraction, rsd):
    if not 0 < rsd <= 1:
        raise ValueError("RSD must be in (0, 1]")
    for shift in range(256):
        if stationary_allocation_rsd(miner_fraction, WINDOW_BLOCKS * shares_per_native(bits, shift)) <= rsd:
            return shift
    return None


@dataclass(frozen=True)
class Proof:
    proof_id: int
    owner: int
    arrival: float
    origin_height: int


def payouts_from_batches(batches, required_samples, reward, bootstrap_owner, policy="numeric"):
    """Independent exact constant-target oracle for native and proposed order.

    Each list is one admitted native-height batch. Numeric is the historical
    v6-r1 proof-ID order. Proportional is the v6-r2 rule: it shares the partially
    consumed oldest height across all its proofs, so within-height hash
    selection cannot change pay. It does not prevent cross-height selection.
    """
    if policy not in ("numeric", "proportional") or required_samples <= 0 or reward < 0:
        raise ValueError("invalid payout inputs")
    remaining, weights = Fraction(required_samples), Counter()
    for batch in reversed(batches):
        if remaining <= 0:
            break
        if len(batch) <= remaining:
            weights.update(p.owner for p in batch)
            remaining -= len(batch)
            continue
        if policy == "proportional" and remaining < len(batch):
            for owner, count in Counter(p.owner for p in batch).items():
                weights[owner] += remaining * count / len(batch)
            remaining = Fraction(0)
        else:
            for proof in reversed(sorted(batch, key=lambda p: p.proof_id)):
                included = min(remaining, 1)
                weights[proof.owner] += included
                remaining -= included
                if not remaining:
                    break
    total = sum(weights.values())
    if not total:
        return {bootstrap_owner: reward}
    return {owner: int(reward * weight / total) for owner, weight in weights.items()
            if int(reward * weight / total)}


class ArrivalWindow:
    """Cumulative counts let dense reference payouts retain exact overlap cheaply."""
    def __init__(self, required_samples, owners=4):
        self.required = Fraction(required_samples)
        self.times = array("d")
        self.owners = array("B")
        self.prefix = [array("I", [0]) for _ in range(owners)]

    def append(self, when, owner):
        if self.times and when < self.times[-1]:
            raise ValueError("reference arrivals must be ordered")
        self.times.append(when)
        self.owners.append(owner)
        for i, values in enumerate(self.prefix):
            values.append(values[-1] + (i == owner))

    def pay(self, cutoff, reward, bootstrap_owner):
        end = bisect_right(self.times, cutoff)
        if not end:
            return {bootstrap_owner: reward}
        needed = min(self.required, end)
        full = needed.numerator // needed.denominator
        fraction = needed - full
        begin = end - full
        result = {}
        for owner, values in enumerate(self.prefix):
            weight = values[end] - values[begin]
            if fraction and self.owners[begin - 1] == owner:
                weight += fraction
            amount = int(reward * weight / needed)
            if amount:
                result[owner] = amount
        return result


@dataclass(frozen=True)
class Scenario:
    pool_fraction: float = 0.01
    share_shift: int = CURRENT_SHIFT
    reference_shift: int = 14
    bits: int = ILLUSTRATIVE_BITS
    refresh_seconds: float = 1.0
    propagation_seconds: float = 0.2
    submission_seconds: float = 0.2
    admission: str = "all-native"
    batch_limit: int = 2048
    warmup_pool_blocks: float = 16.0
    measured_pool_blocks: float = 24.0


def simulate(seed, scenario):
    """One independent run; same hashrate, hash marks, blocks and cutoffs for all payouts.

    All-native admission assumes cooperative foreign producers have these pool
    proofs. Only this pool's queue is simulated: competing pools' byte usage is
    NOT included; whole-network capacity bounds are separately reported.
    Pool-only is a negative control that reveals the three-height expiry gap.
    Outside-pool blocks are valid tip-extending arrivals; the tracked pool can
    additionally lose native solutions while its dispatched parent is stale.
    """
    s = scenario
    timings = (s.pool_fraction, s.refresh_seconds, s.propagation_seconds,
               s.submission_seconds, s.warmup_pool_blocks, s.measured_pool_blocks)
    if (any(not isinstance(v, (float, int)) or isinstance(v, bool) or not math.isfinite(v) for v in timings) or
            not 0 < s.pool_fraction <= 1 or s.reference_shift < s.share_shift or
            s.refresh_seconds <= 0 or min(s.submission_seconds, s.propagation_seconds) < 0 or
            type(s.batch_limit) is not int or s.batch_limit <= 0 or s.warmup_pool_blocks < 0 or s.measured_pool_blocks <= 0 or
            s.admission not in ("all-native", "pool-only")):
        raise ValueError("invalid scenario")
    rng = random.Random(seed)
    native = native_target(s.bits)
    work, ref_work = assigned_work(s.bits, s.share_shift), assigned_work(s.bits, s.reference_shift)
    target, ref_target = HASH_SPACE // work - 1, HASH_SPACE // ref_work - 1
    k, ref_k = shares_per_native(s.bits, s.share_shift), shares_per_native(s.bits, s.reference_shift)
    warmup = s.warmup_pool_blocks * NATIVE_SECONDS / s.pool_fraction
    end = warmup + s.measured_pool_blocks * NATIVE_SECONDS / s.pool_fraction
    dense_rate = s.pool_fraction * float(ref_k) / NATIVE_SECONDS
    external_rate = (1 - s.pool_fraction) / NATIVE_SECONDS
    next_share = rng.expovariate(dense_rate)
    next_external = rng.expovariate(external_rate) if external_rate else math.inf
    native_times = [-math.inf]
    pending, batches = [], []
    same_reference = ArrivalWindow(WINDOW_BLOCKS * k)
    dense_reference = ArrivalWindow(WINDOW_BLOCKS * ref_k)
    payouts = {key: [0] * 4 for key in ("numeric", "proportional", "same_target_arrival", "dense_arrival", "ideal_fixed_split")}
    stats = Counter()
    thresholds = (MINER_WEIGHTS[0], sum(MINER_WEIGHTS[:2]), sum(MINER_WEIGHTS[:3]))

    def process_block(when, pool_block, winner=3):
        nonlocal pending
        height = len(native_times)
        cutoff = math.floor((when - s.propagation_seconds) / s.refresh_seconds) * s.refresh_seconds
        if pool_block and cutoff < native_times[-1]:
            stats["stale_pool_native_solutions"] += 1
            return
        # Outside producers are the explicit valid-block process. Their job is
        # at least as recent as its native parent, but still excludes the winner.
        cutoff = max(cutoff, native_times[-1])
        available, keep = [], []
        for proof in pending:
            if height - proof.origin_height > MAX_SHARE_AGE:
                stats["expired_current_proofs"] += 1
            elif proof.arrival <= cutoff:
                available.append(proof)
            else:
                keep.append(proof)
        # Stable local ACK/arrival prefix. Network peers can observe different
        # arrival orders; this is a local carry policy, not global consensus.
        available.sort(key=lambda p: (p.arrival, p.proof_id))
        chosen = available[:s.batch_limit] if pool_block or s.admission == "all-native" else []
        pending = keep + available[len(chosen):]
        stats["deferred_proof_block_opportunities"] += len(available) - len(chosen)
        stats["peak_pending_proofs"] = max(stats["peak_pending_proofs"], len(pending))
        if pool_block and when >= warmup:
            stats["measured_pool_blocks"] += 1
            for policy in ("numeric", "proportional"):
                pay = payouts_from_batches(batches + [chosen], WINDOW_BLOCKS * k, REWARD, winner, policy)
                for owner, amount in pay.items():
                    payouts[policy][owner] += amount
            for label, reference in (("same_target_arrival", same_reference), ("dense_arrival", dense_reference)):
                for owner, amount in reference.pay(cutoff, REWARD, winner).items():
                    payouts[label][owner] += amount
            for owner, fraction in enumerate(MINER_WEIGHTS):
                payouts["ideal_fixed_split"][owner] += int(REWARD * fraction)
        if chosen:
            stats["admitted_current_proofs"] += len(chosen)
            batches.append(chosen)
        native_times.append(when)
        stats["native_blocks"] += 1

    while min(next_share, next_external) <= end:
        if next_external < next_share:
            process_block(next_external, False)
            next_external += rng.expovariate(external_rate)
            continue
        when = next_share
        next_share += rng.expovariate(dense_rate)
        mark = rng.randrange(ref_target + 1)
        u = rng.random()
        owner = 0 if u < thresholds[0] else 1 if u < thresholds[1] else 2 if u < thresholds[2] else 3
        stats["dense_hash_success_events"] += 1
        cutoff = math.floor((when - s.propagation_seconds) / s.refresh_seconds) * s.refresh_seconds
        known_height = bisect_right(native_times, cutoff) - 1
        origin_height = known_height + 1
        stale = cutoff < native_times[-1]
        if mark <= native:
            stats["pool_native_solutions"] += 1
            assert mark <= target, "every native solution must also be a v6 share"
            process_block(when, True, owner)
        if stale:
            stats["stale_dense_proofs"] += 1
            if mark <= target:
                stats["stale_current_proofs"] += 1
            continue
        # A winning solution is added only AFTER computing its frozen job payout.
        # No winner can insert itself into the snapshot it has just solved.
        dense_reference.append(when + s.submission_seconds, owner)
        if mark <= target:
            stats["eligible_current_proofs"] += 1
            pending.append(Proof(mark, owner, when + s.submission_seconds, origin_height))
            same_reference.append(when + s.submission_seconds, owner)
    stats["remaining_current_proofs"] = len(pending)
    assert stats["eligible_current_proofs"] == (stats["admitted_current_proofs"] +
        stats["expired_current_proofs"] + stats["remaining_current_proofs"])
    return {"seed": seed, "payouts": payouts, "counts": dict(stats)}


def mean_interval(values):
    mean = statistics.fmean(values)
    se = statistics.stdev(values) / math.sqrt(len(values)) if len(values) > 1 else 0
    return {"mean": mean, "standard_error": se, "approximate_95_percent_mean_interval": [mean - 1.96 * se, mean + 1.96 * se]}


def percentile(values, q):
    values = sorted(values)
    x = (len(values) - 1) * q
    low = int(x)
    return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (x - low)


def variance_decomposition(total, fixed):
    """Keep the covariance term; do not subtract block luck as if independent."""
    residual = [x - y for x, y in zip(total, fixed)]
    mf, mr = statistics.fmean(fixed), statistics.fmean(residual)
    covariance = sum((f - mf) * (r - mr) for f, r in zip(fixed, residual)) / (len(total) - 1)
    return {"total_reward_variance": statistics.variance(total),
            "fixed_split_block_luck_variance": statistics.variance(fixed),
            "allocation_residual_variance": statistics.variance(residual),
            "twice_block_luck_allocation_covariance": 2 * covariance,
            "identity": "total = fixed_split + allocation_residual + twice_covariance"}


def summarize(runs, scenario, bootstrap_seed):
    """Uncertainty resamples whole independent runs, never correlated blocks."""
    counts = dict(sum((Counter(r["counts"]) for r in runs), Counter()))
    counts.pop("peak_pending_proofs", None)
    result = {"configuration": asdict(scenario), "runs": len(runs),
              "measured_seconds_per_run": scenario.measured_pool_blocks * 600 / scenario.pool_fraction,
              "warmup_seconds_per_run": scenario.warmup_pool_blocks * 600 / scenario.pool_fraction,
              "counts_sum": counts,
              "peak_pending_proofs_across_runs": max(r["counts"].get("peak_pending_proofs", 0) for r in runs),
              "miners": []}
    for owner, fraction in enumerate(MINER_WEIGHTS[:3]):
        expected = REWARD * fraction * scenario.measured_pool_blocks
        by_label = {label: [r["payouts"][label][owner] / expected for r in runs] for label in runs[0]["payouts"]}
        item = {"pool_hashrate_fraction": fraction, "normalization_expected_satoshis": expected, "payouts": {}}
        for label, values in by_label.items():
            mean = statistics.fmean(values)
            item["payouts"][label] = {**mean_interval(values),
                "sample_variance_of_normalized_total_reward": statistics.variance(values),
                "relative_standard_deviation": statistics.stdev(values) / mean if mean else None,
                "zero_payout_runs": sum(value == 0 for value in values),
                "variance_decomposition": variance_decomposition(values, by_label["ideal_fixed_split"])}
        item["paired_comparisons"] = {}
        for label in ("numeric", "proportional", "same_target_arrival"):
            a, b = by_label[label], by_label["dense_arrival"]
            rng = random.Random(bootstrap_seed + owner)
            ratios = []
            for _ in range(400):
                ids = [rng.randrange(len(runs)) for _ in runs]
                numerator = statistics.variance(a[i] for i in ids)
                denominator = statistics.variance(b[i] for i in ids)
                if denominator:
                    ratios.append(numerator / denominator)
            denominator = statistics.variance(b)
            item["paired_comparisons"][label + "_versus_dense_arrival"] = {
                "paired_normalized_reward_difference": mean_interval([x - y for x, y in zip(a, b)]),
                "sample_total_reward_variance_ratio": statistics.variance(a) / denominator if denominator else None,
                "whole_run_bootstrap_95_percent_variance_ratio_interval": [percentile(ratios, 0.025), percentile(ratios, 0.975)] if ratios else None,
                "bootstrap_resamples": 400}
        result["miners"].append(item)
    return result


def _run_task(args):
    return simulate(*args)


def report(replicates=32, seed=20260913, measured_pool_blocks=24, warmup_pool_blocks=16, progress=None, workers=1):
    if type(replicates) is not int or replicates < 4:
        raise ValueError("at least four independent runs required")
    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("workers must be an integer in [1, 8]")
    configurations = [Scenario(pool_fraction=q, measured_pool_blocks=measured_pool_blocks,
                       warmup_pool_blocks=warmup_pool_blocks) for q in (0.1, 0.01, 0.001)]
    configurations += [Scenario(pool_fraction=0.01, admission="pool-only", measured_pool_blocks=measured_pool_blocks,
                               warmup_pool_blocks=warmup_pool_blocks),
                       Scenario(pool_fraction=0.01, refresh_seconds=30, propagation_seconds=2, submission_seconds=2,
                               measured_pool_blocks=measured_pool_blocks, warmup_pool_blocks=warmup_pool_blocks),
                       Scenario(pool_fraction=0.01, batch_limit=4, measured_pool_blocks=measured_pool_blocks,
                               warmup_pool_blocks=warmup_pool_blocks)]
    scenarios = []
    executor = ProcessPoolExecutor(max_workers=workers) if workers > 1 else None
    try:
        for s in configurations:
            # The same seeds give matched traces when only admission changes.
            tasks = [(seed + i, s) for i in range(replicates)]
            runs = list(executor.map(_run_task, tasks)) if executor else [_run_task(task) for task in tasks]
            scenarios.append(summarize(runs, s, seed + 100000))
            if progress:
                progress(len(scenarios), len(configurations))
    finally:
        if executor:
            executor.shutdown(wait=True)
    profiles = [analytic_profile(ILLUSTRATIVE_BITS, shift) for shift in (10, 12, 14, 16, 18, 19)]
    return {"schema": 1, "kind": "v6-r2 exact-work analytics and coupled CPU Monte Carlo; not native validation or a GPU test",
            "primary_payout_policy": "proportional (v6 rules revision 2)",
            "historical_negative_control": "numeric (v6 rules revision 1)",
            "seed": seed, "independent_runs_per_scenario": replicates,
            "proof_layout_bytes": {str(n): share_layout_bytes(n) for n in (22, 34)},
            "analytic_profiles": profiles,
            "illustrative_5_percent_per_block_allocation_sampling_rsd_targets": [
                {"miner_pool_fraction": a, "minimum_shift_at_illustrative_bits": target_shift_for_allocation_rsd(ILLUSTRATIVE_BITS, a, 0.05)}
                for a in MINER_WEIGHTS[:3]],
            "fixed_day_ideal_block_luck_rsd": {str(q): 1 / math.sqrt(144 * q) for q in (0.1, 0.01, 0.001, 0.0001)},
            "scenarios": scenarios,
            "interpretation_limits": [
                "Proportional is v6-r2 within-height clipping; numeric is the historical v6-r1 negative control. Both retain the exact eight-work window.",
                "An arrival-ordered TIDES pool at the same target is matched exactly in event work and issuance cutoff, not claimed to represent every regular pool.",
                "The denser benchmark uses shift 14 (16 times as many shares as shift 10 at these bits); this is an explicit benchmark, not a measured commercial pool setting.",
                "All-native scenario assumes every native producer relays this pool's verified work; producer censorship and data withholding can defeat that assumption.",
                "The simulation bounds this pool's proof count per batch. It does not simulate competing pools' template or transaction bandwidth; analytical whole-network traffic exposes that missing resource cost.",
                "Bounded carry uses each producer's stable local ACK arrival order. This does not manufacture a provable global receipt order or compel a producer to acknowledge work.",
                "Every tracked pool native solution is one of the same integer hash-marked share events; its own work enters only a later frozen job.",
                "Outside-pool native blocks are valid independent tip extensions; propagation/stale-job delay is applied to the tracked pool, not simulated throughout the external network.",
                "Regular-pool comparators retain received work without the native three-height admission expiry; the negative control intentionally quantifies this economic difference.",
                "No difficulty retarget, changing hashrate, withholding adversary, transaction validation, network partition, proof forgery or real device is modeled.",
                "Exact work describes the PoW threshold. The model omits the negligible protocol exclusion of a zero proof ID (one hash value out of 2^256).",
                "The horizon is fixed wall time expressed in expected pool blocks, not stopping after an observed block count. Warmup starts with empty history and is excluded from measured payouts.",
                "Mean intervals use a normal approximation; variance-ratio intervals bootstrap complete independent runs. Finite samples cannot certify a universal variance tolerance.",
                "Sampling-only per-block allocation RSD, overlapping-window payout variation and native block luck are distinct quantities. Variance ratios use total wall-time rewards with their covariance intact.",
                "Difficulty profile changes alter consensus rules; this tool never changes or activates a node's target.",
                "Native CPU cost, realistic full-template traffic, archival write throughput and peer replication need separate measured benchmarks."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replicates", type=int, default=32)
    parser.add_argument("--seed", type=int, default=20260913)
    parser.add_argument("--measured-pool-blocks", type=float, default=24)
    parser.add_argument("--warmup-pool-blocks", type=float, default=16)
    parser.add_argument("--workers", type=int, default=1, help="1–8 CPU processes; output is independent of worker count")
    args = parser.parse_args()
    value = report(args.replicates, args.seed, args.measured_pool_blocks, args.warmup_pool_blocks,
                   lambda done, total: print(f"Completed calibration scenario {done}/{total}", file=sys.stderr, flush=True),
                   args.workers)
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(raw, encoding="utf-8")
    else:
        print(raw, end="")


if __name__ == "__main__":
    main()
