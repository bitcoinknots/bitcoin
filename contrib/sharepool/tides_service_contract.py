#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Candidate variance envelopes and explicit capacity bounds; no native activation.

Shares/native finds are drawn by the existing coupled event generator. Cached
cohort prefix counts accelerate exact payout queries and are independently
checked against the original straightforward oracle. Historical calibration
artifacts and defaults are retained unchanged.
"""

import argparse
from array import array
from bisect import bisect_right
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from fractions import Fraction
import json
import math
from pathlib import Path
import random
import statistics
import sys

from tides_calibration import (ILLUSTRATIVE_BITS, MINER_WEIGHTS, REWARD, Scenario,
    analytic_profile, mean_interval, percentile, shares_per_native, simulate,
    summarize, variance_decomposition)


class CachedCohortPayouts:
    """Exact constant-target prefix oracle; immutable batch lists are required.

    Cached cohorts retain their source lists, so object IDs cannot be recycled
    into a false hit. Any changed history prefix resets the cache. This is only
    a simulation optimization, not an archival or native validation cache.
    """
    def __init__(self):
        self.clear()

    def clear(self):
        self.sources, self.orders = [], []
        self.total = [0]
        self.prefix = [[0] for _ in MINER_WEIGHTS]

    def __call__(self, batches, required_samples, reward, bootstrap_owner, policy="numeric"):
        if policy not in ("numeric", "proportional") or required_samples <= 0 or reward < 0:
            raise ValueError("invalid payout inputs")
        common = min(len(batches), len(self.sources))
        if len(self.sources) > len(batches) or any(batches[i] is not self.sources[i] for i in range(common)):
            self.clear()
        for batch in batches[len(self.sources):]:
            ordered = array("B", (p.owner for p in sorted(batch, key=lambda p: p.proof_id)))
            counts = Counter(ordered)
            if any(owner >= len(self.prefix) for owner in counts):
                raise ValueError("unsupported simulated owner")
            self.sources.append(batch)
            self.orders.append(ordered)
            self.total.append(self.total[-1] + len(batch))
            for owner, values in enumerate(self.prefix):
                values.append(values[-1] + counts[owner])
        if not self.total[-1]:
            return {bootstrap_owner: reward}
        included = min(Fraction(required_samples), self.total[-1])
        start = self.total[-1] - included
        boundary = bisect_right(self.total, start) - 1
        weights = Counter({owner: values[-1] - values[boundary + 1]
                           for owner, values in enumerate(self.prefix)})
        partial = self.total[boundary + 1] - start
        ordered = self.orders[boundary]
        if policy == "proportional":
            for owner, count in Counter(ordered).items():
                weights[owner] += partial * count / len(ordered)
        else:
            full = partial.numerator // partial.denominator
            if full:
                weights.update(ordered[len(ordered) - full:])
            fraction = partial - full
            if fraction:
                weights[ordered[len(ordered) - full - 1]] += fraction
        return {owner: int(reward * weight / included) for owner, weight in weights.items()
                if int(reward * weight / included)}


def run_fast(seed, scenario):
    return simulate(seed, scenario, payout_calculator=CachedCohortPayouts())


def compare_to_ideal(runs, scenario, seed, resamples=1000):
    """Stationary infinitely-dense reference, with the same actual block luck."""
    output = []
    for owner, weight in enumerate(MINER_WEIGHTS[:3]):
        expected = REWARD * weight * scenario.measured_pool_blocks
        actual = [r["payouts"]["proportional"][owner] / expected for r in runs]
        ideal = [r["payouts"]["ideal_fixed_split"][owner] / expected for r in runs]
        rng = random.Random(seed + owner)
        ratios = []
        for _ in range(resamples):
            ids = [rng.randrange(len(runs)) for _ in runs]
            denominator = statistics.variance(ideal[i] for i in ids)
            if denominator:
                ratios.append(statistics.variance(actual[i] for i in ids) / denominator)
        interval = [percentile(ratios, 0.025), percentile(ratios, 0.975)] if ratios else None
        difference = mean_interval([a - b for a, b in zip(actual, ideal)])
        ratio = statistics.variance(actual) / statistics.variance(ideal) if statistics.variance(ideal) else None
        output.append({"miner_fraction_of_pool": weight,
            "sample_total_reward_variance_ratio_to_ideal": ratio,
            "whole_run_bootstrap_95_percent_variance_ratio_interval": interval,
            "paired_reward_difference_normalized_to_expected": difference,
            "variance_decomposition": variance_decomposition(actual, ideal),
            "engineering_target_maximum_variance_ratio": 1.10,
            "engineering_target_maximum_absolute_normalized_mean_difference": 0.02,
            "variance_interval_within_engineering_target": interval is not None and interval[1] <= 1.10,
            "mean_interval_within_engineering_target": all(-0.02 <= x <= 0.02 for x in difference["approximate_95_percent_mean_interval"]),
            "bootstrap_resamples": resamples})
    return output


def compact_size_length(value):
    if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
        raise ValueError("CompactSize needs an unsigned uint64")
    return 1 if value < 253 else 3 if value <= 65535 else 5 if value <= 0xffffffff else 9


def capacity_predicates(proof_count, *, expanded_bytes_per_origin,
                        transaction_references_per_origin, proofs_per_origin=1,
                        transaction_reuse="disjoint", coinbase_bytes=128):
    """Necessary bounds for a declared workload, never a sufficient admission test.

    Transaction-table index lengths are bounded below by one byte (not assumed
    to be 32-byte transaction hashes). Table bytes are raw transactions plus at
    least one vector-length byte each. Snapshot envelope, certificate/state and
    payout overhead is omitted, so passing the wire bound proves no headroom.
    Every different origin has a different coinbase in the shared-set model.
    """
    positive = (expanded_bytes_per_origin, transaction_references_per_origin,
                proofs_per_origin, coinbase_bytes)
    if (not math.isfinite(proof_count) or proof_count <= 0 or
            any(type(v) is not int or v <= 0 for v in positive) or
            transaction_reuse not in ("disjoint", "all_noncoinbase_shared")):
        raise ValueError("invalid capacity workload")
    body_overhead = 164 + compact_size_length(transaction_references_per_origin)
    raw_transaction_bytes = expanded_bytes_per_origin - body_overhead
    if raw_transaction_bytes < coinbase_bytes + transaction_references_per_origin - 1:
        raise ValueError("expanded body cannot contain the declared transactions")
    if transaction_references_per_origin == 1:
        coinbase_bytes = raw_transaction_bytes
    proofs = math.ceil(proof_count)
    origins = (proofs + proofs_per_origin - 1) // proofs_per_origin
    refs = origins * transaction_references_per_origin
    if transaction_reuse == "disjoint":
        table_raw_bytes = origins * raw_transaction_bytes
        table_transactions = refs
    else:
        table_raw_bytes = raw_transaction_bytes - coinbase_bytes + origins * coinbase_bytes
        table_transactions = transaction_references_per_origin - 1 + origins
    wire_lower_bound = (proofs * 512 + origins * (32 + body_overhead) + refs +
                        table_raw_bytes + table_transactions)
    demand = {"origins": origins, "expanded_template_bytes": origins * expanded_bytes_per_origin,
              "transaction_references": refs, "snapshot_wire_lower_bound_bytes": wire_lower_bound}
    limits = {"origins": 2048, "expanded_template_bytes": 512 * 1024 * 1024,
              "transaction_references": 2_000_000, "snapshot_wire_lower_bound_bytes": 16 * 1024 * 1024}
    checks = {name: demand[name] <= limit for name, limit in limits.items()}
    checks["individual_template_bytes"] = expanded_bytes_per_origin <= 4_000_000
    return {"assumptions": {"proof_count": proof_count, "charged_integer_proof_count": proofs,
                "expanded_bytes_per_origin": expanded_bytes_per_origin,
                "transaction_references_per_origin": transaction_references_per_origin,
                "proofs_per_origin": proofs_per_origin, "transaction_reuse": transaction_reuse,
                "unique_coinbase_bytes_per_origin": coinbase_bytes},
            "demand": demand, "limits": limits, "necessary_predicates": checks,
            "not_ruled_out_by_necessary_bounds": all(checks.values()),
            "sufficient_for_native_admission": False,
            "caveat": "Passing only means these necessary resource bounds do not rule it out. Wire is a lower bound; origins/payouts/certificates/queues, actual validation time and burst competition remain."}


def capacity_bounds(bits=ILLUSTRATIVE_BITS):
    """Necessary mean and burst-load bounds, not native throughput estimates."""
    rows = []
    for shift in (10, 12, 14):
        k = float(shares_per_native(bits, shift))
        # Conditional on every qualifying proof also having independent native
        # probability 1/K, proofs through the next native find are geometric.
        # This is a network-load quantile, not an independent Poisson count in
        # a fixed ten-minute interval, and does not assert immediate admission.
        p99 = math.ceil(math.log(0.01) / math.log1p(-1 / k)) if k > 1 else 1
        workloads = []
        for size, refs in ((512, 1), (100_000, 200), (1_000_000, 2000), (4_000_000, 8000)):
            for reuse in ("disjoint", "all_noncoinbase_shared"):
                for proofs_per_origin in (1, 16):
                    assumptions = dict(expanded_bytes_per_origin=size,
                        transaction_references_per_origin=refs, proofs_per_origin=proofs_per_origin,
                        transaction_reuse=reuse)
                    workloads.append({"at_rounded_mean_proof_load": capacity_predicates(k, **assumptions),
                                      "at_geometric_99_percent_proof_load": capacity_predicates(p99, **assumptions),
                                      "at_conservative_shift_density_upper_mean_load": capacity_predicates(1 << (shift + 1), **assumptions)})
        rows.append({"shift": shift, **analytic_profile(bits, shift),
            "mean_seconds_between_network_proofs": 600 / k,
            "proof_density_interval_away_from_easy_target_clamp": {"inclusive_lower": 1 << shift, "exclusive_upper": 1 << (shift + 1)},
            "geometric_99_percent_network_proofs_through_next_native_find": p99,
            "current_2048_origin_budget_fraction_of_mean_unique_job_demand": min(1, 2048 / k),
            "current_512MiB_expanded_budget_mean_bytes_per_unique_job": (512 * 1024 * 1024) / k,
            "current_2million_reference_budget_mean_references_per_unique_job": 2_000_000 / k,
            "current_16MiB_snapshot_mean_bytes_per_proof_all_fields": (16 * 1024 * 1024) / k,
            "workload_feasibility_predicates": workloads,
            "examples_distinct_full_bodies": [
                {"expanded_bytes_per_origin": size, "maximum_origins_by_512MiB_expanded_limit": (512 * 1024 * 1024) // size,
                 "maximum_fraction_of_mean_proofs_if_every_proof_has_new_origin": min(1, (512 * 1024 * 1024) // size / k),
                 "mean_expanded_bytes_per_native_block": size * k}
                for size in (100_000, 1_000_000, 4_000_000)]})
    return rows


def _task(arg):
    seed, scenario = arg
    return run_fast(seed, scenario)


def report(*, replicas=128, seed=20260919, workers=4, measured=24, warmup=16, controls=True):
    if type(replicas) is not int or replicas < 16 or type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("at least sixteen runs and one to eight workers required")
    # High per-pool count limit isolates payout policy/difficulty in the main
    # sweep. It is explicitly not a claim that current native budgets admit it.
    cases = [("uncongested_variance", Scenario(pool_fraction=q, share_shift=shift, reference_shift=14,
                batch_limit=131072, measured_pool_blocks=measured, warmup_pool_blocks=warmup))
             for q in (0.1, 0.01, 0.001) for shift in (10, 12, 14)]
    if controls:
        # A single tracked pool representing all network work makes the record
        # budget global, unlike quietly giving every small pool the full quota.
        cases += [("global_capacity_control", Scenario(pool_fraction=1, share_shift=shift, reference_shift=14,
                    batch_limit=(512 * 1024 * 1024) // 4_000_000, measured_pool_blocks=measured, warmup_pool_blocks=warmup))
                  for shift in (12, 14)]
    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for number, (kind, s) in enumerate(cases, 1):
            runs = list(executor.map(_task, [(seed + i, s) for i in range(replicas)]))
            item = summarize(runs, s, seed + 1_000_000)
            item["scenario_kind"] = kind
            item["comparison_to_stationary_infinitely_dense_pool"] = compare_to_ideal(runs, s, seed + 2_000_000)
            item["raw_runs"] = runs
            results.append(item)
            print(f"Finished service-contract scenario {number}/{len(cases)}: pool={s.pool_fraction}, shift={s.share_shift}, kind={kind}", file=sys.stderr, flush=True)
    return {"schema": 1, "kind": "Engineering variance envelope candidates; CPU coupled simulation, no rule activation",
        "seed": seed, "independent_runs_per_case": replicas,
        "engineering_targets_are_proposals_not_native_or_user_approved_guarantees": True,
        "horizon": {"warmup_expected_pool_blocks": warmup, "measured_expected_pool_blocks": measured,
                    "stopping_rule": "fixed wall time, not a fixed observed number of wins"},
        "candidate_shifts": [10, 12, 14], "reference_shift": 14,
        "capacity_necessary_conditions": capacity_bounds(),
        "scenarios": results,
        "limits": [
            "The main sweep uses deliberately uncongested admission to isolate difficulty and proportional-height effects. Current native resource budgets do not necessarily support that load.",
            "The ideal fixed split is the infinitely-dense TIDES limit only for steady hashrate fractions, unchanged difficulty and complete work reception; it is not an FPPS promise independent of block luck.",
            "Shares and pool native finds use the same integer hash marks; scenarios differing only in target or admission use the same seeds and event stream. No actual miner or GPU is used.",
            "Confidence intervals resample complete independent runs; overlapping rolling-window observations are never treated as independent payout samples.",
            "A variance ratio target does not guarantee small absolute payout variance, fast earnings, universal inclusion or payment from a pool that stops finding blocks.",
            "Low-participation miners remain permissionless; a tested service envelope limits supported statistical claims, not permission to mine or choose a payout recipient.",
            "Only the all-network single-pool controls apply the modeled count budget globally. The main pool-fraction sweep does not include other pools' competing template traffic.",
            "Unique job demands depend on template/receipt refresh, transaction-set reuse and assigned difficulty. Shared wire transactions do not themselves remove expanded-body or native-validation budgets.",
            "No measured native throughput, archival startup, changing miner population, hashrate retarget, malicious withholding or WAN performance is supplied by this simulation.",
            "No commercial pool's particular vardiff cadence is assumed. The finite dense reference is explicit and the ideal stationary reference supplies a stricter variance comparison."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replicas", type=int, default=128)
    parser.add_argument("--seed", type=int, default=20260919)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--measured-pool-blocks", type=float, default=24)
    parser.add_argument("--warmup-pool-blocks", type=float, default=16)
    parser.add_argument("--no-controls", action="store_true")
    args = parser.parse_args()
    result = report(replicas=args.replicas, seed=args.seed, workers=args.workers,
                    measured=args.measured_pool_blocks, warmup=args.warmup_pool_blocks, controls=not args.no_controls)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
