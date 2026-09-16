#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Integrate stationary independent recipient labels over coupled PoW traces.

This is not valid for label-dependent difficulty, selection, latency, hashrate,
or job issuance. Integer payout rounding is bounded separately. Native block
and share timing, cutoff, expiry and within-height clipping remain simulated.
"""

import argparse
from bisect import bisect_right
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from fractions import Fraction
import json
from pathlib import Path
import random
import statistics
import sys

from tides_calibration import MINER_WEIGHTS, REWARD, Scenario, percentile, simulate
from tides_service_contract import CachedCohortPayouts


class ConditionalAllocation:
    """Accumulate each proof's total reward coefficient across overlapping wins.

    In a proportional-height window, all members of one admitted batch have
    equal coefficients. Range-difference updates handle full cohorts; a point
    update handles the fractional oldest cohort. Recipient labels are unused.
    """
    def __init__(self):
        self.sources = []
        self.total = [0]
        self.difference, self.partial = defaultdict(float), defaultdict(float)
        self.payout_count = 0
        self.bootstrap_count = 0

    def observe(self, batches, required_samples):
        sources = [batch for batch in batches if batch]
        if (len(sources) < len(self.sources) or
                any(a is not b for a, b in zip(sources, self.sources))):
            raise ValueError("conditional trace must preserve an append-only history")
        for batch in sources[len(self.sources):]:
            self.sources.append(batch)
            self.total.append(self.total[-1] + len(batch))
        self.payout_count += 1
        if not self.total[-1]:
            self.bootstrap_count += 1
            return
        included = min(Fraction(required_samples), self.total[-1])
        start = self.total[-1] - included
        boundary = bisect_right(self.total, start) - 1
        partial = self.total[boundary + 1] - start
        self.difference[boundary + 1] += float(1 / included)
        self.difference[len(self.sources)] -= float(1 / included)
        self.partial[boundary] += float(partial / (included * len(self.sources[boundary])))

    def statistics(self):
        if self.bootstrap_count:
            raise ValueError("conditional label estimator excludes empty-history bootstrap; increase warmup")
        cumulative = 0.0
        squares = mass = 0.0
        for i, batch in enumerate(self.sources):
            cumulative += self.difference[i]
            coefficient = cumulative + self.partial[i]
            squares += len(batch) * coefficient * coefficient
            mass += len(batch) * coefficient
        if abs(mass - self.payout_count) > 1e-8 * max(1, self.payout_count):
            raise ArithmeticError("conditional payout coefficient mass does not reconcile")
        return {"payout_count": self.payout_count,
                "sum_squared_lifetime_proof_payout_coefficients": squares,
                "total_payout_coefficient_mass": mass,
                "empty_history_bootstrap_payouts": self.bootstrap_count}


class ConditionalOracle(CachedCohortPayouts):
    def __init__(self):
        super().__init__()
        self.allocation = ConditionalAllocation()

    def __call__(self, batches, required_samples, reward, bootstrap_owner, policy="numeric"):
        if policy == "proportional":
            self.allocation.observe(batches, required_samples)
        return super().__call__(batches, required_samples, reward, bootstrap_owner, policy)


def run_conditioned(seed, scenario):
    oracle = ConditionalOracle()
    run = simulate(seed, scenario, payout_calculator=oracle)
    run["conditional_label_integration"] = oracle.allocation.statistics()
    if run["counts"].get("measured_pool_blocks", 0) != run["conditional_label_integration"]["payout_count"]:
        raise ArithmeticError("conditional payout count differs from observed blocks")
    return run


def summarize_conditioned(runs, scenario, seed, resamples=1000):
    if len(runs) < 2 or type(resamples) is not int or resamples < 1:
        raise ValueError("conditional summary requires two traces and a positive bootstrap count")
    blocks = [run["conditional_label_integration"]["payout_count"] for run in runs]
    quadratic = [run["conditional_label_integration"]["sum_squared_lifetime_proof_payout_coefficients"] for run in runs]
    block_variance = statistics.variance(blocks)
    if not block_variance:
        raise ValueError("conditional variance ratio is unavailable: observed block counts have zero variance")
    mean_quadratic = statistics.fmean(quadratic)
    rng = random.Random(seed)
    excess_factors = []
    for _ in range(resamples):
        ids = [rng.randrange(len(runs)) for _ in runs]
        variance = statistics.variance(blocks[i] for i in ids)
        if variance:
            excess_factors.append(statistics.fmean(quadratic[i] for i in ids) / variance)
    if not excess_factors:
        raise ValueError("conditional variance ratio is unavailable: bootstrap denominators are zero")
    factor_interval = [percentile(excess_factors, q) for q in (0.025, 0.975)]
    rows = []
    for fraction in MINER_WEIGHTS[:3]:
        multiplier = (1 - fraction) / fraction
        ratio = 1 + multiplier * mean_quadratic / block_variance
        interval = [1 + multiplier * x for x in factor_interval]
        # Each output is floored once per block, so cumulative absolute loss is
        # strictly less than the observed block count in satoshis, per miner.
        rounding_bound = max(blocks) / (REWARD * fraction * scenario.measured_pool_blocks)
        rows.append({"miner_fraction_of_pool": fraction,
            "total_reward_variance_ratio_to_ideal_before_integer_rounding": ratio,
            "whole_trace_bootstrap_95_percent_variance_ratio_interval": interval,
            "maximum_observed_normalized_rounding_loss_bound": rounding_bound,
            "expected_mean_difference_before_integer_rounding": 0,
            "variance_interval_within_engineering_target": interval[1] <= 1.10,
            "engineering_target_maximum_variance_ratio": 1.10})
    return {"configuration": asdict(scenario), "independent_traces": len(runs),
        "bootstrap_resamples": resamples, "observed_pool_blocks": sum(blocks),
        "sample_variance_of_pool_block_counts": block_variance,
        "mean_squared_lifetime_proof_coefficient_sum": mean_quadratic,
        "formula": "Var(payout/R) = a*a*Var(B) + a*(1-a)*E[sum_j c_j*c_j] before rounding",
        "miners": rows}


def _task(args):
    return run_conditioned(*args)


def report(replicas=64, seed=20260919, workers=4):
    if type(replicas) is not int or replicas < 16 or type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("at least sixteen independent traces and one to eight workers required")
    cases = [Scenario(pool_fraction=q, share_shift=shift, reference_shift=14, batch_limit=131072)
             for q in (0.1, 0.01, 0.001) for shift in (12, 14)]
    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for i, scenario in enumerate(cases, 1):
            runs = list(executor.map(_task, [(seed + j, scenario) for j in range(replicas)]))
            item = summarize_conditioned(runs, scenario, seed + 3_000_000)
            item["raw_runs"] = runs
            results.append(item)
            print(f"Finished conditional case {i}/{len(cases)}: pool={scenario.pool_fraction}, shift={scenario.share_shift}", file=sys.stderr, flush=True)
    return {"schema": 1, "kind": "Conditional independent-label variance integration on CPU PoW traces",
        "seed": seed, "independent_traces_per_case": replicas,
        "scenarios": results,
        "assumptions": [
            "Recipient labels are independent IID draws at constant hashrate fractions, conditionally on the pool's PoW and native block trajectory.",
            "Assigned difficulty, origin/cutoff, latency, stale handling, selection and refresh are identical across recipients and independent of their labels.",
            "This estimator is inapplicable to recipient-dependent job state, variable difficulty, deliberate label-dependent selection or changing recipient populations.",
            "All native producers cooperate and the modeled proof budget is deliberately uncongested; this does not establish native resource capacity.",
            "The coefficient statistic preserves every proof's correlated reuse across overlapping windows and issued-job cutoffs. It does not treat successive block payouts as independent.",
            "Empty-history bootstrap is rejected by this estimator rather than approximated as ordinary window payouts; the 16-expected-block warmup must remove it in measured traces.",
            "Independent recipient labels have conditional zero mean allocation error and zero block-luck covariance before integer rounding; the raw labeled simulations retain their sample covariance separately.",
            "Mean rounding loss is less than one satoshi per observed block and recipient. The stated variance formula applies before rounding.",
            "Seeds match a subset of the labeled sweep for pairing; these results are not additional independent evidence when pooled with that sweep.",
            "Confidence intervals resample whole PoW traces and estimate uncertainty in block-count variance and the conditional allocation quadratic together."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replicas", type=int, default=64)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()
    args.output.write_text(json.dumps(report(args.replicas, args.seed, args.workers),
                                     indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
