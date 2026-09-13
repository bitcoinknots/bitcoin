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
from decimal import Decimal, localcontext
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


def geometric_sum_quantile(mean, count=1, probability=0.99):
    """Quantile of count positive geometric waiting counts, via a binomial tail.

    This is an analytic workload quantile, not a new Monte Carlo run. Individual
    proofs have native success probability 1/mean; no cutoff or stale losses are
    included. Quantiles of different quantities are not a joint guarantee.
    """
    # Bound the numerical helper's domain: Decimal precision must resolve
    # 1-p and the requested tail. These are analysis limits, not native rules.
    if (type(mean) is bool or not math.isfinite(mean) or not 1 <= mean <= 2**32 or
            type(count) is not int or not 1 <= count <= 8 or
            not 1e-12 <= probability <= 1 - 1e-12):
        raise ValueError("invalid geometric workload")
    if mean == 1:
        return count
    # Decimal arithmetic avoids a binary-float CDF just below an exact
    # threshold (for example the median of several fair-coin waiting counts).
    # This remains numerical evaluation, not arbitrary exact rational math.
    with localcontext() as ctx:
        ctx.prec = 50
        p, threshold = 1 / Decimal(str(mean)), Decimal(str(probability))
        def cdf(n):
            if n < count:
                return Decimal(0)
            smaller = sum(Decimal(math.comb(n, i)) * p**i * (1 - p)**(n - i)
                          for i in range(count))
            return 1 - smaller
        low, high = count - 1, max(count, math.ceil(mean * count))
        while cdf(high) < threshold:
            high *= 2
        while low + 1 < high:
            mid = (low + high) // 2
            if cdf(mid) >= threshold:
                high = mid
            else:
                low = mid
        return high


def v6_snapshot_resources(*, proofs, recent_proofs, origins, recent_origins,
                          recipients, script_bytes=22, body_bytes=100_000,
                          noncoinbase_transactions=199, transaction_sets=1,
                          unique_coinbases=None, script_sig_bytes=100):
    """Account declared v6 vectors with lower/upper CompactSize wire bounds.

    The uniform workload assigns the same recipient count/body size to every
    origin. Non-coinbase sets are disjoint from each other and reused by origins;
    coinbase sharing is explicit. Bounds describe encoded bytes, not native
    transaction validity, achievable mining cadence or allocation overhead.
    An origin-free opening may still repeat the full recent state and payouts.
    """
    values = (proofs, recent_proofs, origins, recent_origins, recipients,
              body_bytes, noncoinbase_transactions, transaction_sets, script_sig_bytes)
    if (any(type(v) is not int or v < 0 for v in values) or script_bytes not in (22, 34) or
            script_sig_bytes > 100):
        raise ValueError("invalid v6 workload")
    if unique_coinbases is None:
        unique_coinbases = origins
    if (type(unique_coinbases) is not int or unique_coinbases < 0 or
            (origins and not 1 <= unique_coinbases <= origins) or
            (not origins and unique_coinbases) or
            (origins and not 1 <= transaction_sets <= origins)):
        raise ValueError("invalid transaction sharing assumptions")
    output_bytes = (8 + 1 + script_bytes) * recipients
    # Explicit 100-byte-or-shorter scriptSig, one null coinbase input,
    # R payout outputs, one 47-byte witness commitment and its 36 witness bytes.
    coinbase_base = 4 + 1 + 36 + 1 + script_sig_bytes + 4 + compact_size_length(recipients + 1) + output_bytes + 47 + 4
    coinbase_raw = coinbase_base + 36
    references = table_count = table_lower = table_upper = record_lower = record_upper = 0
    if origins:
        tx_count = noncoinbase_transactions + 1
        noncoinbase_bytes = body_bytes - 164 - compact_size_length(tx_count) - coinbase_raw
        if noncoinbase_bytes < noncoinbase_transactions * 10 or (not noncoinbase_transactions and noncoinbase_bytes):
            raise ValueError("body cannot contain the declared coinbase and transaction sets")
        table_count = transaction_sets * noncoinbase_transactions + unique_coinbases
        table_raw = transaction_sets * noncoinbase_bytes + unique_coinbases * coinbase_raw
        table_lower = table_raw + table_count
        table_upper = (table_raw + transaction_sets * noncoinbase_transactions * compact_size_length(noncoinbase_bytes) +
                       unique_coinbases * compact_size_length(coinbase_raw))
        references = origins * tx_count
        record_lower = origins * (32 + 164 + compact_size_length(tx_count)) + references
        record_upper = (origins * (32 + 164 + compact_size_length(tx_count)) +
                        references * compact_size_length(table_count - 1))
    counts = (table_count, origins, proofs, recent_proofs, recipients, recent_origins)
    framing = 284 + script_bytes - 22 + 64 + 32 + 32 + sum(compact_size_length(n) for n in counts)
    fixed = framing + proofs * (512 + script_bytes - 22) + recent_proofs * 36 + recent_origins * 100 + output_bytes
    lower, upper = fixed + table_lower + record_lower, fixed + table_upper + record_upper
    certificate_bytes = compact_size_length(recent_origins) + 100 * recent_origins
    reservation = 4 * (379 + output_bytes) + 36
    checks = {"snapshot_lower_bound_within_16MiB": lower <= 16 * 1024 * 1024,
              "snapshot_upper_bound_within_16MiB": upper <= 16 * 1024 * 1024,
              "expanded_bodies_within_512MiB": origins * body_bytes <= 512 * 1024 * 1024,
              "references_within_2million": references <= 2_000_000,
              "certificates_within_4MiB": certificate_bytes <= 4 * 1024 * 1024,
              "individual_body_within_4million_bytes": not origins or body_bytes <= 4_000_000,
              "payout_reservation_within_4million_WU": reservation <= 4_000_000,
              "payout_reservation_within_RDTS_800000_WU": reservation <= 800_000}
    return {"assumptions": {"proofs": proofs, "recent_proofs": recent_proofs, "origins": origins,
                "recent_origins": recent_origins, "recipients_per_origin_and_winning_pool": recipients,
                "script_bytes": script_bytes, "body_bytes_per_origin": body_bytes,
                "noncoinbase_transactions_per_set": noncoinbase_transactions,
                "disjoint_noncoinbase_sets": transaction_sets if origins else 0,
                "unique_coinbases": unique_coinbases, "coinbase_script_sig_bytes": script_sig_bytes},
            "bytes": {"snapshot_lower": lower, "snapshot_upper": upper, "framing": framing,
                "proofs": proofs * (512 + script_bytes - 22), "recent_state": recent_proofs * 36,
                "certificates_with_count": certificate_bytes, "payout_outputs": output_bytes,
                "coinbase_per_origin_raw": coinbase_raw, "unique_coinbases_raw": unique_coinbases * coinbase_raw,
                "transaction_table_lower": table_lower, "transaction_table_upper": table_upper,
                "template_records_lower": record_lower, "template_records_upper": record_upper,
                "expanded_templates": origins * body_bytes},
            "transaction_references": references, "coinbase_reservation_weight": reservation,
            "predicates": checks,
            "encoded_size_bounds_do_not_prove_native_transaction_validity": True}


def v6_dependency_resources(root, parent, opening, *, extra_origins=0,
                            extra_dependency_bytes=0, depth=1, reserve_future_job=True):
    """Best-case forest: root/parent plus one distinct opening per direct origin.

    Certificates stop recursive revalidation but do not remove exact openings.
    Extra origins/bytes must be supplied for any additional dependency closure.
    The future job edge/origin reservation matches the local mining gate.
    """
    if any(type(v) is not int or v < 0 for v in (extra_origins, extra_dependency_bytes, depth)):
        raise ValueError("invalid dependency workload")
    origins = root["assumptions"]["origins"]
    counts = origins + extra_origins + int(reserve_future_job)
    lower = root["bytes"]["snapshot_lower"] + parent["bytes"]["snapshot_lower"] + origins * opening["bytes"]["snapshot_lower"] + extra_dependency_bytes
    upper = root["bytes"]["snapshot_upper"] + parent["bytes"]["snapshot_upper"] + origins * opening["bytes"]["snapshot_upper"] + extra_dependency_bytes
    return {"distinct_job_openings": origins, "extra_dependency_origins": extra_origins,
            "charged_origin_count_with_future_reservation": counts,
            "depth_with_future_reservation": depth + int(reserve_future_job),
            "closure_lower_bytes": lower, "closure_upper_bytes": upper,
            "empty_current_delta_job_opening_bytes": opening["bytes"]["snapshot_upper"],
            "mean_proofs_per_origin_required_by_declared_workload": root["assumptions"]["proofs"] / origins if origins else None,
            "predicates": {"origins_within_2048": counts <= 2048,
                "depth_within_64": depth + int(reserve_future_job) <= 64,
                "closure_lower_within_64MiB": lower <= 64 * 1024 * 1024,
                "closure_upper_within_64MiB": upper <= 64 * 1024 * 1024},
            "no_admission_or_availability_guarantee": True}


def v6_history_resources(k, snapshot_bytes, *, pool_fraction, admission_object_bytes=128,
                         script_bytes=22, oldest_cohort_proofs=0):
    """Cold full-snapshot scan versus retained target-pool query estimates.

    The default sizeof(Admission)=128 is a declared 64-bit layout estimate,
    not a portable sizeof measurement. Node budgets are per-thread local limits.
    """
    if (not math.isfinite(k) or k < 1 or not 0 < pool_fraction <= 1 or
            any(type(v) is not int or v < 0 for v in (snapshot_bytes, admission_object_bytes, oldest_cohort_proofs)) or
            script_bytes not in (22, 34)):
        raise ValueError("invalid history workload")
    window = math.ceil(8 * k)
    selected = window + oldest_cohort_proofs
    scans = math.ceil(8 / pool_fraction)
    per_entry = admission_object_bytes + script_bytes
    return {"pool_fraction": pool_fraction, "nominal_window_pool_proofs": window,
            "extra_retained_oldest_cohort_proofs": oldest_cohort_proofs,
            "mean_native_blocks_to_collect_window": 8 / pool_fraction,
            "rounded_mean_cold_snapshot_reads": scans,
            "cold_full_snapshot_bytes_at_that_scan_length": scans * snapshot_bytes,
            "approximate_global_admissions_examined": scans * k,
            "assumed_charged_bytes_per_admission": per_entry,
            "retained_one_pool_query_bytes": selected * per_entry,
            "query_bytes_within_default_64MiB": selected * per_entry <= 64 * 1024 * 1024,
            "minimum_64MiB_scan_budget_chunks_by_bytes": (scans * snapshot_bytes + 64 * 1024 * 1024 - 1) // (64 * 1024 * 1024),
            "minimum_65536_entry_scan_budget_chunks": math.ceil(scans * k / 65536),
            "history_limits_are_local_resumable_not_consensus": True,
            "query_budget_shared_by_up_to_16_cached_queries": True,
            "full_pool_index_or_payout_aggregate_optimization_not_assumed": True}


def v6_mean_origin_envelope(proofs, *, recipients=100, body_bytes=100_000,
                            noncoinbase_transactions=199):
    """Maximum declared mean jobs under upper byte bounds and optimistic leaves.

    All origins have distinct coinbases and share one non-coinbase transaction
    set; all opening dependencies are certified leaves repeating three cohorts.
    This is a diagnostic for the same stationary load, not an admission policy.
    """
    def allowed(origins, include_dependencies):
        root = v6_snapshot_resources(proofs=proofs, recent_proofs=4 * proofs,
            origins=origins, recent_origins=4 * origins, recipients=recipients,
            body_bytes=body_bytes, noncoinbase_transactions=noncoinbase_transactions)
        if not all(root["predicates"].values()):
            return False
        if not include_dependencies:
            return True
        opening = v6_snapshot_resources(proofs=0, recent_proofs=3 * proofs,
            origins=0, recent_origins=3 * origins, recipients=recipients)
        return all(v6_dependency_resources(root, root, opening)["predicates"].values())
    def maximum(include_dependencies):
        low, high = 0, 2048  # Reserve one origin for the next mining job.
        while low + 1 < high:
            mid = (low + high) // 2
            if allowed(mid, include_dependencies):
                low = mid
            else:
                high = mid
        return low
    before, after = maximum(False), maximum(True)
    return {"proofs_per_height": proofs, "recipients": recipients,
        "body_bytes": body_bytes, "transactions_per_origin": noncoinbase_transactions + 1,
        "shared_noncoinbase_sets": 1, "distinct_coinbases_per_origin": True,
        "maximum_origins_by_snapshot_expanded_references_and_future_origin_reservation": before,
        "maximum_origins_also_fitting_optimistic_dependency_forest": after,
        "minimum_average_proofs_per_origin_with_dependencies": proofs / after if after else None,
        "no_supported_statistical_or_burst_contract_established": True}


def resource_budget_report(bits=ILLUSTRATIVE_BITS):
    """Current-v6 resource diagnostics only; no statistical sweep or rule change."""
    k = float(shares_per_native(bits, 14))
    average = math.ceil(k)
    upper = 1 << 15
    loads = [("illustrative_mean", average, 4 * average),
             ("illustrative_single_interval_p99_prior_three_means", geometric_sum_quantile(k), 3 * average + geometric_sum_quantile(k)),
             ("shift14_upper_density_mean", upper, 4 * upper),
             ("shift14_upper_density_single_interval_p99_prior_three_means", geometric_sum_quantile(upper), 3 * upper + geometric_sum_quantile(upper))]
    cases = []
    # O=16 diagnoses the tight dependency-only mean envelope. O=100/1000
    # represent distinct jobs, not claims about mandatory miner identities.
    for name, proofs, recent in loads:
        historical_per_height = upper if name.startswith("shift14_upper") else average
        for origins, recipients, body, transactions, sets in (
                (16, 100, 100_000, 199, 1), (100, 100, 100_000, 199, 1),
                (100, 1000, 100_000, 199, 1), (1000, 1000, 100_000, 199, 1),
                (100, 100, 3_850_000, 199, 1), (1000, 100, 1_000_000, 7999, 1),
                (100, 100, 100_000, 199, 100)):
            settings = dict(origins=origins, recent_origins=4 * origins, recipients=recipients,
                            body_bytes=body, noncoinbase_transactions=transactions, transaction_sets=sets)
            root = v6_snapshot_resources(proofs=proofs, recent_proofs=recent, **settings)
            parent = v6_snapshot_resources(proofs=historical_per_height, recent_proofs=4 * historical_per_height, **settings)
            opening = v6_snapshot_resources(proofs=0, recent_proofs=3 * historical_per_height,
                origins=0, recent_origins=3 * origins, recipients=recipients)
            graph = v6_dependency_resources(root, parent, opening)
            lower_checks = [v for key, v in root["predicates"].items() if key not in ("snapshot_upper_bound_within_16MiB", "payout_reservation_within_RDTS_800000_WU")]
            lower_checks += [v for key, v in graph["predicates"].items() if key != "closure_upper_within_64MiB"]
            cases.append({"load": name, "root": root, "assumed_native_parent": parent,
                "minimum_current_delta_job_opening": opening, "dependency_forest": graph,
                "not_ruled_out_by_declared_4M_WU_necessary_bounds": all(lower_checks),
                "sufficient_for_production_or_native_admission": False})
    sample = next(c for c in cases if c["load"] == "illustrative_mean" and c["root"]["assumptions"]["origins"] == 100 and c["root"]["assumptions"]["recipients_per_origin_and_winning_pool"] == 100 and c["root"]["assumptions"]["body_bytes_per_origin"] == 100_000)
    history = [v6_history_resources(k, sample["root"]["bytes"]["snapshot_upper"], pool_fraction=q,
                oldest_cohort_proofs=math.ceil(q * k)) for q in (0.1, 0.01, 0.001)]
    output_limits = []
    for script in (22, 34):
        for weight in (4_000_000, 800_000):
            count = max(0, ((weight - 36) // 4 - 379) // (9 + script))
            output_limits.append({"script_bytes": script, "native_weight_limit": weight,
                "maximum_recipients_by_RPC_conservative_coinbase_only_reservation": count,
                "ordinary_transaction_capacity_reserved": False})
    return {"schema": 2, "kind": "Resource-only current-v6 bounds and local history costs; no new Monte Carlo",
        "native_bits_hex": f"{bits:08x}", "candidate_shift": 14, "native_shift_unchanged": 10,
        "illustrative_proofs_per_expected_native_block": k,
        "shift14_density_interval": {"inclusive_lower": 16384, "exclusive_upper": 32768},
        "single_interval_proofs_p99": geometric_sum_quantile(k),
        "four_interval_total_proofs_p99": geometric_sum_quantile(k, 4),
        "proof_plus_four_height_state_bytes_per_mean_proof": {"P2WPKH": 512 + 4 * 36, "P2TR": 524 + 4 * 36},
        "maximum_equal_per_height_proofs_by_proof_and_state_only_16MiB": {"P2WPKH": (16 * 1024 * 1024) // 656, "P2TR": (16 * 1024 * 1024) // 668},
        "workloads": cases, "history_estimates": history, "recipient_reservation_bounds": output_limits,
        "mean_origin_reuse_diagnostics": [v6_mean_origin_envelope(average, body_bytes=body,
                noncoinbase_transactions=transactions) for body, transactions in
                ((100_000, 199), (1_000_000, 1999), (3_850_000, 199))],
        "current_v6_SHIFT14_general_production_envelope_passes": False,
        "limits": [
            "Recent-state/certificate counts assume immediate admissions across four height cohorts; each load declares its state count. Backlog and older origins can change those counts.",
            "Every exact origin opening is charged even when certified. The diagnostic dependency forest omits additional recursive origins and thus gives optimistic lower bounds.",
            "An origin with no new share delta still includes inherited recent state and payout outputs. It does not represent a miner updating all newly received work every second.",
            "Native 4M/800k weight checks cover conservative coinbase reservation only. Body sizes and transaction counts are synthetic encoding workloads, not validated transactions or a simultaneous native-limit achievement.",
            "Unique coinbases are an explicit workload assumption, not implied solely by different header commitments. Shared transaction tables do not share identical byte prefixes of different coinbase transactions.",
            "Wire upper bounds assume declared body lengths, vector counts and sharing; they do not bound native validation CPU, heap overhead, disk latency or additional dependencies.",
            "A single-interval p99 with three prior means is a declared stress case, not a joint 99% guarantee. Unbounded Poisson/geometric tails and finite share age prevent unconditional admission guarantees.",
            "History estimates assume full network work is admitted and snapshot size held at the stated value. They are cold read/operation estimates, not measured disk throughput.",
            "The 2048-origin,512MiB-expanded,2M-reference,16MiB-snapshot and64MiB-dependency consensus limits and difficulty are unchanged.",
            "Prior statistical artifacts and source-hash manifests remain historical evidence; this resource-only artifact does not rewrite or rerun them."]}


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
    parser.add_argument("--resource-only", action="store_true", help="write corrected resource bounds without running simulations")
    parser.add_argument("--seed", type=int, default=20260919)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--measured-pool-blocks", type=float, default=24)
    parser.add_argument("--warmup-pool-blocks", type=float, default=16)
    parser.add_argument("--no-controls", action="store_true")
    args = parser.parse_args()
    result = resource_budget_report() if args.resource_only else report(
        replicas=args.replicas, seed=args.seed, workers=args.workers,
        measured=args.measured_pool_blocks, warmup=args.warmup_pool_blocks, controls=not args.no_controls)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
