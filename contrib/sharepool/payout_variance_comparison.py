#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Conditional payout statistics and explicit benchmarks, not production forecasts.

Standard library only. No miner, GPU, node or random simulation is involved.
Window positions are supplied to the covariance model; their actual distribution
at block discovery, and its dependence on job issuance, are not simulated.
"""

import argparse
import json
import math
from pathlib import Path

from share_difficulty_capacity import CURRENT_SHIFT, MINIMAL_PROOF_BYTES, NATIVE_INTERVAL_SECONDS


BASELINE_SOURCES = {
    "direct_coinbase_rolling_work_window": "https://ocean.xyz/docs/tides",
    "fpps_accounting": "https://docs.luxor.tech/platform/mining/revenue-payments",
}
MINER_FRACTIONS = (0.1, 0.01, 0.0001)
DOMAIN_FRACTIONS = (1, 0.1, 0.01, 0.001, 0.0001)


def fraction(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or not 0 < value <= 1):
        raise ValueError("fraction must be finite and in (0, 1]")
    return value


def positive_count(value):
    if type(value) is not int or value <= 0:
        raise ValueError("count must be a positive integer")
    return value


def fixed_window(miner_fraction, proof_count):
    """X/N for X~Binomial(N,a), conditional on a miner-neutral equal-work window."""
    a, n = fraction(miner_fraction), positive_count(proof_count)
    variance = a * (1 - a) / n
    return {
        "miner_fraction_of_domain": a,
        "equal_work_proofs": n,
        "expected_payout_fraction": a,
        "payout_fraction_variance": variance,
        "relative_allocation_standard_deviation": math.sqrt(variance) / a,
        "probability_miner_absent": math.exp(n * math.log1p(-a)) if a < 1 else 0,
    }


def overlapping_windows(miner_fraction, proof_count, cutoffs):
    """Exact conditional covariance for IID owner labels at specified cutoffs.

    A window contains integer proof positions [cutoff-N, cutoff). Each payout
    distributes one fixed reward unit. This conditions on block count and window
    positions; it does not predict unconditional payout variance over wall time.
    """
    a, n = fraction(miner_fraction), positive_count(proof_count)
    cutoffs = tuple(cutoffs)
    if (not 1 <= len(cutoffs) <= 144 or any(type(x) is not int or x < n for x in cutoffs) or
            tuple(sorted(cutoffs)) != cutoffs):
        raise ValueError("provide 1..144 nondecreasing integer cutoffs at least N")
    b = len(cutoffs)
    overlap = sum(max(0, n - (cutoffs[j] - cutoffs[i]))
                  for i in range(b) for j in range(i + 1, b))
    multiplicity_squared = b * n + 2 * overlap
    variance = a * (1 - a) * multiplicity_squared / (n * n)
    return {
        "miner_fraction_of_domain": a,
        "equal_work_proofs_per_window": n,
        "fixed_reward_count": b,
        "cutoffs_in_proof_positions": cutoffs,
        "total_pairwise_shared_proofs": overlap,
        "expected_total_reward_units": a * b,
        "total_reward_units_variance_conditional_on_cutoffs": variance,
        "relative_standard_deviation_conditional_on_cutoffs": math.sqrt(variance) / (a * b),
        "effective_proofs_for_average_allocation": (b * n) ** 2 / multiplicity_squared,
    }


def block_luck_and_ideal_pps(domain_fraction, miner_fraction, intervals, shift=CURRENT_SHIFT):
    """Separate fixed-split block-luck and fixed-price-per-proof benchmarks.

    Rewards, target and hashrates stay constant; trials are Poisson. PPS is an
    ideal solvent credit obligation at 1/2**shift reward units per proof. Actual
    fees, contract defaults, payment timing and operator reserves are excluded.
    """
    q, a, b = fraction(domain_fraction), fraction(miner_fraction), positive_count(intervals)
    if type(shift) is not int or not 0 <= shift <= 32:
        raise ValueError("shift must be an integer in [0, 32]")
    blocks = q * b
    miner_proofs = a * blocks * 2 ** shift
    mean = a * blocks
    return {
        "domain_fraction_of_network": q,
        "miner_fraction_of_domain": a,
        "duration_seconds": b * NATIVE_INTERVAL_SECONDS,
        "expected_domain_blocks": blocks,
        "expected_miner_proofs": miner_proofs,
        "expected_reward_units_both_benchmarks": mean,
        "ideal_fixed_split_block_luck_variance": a * a * blocks,
        "ideal_fixed_split_block_luck_relative_standard_deviation": 1 / math.sqrt(blocks),
        "ideal_fixed_rate_pps_credit_variance": miner_proofs / (2 ** shift) ** 2,
        "ideal_fixed_rate_pps_credit_relative_standard_deviation": 1 / math.sqrt(miner_proofs),
    }


def age_opportunities(domain_fraction, already_winning_proof=False, maximum_age=3):
    """Optimistic chance of a matching-domain block within eligible heights.

    q is the hashrate actually mining this settlement domain, not necessarily a
    business pool's reported hashrate. Job cutoff, relay and queue delays can
    remove opportunities. A proof is never included in its own winning block.
    """
    q = fraction(domain_fraction)
    if type(maximum_age) is not int or maximum_age < 0:
        raise ValueError("maximum age must be a nonnegative integer")
    opportunities = maximum_age + (0 if already_winning_proof else 1)
    failure = (1 - q) ** opportunities
    success = -math.expm1(opportunities * math.log1p(-q)) if q < 1 else int(opportunities > 0)
    return {
        "effective_domain_fraction_of_network": q,
        "already_winning_proof": already_winning_proof,
        "maximum_origin_age_in_network_heights": maximum_age,
        "optimistic_matching_block_opportunities": opportunities,
        "probability_at_least_one_matching_block": success,
        "probability_no_matching_block": failure,
    }


def fixed_time_empty_window(domain_fraction, miner_fraction, intervals=4):
    """Empty-batch illustration for a window chosen independently of block finds.

    This is not the current protocol's stopped, expiring, one-time batch law.
    Fixed owner attribution is an extra assumption used to expose zero handling.
    """
    q, a, b = fraction(domain_fraction), fraction(miner_fraction), positive_count(intervals)
    mean = q * b * 2 ** CURRENT_SHIFT
    empty = math.exp(-mean)
    return {
        "domain_fraction_of_network": q,
        "miner_fraction_of_domain": a,
        "fixed_duration_seconds": b * NATIVE_INTERVAL_SECONDS,
        "expected_total_domain_proofs": mean,
        "probability_empty_domain_window": empty,
        "expected_payout_fraction_if_miner_is_not_fallback_owner": a * (1 - empty),
        "expected_payout_fraction_if_miner_is_always_fallback_owner": a * (1 - empty) + empty,
        "scope": "Independent fixed-time proxy only; excludes actual block stopping, previous settlement and self-proof rules.",
    }


def comparison_report():
    k = 2 ** CURRENT_SHIFT
    return {
        "profile_version": 4,
        "experimental_share_target_shift": CURRENT_SHIFT,
        "sources": BASELINE_SOURCES,
        "claim": "Conditional comparisons only; current v4 payout-variance equivalence is not established.",
        "notation": {
            "a": "individual miner fraction of the settlement domain's steady hashrate",
            "q": "fraction of network hashrate actually mining that settlement domain",
            "N": "equal-work proofs in a specific payout window",
            "b": "fixed 600-second wall-time intervals, not an observed random block count",
        },
        "limits": [
            "Equal share difficulty; unclamped 2**shift target ratio; independent uniform hash trials.",
            "Owner labels are IID and independent of the specified window cutoffs; no miner-selective omissions.",
            "Constant block reward and hashrates; no satoshi rounding, payout minimums, stales, latency or reorgs.",
            "Actual native block successes are a subset of proof successes; no independent block/share simulation is asserted.",
            "Fixed-window and overlap formulas condition on window membership, not actual block-discovery stopping times.",
            "Fixed-split block luck and PPS credits are separate benchmarks, not terms added into a forecast.",
            "Current v4 proof counts per settlement are variable; fixed N examples are not measurements of those batches.",
            "Current v4 pays the owner when the selected proof set is empty; conditional nonempty allocation statistics omit that policy bias.",
            "Durable carry-forward preserves evidence but does not extend the current consensus age or permit repeated payment.",
        ],
        "conditional_single_payout_cases": [fixed_window(a, n)
                                            for a in MINER_FRACTIONS for n in (64, k, 8 * k)],
        "conditional_multiple_payout_cases": [
            {"model": name, **overlapping_windows(a, n, ends)}
            for a in MINER_FRACTIONS
            for name, n, ends in (
                ("disjoint_same_size_windows", 8 * k, [(i + 1) * 8 * k for i in range(8)]),
                ("overlapping_eight_work_unit_windows", 8 * k, [8 * k + i * k for i in range(8)]),
                ("disjoint_one_work_unit_windows", k, [(i + 1) * k for i in range(8)]),
            )],
        "same_hashrate_block_luck_and_pps_benchmarks": [
            block_luck_and_ideal_pps(q, a, b)
            for q in DOMAIN_FRACTIONS for a in MINER_FRACTIONS for b in (1, 144)],
        "current_age_eligibility_upper_bounds": [age_opportunities(q, winning)
                                                  for q in DOMAIN_FRACTIONS for winning in (False, True)],
        "empty_window_fixed_time_proxies_not_actual_batch_distribution": [
            fixed_time_empty_window(q, 0.01) for q in (0.01, 0.001, 0.0001)],
        "rolling_eight_work_unit_window": {
            "equal_work_proofs_at_shift10": 8 * k,
            "minimum_proof_bytes_excluding_all_other_data": 8 * k * MINIMAL_PROOF_BYTES,
            "expected_fill_seconds_by_domain_fraction": [
                {"q": q, "seconds": 8 * NATIVE_INTERVAL_SECONDS / q} for q in DOMAIN_FRACTIONS],
        },
        "design_decisions_needed": [
            "Select the reference contract: a direct-coinbase rolling-work pool or operator-funded PPS/FPPS credits.",
            "For a rolling-work baseline, define an authenticated work-window ledger and permit repeated participation in distinct block rewards.",
            "Separate duplicate proof submission and duplicate settlement protection from legitimate reuse across rolling payouts.",
            "Replace the short native-height payment expiry with the chosen work-window eligibility, preserving acknowledged deferred work.",
            "Specify deterministic job cutoff and ordered work-window updates, including difficulty changes, reorgs and late receipts.",
            "Match miner-level effective sample counts and window weights under the same aggregate hashrate, target and payout horizon.",
            "Validate payout variance and mean on coupled block/share traces; retain covariance and block-finding dependence.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(comparison_report(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(raw, end="")
    else:
        args.output.write_text(raw, encoding="utf-8")


if __name__ == "__main__":
    main()
