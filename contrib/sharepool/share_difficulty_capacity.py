#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reproducible analytical capacity bounds, not a production target selection.

Only the Python standard library is required. Run without arguments for JSON,
or pass --output PATH to write the same deterministic report to a file.
"""

import argparse
import json
import math
from pathlib import Path


NATIVE_INTERVAL_SECONDS = 600
SECONDS_PER_DAY = 86_400
PROFILE_VERSION = 4
CURRENT_SHIFT = 10
COMPARISON_SHIFTS = (10, 14, 18)
POOL_FRACTIONS = (1, 0.1, 0.01, 0.001, 0.0001)
NOMINAL_INTERVALS = (1, 6, 144)
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024

# Share.header + Share.origin + Share.authorization. The shortest accepted
# payout script is 22 bytes (P2WPKH); its CompactSize prefix is one byte.
# Envelope: version, genesis, rules, height, native_parent, pool, owner,
#           payout script, and three reserved 32-byte fields.
MINIMAL_PROOF_LAYOUT = {
    "native_header": 164,
    "envelope_version": 1,
    "genesis": 32,
    "rules": 32,
    "origin_height": 4,
    "native_parent": 32,
    "pool": 32,
    "owner_public_key": 32,
    "payout_script_length": 1,
    "payout_script": 22,
    "reserved_fields": 96,
    "owner_signature": 64,
}
MINIMAL_PROOF_BYTES = sum(MINIMAL_PROOF_LAYOUT.values())


def scenario(shift, fraction, intervals):
    """Poisson statistics during fixed intervals * 600 seconds of wall time.

    lambda uses the idealized, unclamped 2**shift target ratio. Integer target
    rounding and the +1 in the exact hash success probability are neglected.
    """
    if type(shift) is not int or not 0 <= shift <= 32:
        raise ValueError("shift must be an integer in [0, 32]")
    if (not isinstance(fraction, (int, float)) or isinstance(fraction, bool) or
            not math.isfinite(fraction) or not 0 < fraction <= 1):
        raise ValueError("pool fraction must be finite and in (0, 1]")
    if type(intervals) is not int or intervals <= 0:
        raise ValueError("nominal intervals must be a positive integer")
    expected = (2 ** shift) * fraction * intervals
    rate = (2 ** shift) * fraction / NATIVE_INTERVAL_SECONDS
    return {
        "shift": shift,
        "pool_fraction": fraction,
        "nominal_intervals": intervals,
        "duration_seconds": intervals * NATIVE_INTERVAL_SECONDS,
        "expected_proofs": expected,
        "probability_zero_proofs": math.exp(-expected),
        "log_probability_zero_proofs": -expected,
        "relative_sampling_standard_deviation": 1 / math.sqrt(expected),
        "expected_proofs_per_second": rate,
        "expected_minimal_proof_bytes": expected * MINIMAL_PROOF_BYTES,
        "expected_minimal_proof_bytes_per_second": rate * MINIMAL_PROOF_BYTES,
        "expected_unique_proof_archive_bytes_per_day":
            rate * SECONDS_PER_DAY * MINIMAL_PROOF_BYTES,
    }


def illustrative_shift(fraction, intervals, relative_stddev=0.05, zero_probability=0.01):
    """Smallest idealized shift meeting both illustrative sampling objectives."""
    scenario(0, fraction, intervals)
    if (not math.isfinite(relative_stddev) or not 0 < relative_stddev <= 1 or
            not math.isfinite(zero_probability) or not 0 < zero_probability < 1):
        raise ValueError("sampling objectives must be finite probabilities in range")
    required_mean = max(relative_stddev ** -2, -math.log(zero_probability))
    ratio = required_mean / (fraction * intervals)
    return max(0, math.ceil(math.log2(ratio)))


def report():
    profiles = []
    for shift in COMPARISON_SHIFTS:
        item = scenario(shift, 1, 1)
        profiles.append({
            key: item[key] for key in (
                "shift", "expected_proofs", "expected_proofs_per_second",
                "expected_minimal_proof_bytes", "expected_minimal_proof_bytes_per_second",
                "expected_unique_proof_archive_bytes_per_day")
        })
    objectives = []
    for fraction in POOL_FRACTIONS:
        for intervals in (1, 144):
            shift = illustrative_shift(fraction, intervals)
            objectives.append({
                "pool_fraction": fraction,
                "nominal_intervals": intervals,
                "maximum_relative_sampling_standard_deviation": 0.05,
                "maximum_zero_probability": 0.01,
                "minimum_idealized_shift": shift,
                "whole_network_minimal_proof_archive_bytes_per_day":
                    scenario(shift, 1, 1)["expected_unique_proof_archive_bytes_per_day"],
            })
    return {
        "model": "fixed-duration Poisson sampling; analytical, no miner or GPU execution",
        "profile_version": PROFILE_VERSION,
        "current_experimental_target_shift": CURRENT_SHIFT,
        "nominal_native_interval_seconds": NATIVE_INTERVAL_SECONDS,
        "assumptions": [
            "Independent uniform proof-of-work trials; constant network and pool hashrates.",
            "Native target remains constant and 2**shift scaling is not clamped.",
            "The idealized share/native success ratio is 2**shift; integer rounding is neglected.",
            "An interval means 600 fixed wall-clock seconds, not a random observed block count.",
            "All discovered proofs are available and recorded exactly once; no stales, losses or withholding.",
            "Unique proof archival excludes all template, state, database, network and redundancy overhead.",
            "exp(-lambda) may underflow to numeric zero; log probability retains the model result.",
        ],
        "minimal_proof_layout_bytes": MINIMAL_PROOF_LAYOUT,
        "minimal_proof_bytes": MINIMAL_PROOF_BYTES,
        "snapshot_byte_limit": MAX_SNAPSHOT_BYTES,
        "proof_only_snapshot_upper_bound_ignoring_all_other_fields":
            MAX_SNAPSHOT_BYTES // MINIMAL_PROOF_BYTES,
        "profiles": profiles,
        "scenarios": [scenario(shift, fraction, intervals)
                      for shift in COMPARISON_SHIFTS
                      for fraction in POOL_FRACTIONS
                      for intervals in NOMINAL_INTERVALS],
        "illustrative_objectives_not_production_requirements": objectives,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args()
    raw = json.dumps(report(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(raw, end="")
    else:
        args.output.write_text(raw, encoding="utf-8")


if __name__ == "__main__":
    main()
