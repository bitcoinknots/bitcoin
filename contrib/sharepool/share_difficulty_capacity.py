#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reproducible analytical capacity bounds, not a production target selection.

Only the Python standard library is required. Run without arguments for JSON,
or pass --output PATH to write the same deterministic report to a file.
"""

import argparse
import hashlib
import json
import math
from pathlib import Path

from live_capacity_metrics import phase_counts
from tides_calibration import (ILLUSTRATIVE_BITS, assigned_work, native_target,
                               shares_per_native)


NATIVE_INTERVAL_SECONDS = 600
SECONDS_PER_DAY = 86_400
PROFILE_VERSION = 4
CURRENT_SHIFT = 10
COMPARISON_SHIFTS = (10, 14, 18)
POOL_FRACTIONS = (1, 0.1, 0.01, 0.001, 0.0001)
NOMINAL_INTERVALS = (1, 6, 144)
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
V7_MAX_COMPACT_SHARES = MAX_SNAPSHOT_BYTES // 512

# ReserveCoinbasePayouts in src/sharepool/mining_budget.h. This is the local
# constructor's conservative reservation, not an exact consensus output cap.
COINBASE_RESERVATION_OVERHEAD = 164 + 9 + 4 + 1 + 36 + 1 + 100 + 4 + 9 + 47 + 4
COINBASE_WITNESS_BYTES = 36

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


def _number(value, name, *, minimum=0, maximum=1e15, positive=False, integer=False):
    if (type(value) not in ((int,) if integer else (int, float)) or
            not minimum <= value <= maximum or (positive and value == 0)):
        raise ValueError(f"invalid {name}")
    # Comparison above rejects NaN and bounds huge integers before isfinite.
    return value


def payout_capacity(recipients, *, script_bytes=22, non_payout_weight=0, reduced_data=False):
    """Conservative construction screen, including space left for transactions.

    The zero-transaction ceiling must not be advertised as a supported pool
    size. Snapshot, dependency, sigop and validation budgets remain separate.
    """
    _number(recipients, "recipient count", integer=True, maximum=1_000_000)
    if script_bytes not in (22, 34) or type(script_bytes) is not int or type(reduced_data) is not bool:
        raise ValueError("supported witness script and contextual RDTS flag required")
    limit = 800_000 if reduced_data else 4_000_000
    _number(non_payout_weight, "non-payout weight", integer=True, maximum=4_000_000)
    output_size = 8 + 1 + script_bytes
    overhead = 4 * COINBASE_RESERVATION_OVERHEAD + COINBASE_WITNESS_BYTES
    room = max(0, limit - non_payout_weight - overhead)
    reservation = overhead + recipients * output_size * 4
    return {
        "recipients": recipients, "script_bytes": script_bytes,
        "serialized_payout_output_bytes": recipients * output_size,
        "reserved_header_and_coinbase_weight": reservation,
        "declared_non_payout_weight": non_payout_weight,
        "contextual_weight_limit": limit,
        "maximum_recipients_by_this_reservation_only": room // (4 * output_size),
        "fits_declared_weight_budget": reservation + non_payout_weight <= limit,
        "sufficient_for_native_admission": False,
    }


def finite_capacity_evidence(value):
    """Reconcile the native finite-epoch fixture without calling it sustained.

    Nested RPC timers overlap their callers and are deliberately not summed.
    Count/time is an achieved rate in this exact workload, not a maximum rate.
    Diagnostic resource flags do not substitute for native/peer acceptance.
    """
    if (value.get("schema") != 1 or value.get("result") != "passed" or
            value.get("profile") != "hash-only-v7-compact-tides" or
            value.get("network") != "isolated native regtest" or
            value.get("opaque_proof_fixtures") != 0 or value.get("native_nodes", 0) < 2 or
            value.get("payout_oracle_verified") is not True or
            value.get("peer_recovery_verified") is not True):
        raise ValueError("verified v7 native capacity evidence required")
    count_names = ("offered", "acknowledged", "admitted", "peer_verified_admitted", "expired",
                   "unresolved_receipts", "final_backlog", "current_acknowledged_backlog",
                   "peer_verification_backlog")
    counts = {name: _number(value[name], name, integer=True) for name in count_names}
    seconds = _number(value["seconds"], "capture duration", positive=True)
    if not counts["offered"] >= counts["acknowledged"] >= counts["admitted"] >= counts["peer_verified_admitted"] > 0:
        raise ValueError("capacity count order is inconsistent")
    epochs, rewards = value["epochs"], value["rewards"]
    if not epochs or not rewards:
        raise ValueError("epoch and native payout evidence required")
    blocks = [block for epoch in epochs for block in epoch["blocks"]]
    if (len({block["hash"] for block in blocks}) != len(blocks) or
            any(block.get("native_accepted") is not True or block.get("peer_ready") is not True for block in blocks)):
        raise ValueError("unique accepted and peer-verified blocks required")
    for name in ("offered", "acknowledged", "admitted"):
        if sum(_number(e[name], name, integer=True) for e in epochs) != counts[name]:
            raise ValueError(f"epoch {name} count does not reconcile")
    if sum(_number(block["admitted"], "block admissions", integer=True) for block in blocks) != counts["admitted"]:
        raise ValueError("native block admissions do not reconcile")
    reward_by_height = {item["height"]: item for item in rewards}
    if len(reward_by_height) != len(blocks) or len(rewards) != len(blocks):
        raise ValueError("one payout oracle result per admission block required")
    for block in blocks:
        reward = reward_by_height.get(block["height"], {})
        if (reward.get("new_admissions") != block["admitted"] or
                reward.get("exact_rational_window_and_coinbase_verified") is not True or
                reward.get("whole_admission_height_cohorts_verified") is not True):
            raise ValueError("native payout oracle does not match admissions")
    miners = _number(value["configuration"]["miners"], "fixture miners", integer=True, positive=True)
    epoch_rates = []
    for epoch in epochs:
        duration = _number(epoch["seconds"], "epoch seconds", positive=True)
        ingress = _number(epoch["admission_seconds"], "ingress seconds", positive=True)
        preparation = _number(epoch["origin_preparation_seconds"], "origin preparation seconds")
        if ingress + preparation > duration + 0.001:
            raise ValueError("epoch stage durations exceed the containing interval")
        epoch_rates.append({"epoch": epoch["epoch"], "seconds": duration,
            "native_admissions_per_elapsed_second": epoch["admitted"] / duration,
            "acknowledgements_per_ingress_second": epoch["acknowledged"] / ingress,
            "origin_preparation_seconds": preparation})
    if sum(item["seconds"] for item in epoch_rates) > seconds + 0.001:
        raise ValueError("epoch durations exceed complete capture")
    return {
        "kind": "finite_native_bursts_with_controlled_settlement_and_drain",
        "sustained_capacity_qualified": False,
        "duration_seconds": seconds, "counts": counts, "miners": miners,
        "native_blocks": len(blocks),
        "maximum_verified_payout_recipients_in_one_block": max(
            _number(item["payout_scripts"], "verified recipients", integer=True) for item in rewards),
        "observed_native_admissions_per_elapsed_second": counts["admitted"] / seconds,
        "observed_peer_verified_admissions_per_elapsed_second": counts["peer_verified_admitted"] / seconds,
        "per_epoch": epoch_rates,
        "final_receipts_drained_without_loss": (counts["offered"] == counts["acknowledged"] ==
            counts["admitted"] == counts["peer_verified_admitted"] and
            all(counts[name] == 0 for name in count_names[4:])),
        "configuration": value["configuration"],
        "limitations": value["limitations"],
    }


def live_capacity_evidence(value):
    """Recompute a fixed live phase from proof events, excluding later drain.

    A finite continuously offered experiment still cannot establish long-run
    stability. Its source scheduling queue is part of offered-load coverage.
    """
    if (value.get("schema") != 1 or value.get("result") != "passed" or
            value.get("profile") != "hash-only-v7-compact-tides" or
            value.get("network") != "isolated native regtest" or
            value.get("native_nodes", 0) < 2 or value.get("cleanup_error") or
            value.get("payout_oracle_verified") is not True or value.get("peer_verified") is not True):
        raise ValueError("verified v7 live native capacity evidence required")
    duration = _number(value["configuration"]["duration_seconds"], "fixed phase seconds", positive=True)
    elapsed = _number(value["live_and_drain_seconds"], "live and drain seconds", minimum=duration)
    phase = phase_counts(value["events"], seconds=duration)
    completed = phase_counts(value["events"], seconds=elapsed)
    for actual, name in ((phase, "measured_phase"), (completed, "completed_run")):
        if any(value[name].get(key) != item for key, item in actual.items()):
            raise ValueError(f"{name} counters or rates disagree with timestamped events")
    planned = _number(value["scheduled_requests"], "scheduled requests", integer=True, positive=True)
    unfulfilled = planned - phase["offered"]
    if (unfulfilled < 0 or value["measured_phase"].get("scheduled_requests_due") != planned or
            value["measured_phase"].get("source_unfulfilled_requests") != unfulfilled or
            completed["offered"] != planned):
        raise ValueError("source scheduling coverage does not reconcile")
    expired = _number(value["expired_acknowledged"], "expired acknowledged proofs", integer=True)
    if expired or any(completed[name] for name in ("unacknowledged_queue", "acknowledged_backlog", "peer_backlog")):
        raise ValueError("completed live capture lost acknowledged work or retains unresolved queues")
    if completed["rejected"] != value["rejected_before_ack"]:
        raise ValueError("rejected live offers do not reconcile")
    blocks, rewards = value["blocks"], value["rewards"]
    if (not blocks or len({block["hash"] for block in blocks}) != len(blocks) or
            any(block.get("native_accepted") is not True or block.get("peer_ready") is not True for block in blocks) or
            sum(_number(block["admitted"], "block admissions", integer=True) for block in blocks) != completed["admitted"]):
        raise ValueError("accepted native and peer-verified blocks do not match live admissions")
    reward_by_height = {row["height"]: row for row in rewards}
    if len(reward_by_height) != len(blocks) or len(rewards) != len(blocks):
        raise ValueError("one live payout oracle per block required")
    phase_blocks = []
    for block in blocks:
        reward = reward_by_height.get(block["height"], {})
        recipients = _number(block["payout_recipients"], "verified live recipients", integer=True)
        if (reward.get("new_admissions") != block["admitted"] or reward.get("payout_scripts") != recipients or
                reward.get("exact_rational_window_and_coinbase_verified") is not True or
                reward.get("whole_admission_height_cohorts_verified") is not True):
            raise ValueError("live payout oracle disagrees with its native block")
        local = _number(block["local_seconds"], "local acceptance time", maximum=elapsed)
        peer = _number(block["peer_seconds"], "peer acceptance time", minimum=local, maximum=elapsed)
        weight = _number(block["native_weight"], "native block weight", integer=True, positive=True, maximum=4_000_000)
        _number(block["coinbase_weight"], "coinbase weight", integer=True, positive=True, maximum=weight)
        if peer <= duration:
            phase_blocks.append(block)
    miners = _number(value["configuration"]["miners"], "live miners", integer=True, positive=True)
    return {"kind": "finite_continuously_scheduled_native_phase_then_explicit_drain",
        "sustained_capacity_qualified": False, "duration_seconds": duration,
        "live_and_drain_seconds": elapsed, "counts": phase, "completed_run_counts": completed,
        "scheduled_requests": planned, "source_unfulfilled_requests_at_cutoff": unfulfilled,
        "fixed_phase_all_scheduled_work_confirmed": phase["peer_verified"] == planned,
        "miners": miners, "native_blocks": len(blocks),
        "maximum_verified_payout_recipients_in_one_block": max(block["payout_recipients"] for block in blocks),
        "maximum_phase_verified_payout_recipients_in_one_block": max(
            (block["payout_recipients"] for block in phase_blocks), default=0),
        "maximum_verified_coinbase_weight": max(block["coinbase_weight"] for block in blocks),
        "maximum_verified_native_weight": max(block["native_weight"] for block in blocks),
        "maximum_phase_verified_coinbase_weight": max((block["coinbase_weight"] for block in phase_blocks), default=0),
        "maximum_phase_verified_native_weight": max((block["native_weight"] for block in phase_blocks), default=0),
        "observed_native_admissions_per_elapsed_second": phase["observed_admitted_per_second"],
        "observed_peer_verified_admissions_per_elapsed_second": phase["observed_peer_verified_per_second"],
        "final_receipts_drained_without_loss": True,
        "all_offers_acknowledged_without_rejection": completed["rejected"] == 0,
        "configuration": value["configuration"], "limitations": value["limitations"]}


def production_capacity_report(evidence, *, pool_fraction=1 / 144, miners=100,
        native_bits=ILLUSTRATIVE_BITS, observation_seconds=SECONDS_PER_DAY,
        reference_share_seconds=(10, 30, 60), monitored_network_fraction=1,
        required_rate_headroom=2, script_bytes=22, non_payout_weight=0):
    """Measured-workload screens plus explicit, constant-hashrate scenarios.

    Reference cadences are user inputs, never claims about a commercial pool.
    Poisson count variance cannot establish rolling-window payout variance.
    """
    _number(pool_fraction, "pool fraction", minimum=1e-12, maximum=1)
    _number(monitored_network_fraction, "monitored network fraction", minimum=1e-12, maximum=1)
    if monitored_network_fraction < pool_fraction:
        raise ValueError("monitored fraction must include the scenario pool")
    _number(miners, "equal miners", integer=True, positive=True, maximum=1_000_000)
    _number(observation_seconds, "observation seconds", minimum=1e-6, maximum=SECONDS_PER_DAY * 365)
    _number(required_rate_headroom, "rate headroom", minimum=1, maximum=1000)
    native_target(native_bits)
    if not reference_share_seconds or len(reference_share_seconds) > 32:
        raise ValueError("one to 32 explicit reference cadences required")
    for cadence in reference_share_seconds:
        _number(cadence, "reference share interval", minimum=1e-6, maximum=SECONDS_PER_DAY * 365)
    observed = (live_capacity_evidence(evidence) if "measured_phase" in evidence
                else finite_capacity_evidence(evidence))
    rate = observed["observed_peer_verified_admissions_per_elapsed_second"]
    def rate_screen(demand):
        needed = demand * required_rate_headroom
        return {"required_proofs_per_second": demand, "required_rate_with_headroom": needed,
            "required_over_observed_rate": needed / rate if rate else None,
            "not_exceeding_observed_workload_rate": needed <= rate,
            "expected_admissions_per_nominal_native_interval": demand * NATIVE_INTERVAL_SECONDS,
            "v7_maximum_compact_shares_per_block": V7_MAX_COMPACT_SHARES,
            "expected_proof_arrivals_per_day": demand * SECONDS_PER_DAY,
            "v7_maximum_mean_admissions_per_day_at_600_second_blocks":
                V7_MAX_COMPACT_SHARES * (SECONDS_PER_DAY // NATIVE_INTERVAL_SECONDS),
            "mean_load_exceeds_v7_count_ceiling": demand * NATIVE_INTERVAL_SECONDS > V7_MAX_COMPACT_SHARES,
            "sustainable_capacity_established": False}
    current = []
    for shift in (10, 12, 14):
        k = shares_per_native(native_bits, shift)
        network_rate = float(k) / NATIVE_INTERVAL_SECONDS
        per_miner = network_rate * pool_fraction / miners
        mean = per_miner * observation_seconds
        current.append({"shift": shift, "active": shift == CURRENT_SHIFT,
            "assigned_expected_hash_work": str(assigned_work(native_bits, shift)),
            "exact_shares_per_native_block": [str(k.numerator), str(k.denominator)],
            "network_proofs_per_second": network_rate,
            "pool_proofs_per_second": network_rate * pool_fraction,
            "mean_seconds_per_equal_miner_share": 1 / per_miner,
            "expected_proofs_per_miner_in_observation": mean,
            "proof_count_relative_standard_deviation": 1 / math.sqrt(mean),
            "probability_zero_proofs_per_miner": math.exp(-mean),
            "log_probability_zero_proofs_per_miner": -mean,
            "monitored_rate_screen": rate_screen(network_rate * monitored_network_fraction)})
    references = []
    for cadence in reference_share_seconds:
        pool_rate = miners / cadence
        network_rate = pool_rate / pool_fraction
        candidate_shift = next((shift for shift in range(256) if
            float(shares_per_native(native_bits, shift)) / NATIVE_INTERVAL_SECONDS >= network_rate), None)
        candidate_rate = (float(shares_per_native(native_bits, candidate_shift)) / NATIVE_INTERVAL_SECONDS
                          if candidate_shift is not None else None)
        count_mean = observation_seconds / cadence
        references.append({"declared_seconds_per_equal_miner_share": cadence,
            "expected_proofs_per_miner_in_observation": count_mean,
            "proof_count_relative_standard_deviation": 1 / math.sqrt(count_mean),
            "requested_pool_proofs_per_second": pool_rate,
            "implied_network_proofs_per_second_at_one_global_target": network_rate,
            "minimum_analytical_shift_meeting_this_cadence": candidate_shift,
            "candidate_network_proofs_per_second": candidate_rate,
            "candidate_monitored_rate_screen": (rate_screen(candidate_rate * monitored_network_fraction)
                                                if candidate_rate is not None else None),
            "candidate_v7_compact_proof_component_bytes_per_day_lower_bound": (
                candidate_rate * monitored_network_fraction * SECONDS_PER_DAY * 33
                if candidate_rate is not None else None),
            "reference_cadence_is_not_a_production_requirement": True})
    payout = [payout_capacity(miners, script_bytes=script_bytes,
        non_payout_weight=non_payout_weight, reduced_data=reduced) for reduced in (False, True)]
    return {"schema": 1, "result": "production_capacity_not_established",
        "consensus_parameters_changed": False, "current_profile_version": 7,
        "scenario_inputs": {"native_bits_hex": f"{native_bits:08x}", "pool_fraction": pool_fraction,
            "equal_hashrate_miners_and_payout_recipients": miners,
            "expected_pool_round_seconds": NATIVE_INTERVAL_SECONDS / pool_fraction,
            "observation_seconds": observation_seconds,
            "monitored_network_fraction": monitored_network_fraction,
            "required_rate_headroom": required_rate_headroom},
        "native_evidence": observed, "global_difficulty_scenarios": current,
        "declared_reference_cadences": references, "direct_payout_weight_screens": payout,
        "recipient_count_exceeds_native_fixture_coverage": miners >
            observed["maximum_verified_payout_recipients_in_one_block"],
        "recipient_count_exceeds_measured_phase_coverage": (
            miners > observed["maximum_phase_verified_payout_recipients_in_one_block"]
            if "maximum_phase_verified_payout_recipients_in_one_block" in observed else None),
        "payout_variance_equivalence_established": False,
        "minimum_seconds_per_equal_miner_share_at_observed_rate_screen":
            miners * monitored_network_fraction / pool_fraction * required_rate_headroom / rate if rate else None,
        "limitations": [
            "The finite capture's achieved rate is not a sustained rate, saturation maximum or impossibility bound; live phase rates exclude later drain.",
            "Observed proof counts have a different target, transaction geometry, churn and block timing from this scenario.",
            "Count sampling RSD excludes block luck, overlapping TIDES windows, cutoff, admission, expiry and payout rounding.",
            "The explicit native target and reference cadences are analytical inputs, not live network measurements or a regular-pool standard.",
            "A global share target implies traffic outside the example pool; monitored_network_fraction declares this scope.",
            "The 33-byte compact proof component omits shared job descriptors, templates, transactions, snapshots, relaying and archive overhead.",
            "V7 still admits at most 32768 proofs per block; shrinking wire records did not raise this verification-work ceiling. Mean load below it proves no burst headroom.",
            "A direct-payout weight screen does not establish simultaneous native recipient coverage or snapshot/validation capacity.",
        ],
        "remaining_gates": ["continuous arrivals during construction and settlement with bounded queues",
            "admission and peer verification before expiry, including recovery under continued arrivals",
            "native exact payouts at the declared simultaneous recipient count and transaction weight",
            "admission-aware paired payout variance against a specified pool contract",
            "WAN, resource exhaustion, long-duration retention and independent consensus review"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    parser.add_argument("--capacity-evidence", type=Path, help="screen v7 scenarios against a recorded native capacity JSON")
    parser.add_argument("--pool-fraction", type=float, default=1 / 144)
    parser.add_argument("--miners", type=int, default=100)
    parser.add_argument("--native-bits", type=lambda value: int(value, 16), default=ILLUSTRATIVE_BITS)
    parser.add_argument("--reference-share-seconds", type=float, nargs="+", default=(10, 30, 60))
    parser.add_argument("--monitored-network-fraction", type=float, default=1)
    parser.add_argument("--required-rate-headroom", type=float, default=2)
    parser.add_argument("--observation-seconds", type=float, default=SECONDS_PER_DAY)
    parser.add_argument("--payout-script-bytes", type=int, choices=(22, 34), default=22)
    parser.add_argument("--non-payout-weight", type=int, default=0)
    args = parser.parse_args()
    result = report()
    if args.capacity_evidence is not None:
        raw_evidence = args.capacity_evidence.read_bytes()
        result = production_capacity_report(json.loads(raw_evidence), pool_fraction=args.pool_fraction,
            miners=args.miners, native_bits=args.native_bits,
            reference_share_seconds=args.reference_share_seconds,
            monitored_network_fraction=args.monitored_network_fraction,
            required_rate_headroom=args.required_rate_headroom,
            observation_seconds=args.observation_seconds, script_bytes=args.payout_script_bytes,
            non_payout_weight=args.non_payout_weight)
        result["evidence_artifact"] = {"path": str(args.capacity_evidence),
            "sha256": hashlib.sha256(raw_evidence).hexdigest()}
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(raw, end="")
    else:
        args.output.write_text(raw, encoding="utf-8")


if __name__ == "__main__":
    main()
