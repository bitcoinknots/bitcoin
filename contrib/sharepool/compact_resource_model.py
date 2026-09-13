#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Declared v7 wire/closure comparisons; no activation or throughput claim.

Reuses the historical v6 workload geometry unchanged. The transaction table
still deduplicates complete transactions, so different coinbases repeat their
full output lists. V7 changes job/proof encoding and derives recent state; it
does not change physical recipient limits or guarantee acknowledged admission.
"""

import argparse
import hashlib
import json
from pathlib import Path

from tides_service_contract import compact_size_length as cs, v6_snapshot_resources

MIB = 1024 * 1024
MAX_PROOFS = 32768
MAX_DEPENDENCY_PROOFS = 131072


def job_proof_bytes(proofs, template_count, *, jobs=None):
    """Exact dictionary/proof index costs for explicitly balanced job counts.

    Used jobs occupy the first J canonical template indexes. Each gets P//J
    proofs, and the first P%J jobs get one more. Proof-ID sorting does not
    change these byte counts. Dictionary envelope/signature bytes are separate.
    """
    if jobs is None:
        jobs = min(proofs, template_count)
    if any(type(n) is not int or n < 0 for n in (proofs, template_count, jobs)):
        raise ValueError("nonnegative integer proof/template/job counts required")
    if jobs > min(proofs, template_count) or bool(proofs) != bool(jobs):
        raise ValueError("each compact proof requires a used dictionary job")
    # This analytic domain is bounded independently of native admission flags.
    if jobs > 65536:
        raise ValueError("model supports at most 65536 job indexes")
    quotient, extra = divmod(proofs, jobs) if jobs else (0, 0)
    descriptor_indexes = sum(cs(i) for i in range(jobs))
    proof_indexes = sum((quotient + (i < extra)) * cs(i) for i in range(jobs))
    return {"jobs": jobs, "descriptor_index_bytes": descriptor_indexes,
            "proof_index_bytes": proof_indexes, "proof_payload_bytes": 32 * proofs + proof_indexes,
            "proof_payload_33_byte_records": sum(quotient + (i < extra) for i in range(min(jobs, 253))),
            "proof_payload_35_byte_records": sum(quotient + (i < extra) for i in range(253, jobs)),
            "balanced_counts_by_canonical_job_index": True}


def v7_snapshot_resources(*, proofs, origins, recipients, recent_proofs=0, recent_origins=0,
                          script_bytes=22, body_bytes=100_000, noncoinbase_transactions=199,
                          transaction_sets=1, unique_coinbases=None, script_sig_bytes=100, jobs=None):
    """Same declared transaction geometry as v6, exact v7 dictionary framing.

    Lower/upper bounds concern unspecified transaction vector sizes/indexes.
    The dictionary/proof byte counts are exact under job_proof_bytes' declared
    distribution. Passing these bounds is not native validity or a service SLA.
    """
    old = v6_snapshot_resources(proofs=proofs, recent_proofs=recent_proofs, origins=origins,
        recent_origins=recent_origins, recipients=recipients, script_bytes=script_bytes,
        body_bytes=body_bytes, noncoinbase_transactions=noncoinbase_transactions,
        transaction_sets=transaction_sets, unique_coinbases=unique_coinbases,
        script_sig_bytes=script_sig_bytes)
    compact = job_proof_bytes(proofs, origins, jobs=jobs)
    used_jobs = compact["jobs"]
    # Envelope(284/296) + signature64 once per used exact signed job.
    descriptor_bytes = used_jobs * (348 + script_bytes - 22) + compact["descriptor_index_bytes"]
    frame = old["bytes"]["framing"] - cs(recent_proofs) - cs(recent_origins) + cs(used_jobs)
    removed = old["bytes"]["proofs"] + 36 * recent_proofs + 100 * recent_origins
    change = frame - old["bytes"]["framing"] - removed + descriptor_bytes + compact["proof_payload_bytes"]
    lower, upper = old["bytes"]["snapshot_lower"] + change, old["bytes"]["snapshot_upper"] + change
    predicates = dict(old["predicates"])
    predicates.update(snapshot_lower_bound_within_16MiB=lower <= 16 * MIB,
                      snapshot_upper_bound_within_16MiB=upper <= 16 * MIB,
                      compact_proofs_within_32768=proofs <= MAX_PROOFS,
                      derived_state_count_within_preserved_bound=recent_proofs <= 16 * MIB // 36)
    return {"assumptions": old["assumptions"] | {"used_signed_jobs": used_jobs,
                "balanced_proofs_per_job": True, "used_template_indexes_are_first_canonical_indexes": True},
            "bytes": old["bytes"] | {"snapshot_lower": lower, "snapshot_upper": upper,
                "framing": frame, "proofs": compact["proof_payload_bytes"],
                "job_descriptors_without_count": descriptor_bytes,
                "job_table_with_count": cs(used_jobs) + descriptor_bytes,
                "recent_state": 0, "certificates_with_count": 0},
            "compact_records": compact,
            "derived_state_and_certificates_omitted_from_wire_not_from_validation": True,
            "transaction_references": old["transaction_references"],
            "coinbase_reservation_weight": old["coinbase_reservation_weight"],
            "predicates": predicates, "sufficient_for_native_admission": False}


def closure_resources(root, native, opening, *, prior_native_snapshots=4, extra_origins=0,
                      additional_bytes=0, additional_proofs=0, lower_bound_only=False):
    """Declared distinct dependency graph, including exact signed job openings.

    Four prior native snapshots cover current parent materialization. Aged,
    uncertified origins can extend that suffix; caller specifies its length.
    Additional recursive origins/dependencies must be declared, never silently
    assumed free. Payout-history scanning is a separate local resumable cost.
    """
    values = (prior_native_snapshots, extra_origins, additional_bytes, additional_proofs)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("invalid dependency count")
    count = root["assumptions"]["origins"]
    sizes = {bound: root["bytes"][f"snapshot_{bound}"] +
            prior_native_snapshots * native["bytes"][f"snapshot_{bound}"] +
            count * opening["bytes"][f"snapshot_{bound}"] + additional_bytes
            for bound in ("lower", "upper")}
    proofs = root["assumptions"]["proofs"] + prior_native_snapshots * native["assumptions"]["proofs"] + count * opening["assumptions"]["proofs"] + additional_proofs
    origins = count + extra_origins + 1 # Future issued-job origin reservation.
    return {"prior_native_snapshots": prior_native_snapshots, "distinct_exact_job_openings": count,
            "charged_raw_proof_instances": proofs, "charged_origins_with_future_reservation": origins,
            "closure_lower_bytes": sizes["lower"], "closure_upper_bytes": sizes["upper"],
            "depth_with_future_reservation_for_declared_leaf_forest": 2,
            "lower_bound_only_due_to_omitted_recursive_dependencies": lower_bound_only,
            "predicates": {"raw_proof_instances_within_131072": proofs <= MAX_DEPENDENCY_PROOFS,
                "origins_within_2048": origins <= 2048,
                "closure_lower_within_64MiB": sizes["lower"] <= 64 * MIB,
                "closure_upper_within_64MiB": sizes["upper"] <= 64 * MIB},
            "additional_payout_history_reads_are_local_resumable_work": True,
            "sufficient_for_native_admission": False}


def _convert(row):
    args = row["assumptions"]
    return v7_snapshot_resources(proofs=args["proofs"], recent_proofs=args["recent_proofs"],
        origins=args["origins"], recent_origins=args["recent_origins"],
        recipients=args["recipients_per_origin_and_winning_pool"], script_bytes=args["script_bytes"],
        body_bytes=args["body_bytes_per_origin"], noncoinbase_transactions=args["noncoinbase_transactions_per_set"],
        transaction_sets=max(1, args["disjoint_noncoinbase_sets"]), unique_coinbases=args["unique_coinbases"],
        script_sig_bytes=args["coinbase_script_sig_bytes"])


def report(historical_path=None):
    historical_path = historical_path or Path(__file__).with_name("results") / "tides-v6-resource-budget.json"
    raw = historical_path.read_bytes()
    historical = json.loads(raw)
    rows = []
    for old in historical["workloads"]:
        root, parent = _convert(old["root"]), _convert(old["assumed_native_parent"])
        opening = _convert(old["minimum_current_delta_job_opening"])
        certified = closure_resources(root, parent, opening)
        aged = closure_resources(root, parent, opening, prior_native_snapshots=7)
        # Each distinct job copies the same still-unadmitted acknowledged delta. Those
        # proof IDs are not new work merely because several jobs repeat them.
        # Older origin dependencies needed to support the repeated delta add
        # further costs, so this is explicitly a lower-bound stress case.
        repeated = closure_resources(root, parent, parent, extra_origins=parent["assumptions"]["origins"], lower_bound_only=True)
        rows.append({"load": old["load"], "v6_root_snapshot_bounds_bytes": {
                bound: old["root"]["bytes"][f"snapshot_{bound}"] for bound in ("lower", "upper")},
            "v6_historical_optimistic_dependency_bounds_bytes": {
                bound: old["dependency_forest"][f"closure_{bound}_bytes"] for bound in ("lower", "upper")},
            "v7_root": root, "assumed_prior_native_snapshot": parent,
            "exact_empty_current_delta_job_opening": opening,
            "certified_leaf_or_fresh_empty_job_closure": certified,
            "uncertified_age3_child_free_job_closure": aged,
            "repeated_prior_current_delta_in_each_job_lower_bound_stress": repeated,
            "root_upper_byte_reduction_fraction": 1 - root["bytes"]["snapshot_upper"] / old["root"]["bytes"]["snapshot_upper"],
            "ordinary_weight_necessary_bounds_fit_for_certified_leaf_assumption": all(
                value for name, value in root["predicates"].items() if name != "payout_reservation_within_RDTS_800000_WU") and all(certified["predicates"].values()),
            "production_capacity_or_variance_contract_established": False})
    return {"schema": 1, "kind": "v7 declared serialization/closure model; not a native performance measurement",
        "historical_v6_input": {"file": historical_path.name, "sha256": hashlib.sha256(raw).hexdigest()},
        "native_bits_hex": historical["native_bits_hex"], "illustrative_candidate_shift": 14,
        "active_native_shift_unchanged": 10,
        "illustrative_proofs_per_expected_native_block": historical["illustrative_proofs_per_expected_native_block"],
        "single_interval_proofs_p99": historical["single_interval_proofs_p99"],
        "workloads": rows, "recipient_reservation_bounds_unchanged": historical["recipient_reservation_bounds"],
        "limitations": [
            "Job counts identify exact templates, not exclusive physical miners or addresses.",
            "Each distinct coinbase still contains every actual payout output. Only whole transactions are shared in the table.",
            "Compact proof records are 33 bytes for job indexes 0..252 and 35 bytes for 253..65535. The declared balanced distribution fixes their counts.",
            "The optimistic certified/fresh graph includes root+four prior native snapshots and one exact empty-current-delta opening per direct job. It does not silently reuse one opening for different signed jobs.",
            "Uncertified age-three, child-free jobs can need seven prior native snapshots. Further recursive jobs, data retention and validation time require additional budgets and tests.",
            "Repeated-current-delta stress models the same still-unadmitted acknowledged delta in every distinct opening; these are duplicate validation bytes, not newly credited work. Its omitted child openings make totals lower bounds.",
            "Derived recent state/certificates remain verified and bounded. Small wire payloads do not imply small validation, heap or archive cost.",
            "The 32768-proof snapshot and 131072-proof dependency bounds preserve precompression work ceilings. Bursts may exceed them despite fitting compact bytes.",
            "PoW, signatures, scripts, fees, actual payouts, backlog survival and native validity are not established by these synthetic serialization models.",
            "SHIFT14 remains illustrative and inactive. Historical variance artifacts were read unchanged; no statistical simulation was rerun."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(report(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
