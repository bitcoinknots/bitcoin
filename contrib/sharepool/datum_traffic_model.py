#!/usr/bin/env python3
"""Payload-only traffic planning from measured encoder sizes and DATUM cadence.

This is an analytical workload model, not a node capacity benchmark or a live
template relay. A gateway produces one transaction-template stream regardless of
the number of ASIC clients using extranonces on it. See doc/sharepool-datum-traffic.md.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path


ENCODER_SAMPLE = Path(__file__).resolve().parent / "results/datum-traffic-encoder.json"


def _positive(value, name, *, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive finite number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or value <= 0 or (integer and not isinstance(value, int)):
        raise ValueError(f"{name} must be a positive {'integer' if integer else 'finite number'}")
    return value


def read_sample(path=ENCODER_SAMPLE):
    raw = Path(path).read_bytes()
    value = json.loads(raw)
    rows = {row["jobs"]: row for row in value["rows"]}
    one, batch = rows[1], rows[100]
    for row in (one, batch):
        for key in ("snapshot_bytes", "expanded_template_bytes"):
            _positive(row[key], key, integer=True)
        if row["recipients_per_job"] != 100 or not row["all_noncoinbase_transactions_exactly_shared"]:
            raise ValueError("model requires the measured 100-recipient, shared-transaction fixture")
    if batch["expanded_template_bytes"] != 100 * one["expanded_template_bytes"]:
        raise ValueError("expanded template samples disagree")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source": value["source"],
        "full_template_bytes": one["expanded_template_bytes"],
        "one_job_snapshot_bytes": one["snapshot_bytes"],
        "batch_jobs": 100,
        "batch_snapshot_bytes": batch["snapshot_bytes"],
        "recipients_per_job": 100,
        "proof_records_per_job": 1,
    }


def _traffic(payload_per_refresh, refreshes, duration):
    _positive(payload_per_refresh, "payload_per_refresh", integer=True)
    received = payload_per_refresh * refreshes
    _positive(received, "received_payload_bytes")
    mean_mbps = received / duration * (8 / 1e6)
    _positive(mean_mbps, "mean_inbound_Mbps")
    return {"payload_bytes_per_refresh_wave": payload_per_refresh,
            "received_payload_bytes": received,
            "received_payload_GB": received / 1e9,
            "mean_inbound_Mbps": mean_mbps}


def estimate(*, gateways=100, miners_per_gateway=1, refresh_seconds=40,
             block_interval_seconds=600, duration_seconds=86400,
             illustrative_submissions_per_minute_per_miner=8, sample=None):
    """Estimate one received copy; miner counts do not multiply gateway jobs.

    A Poisson block arrival resets the template timer. The steady-state refresh
    rate is 1/E[min(Exp(lambda), T)] = lambda/(1-exp(-lambda*T)). The additive
    1/T + lambda figure is a conservative long-run planning allowance, not the
    exact finite-duration expected count from a cold start or a worst-case bound.
    """
    _positive(gateways, "gateways", integer=True)
    _positive(miners_per_gateway, "miners_per_gateway", integer=True)
    _positive(refresh_seconds, "refresh_seconds")
    if not 5 <= refresh_seconds <= 120:
        raise ValueError("refresh_seconds must be between 5 and 120")
    _positive(block_interval_seconds, "block_interval_seconds")
    _positive(duration_seconds, "duration_seconds")
    _positive(illustrative_submissions_per_minute_per_miner,
              "illustrative_submissions_per_minute_per_miner")
    sample = read_sample() if sample is None else sample
    batch_count, residual = divmod(gateways, sample["batch_jobs"])
    shared_payload = (batch_count * sample["batch_snapshot_bytes"]
                      + residual * sample["one_job_snapshot_bytes"])
    full_payload = gateways * sample["full_template_bytes"]
    block_rate = 1 / block_interval_seconds
    _positive(block_rate, "block_rate")
    renewal_rate = block_rate / -math.expm1(-block_rate * refresh_seconds)
    additive_rate = 1 / refresh_seconds + block_rate
    plans = {}
    for name, rate in (("steady_state_expected", renewal_rate),
                       ("conservative_additive_allowance", additive_rate)):
        refreshes = rate * duration_seconds
        changed_jobs = gateways * rate
        _positive(refreshes, "refreshes_per_gateway")
        _positive(changed_jobs, "changed_jobs_per_second")
        plans[name] = {
            "refreshes_per_gateway": refreshes,
            "changed_jobs_per_second": changed_jobs,
            "separate_full_templates": _traffic(full_payload, refreshes, duration_seconds),
            "optimistic_shared_batches": _traffic(shared_payload, refreshes, duration_seconds),
        }
    total_miners = gateways * miners_per_gateway
    _positive(total_miners, "total_miners", integer=True)
    submissions = total_miners * (illustrative_submissions_per_minute_per_miner / 60) * duration_seconds
    _positive(submissions, "illustrative_submissions")
    return {
        "gateways": gateways,
        "miners_per_gateway": miners_per_gateway,
        "total_miners": total_miners,
        "refresh_seconds": refresh_seconds,
        "block_interval_seconds": block_interval_seconds,
        "duration_seconds": duration_seconds,
        "expected_network_blocks": block_rate * duration_seconds,
        "batching": {"full_100_job_batches": batch_count,
                     "residual_jobs_costed_as_separate_one_job_snapshots": residual},
        "illustrative_submissions": {
            "per_minute_per_miner": illustrative_submissions_per_minute_per_miner,
            "total_count": submissions,
            "changes_active_share_difficulty": False,
            "included_in_payload_estimate": False,
            "note": "Hypothetical client submission cadence; not active SHIFT10 proof arrivals. "
                    "Payload fixture contains only one proof record per job.",
        },
        "plans": plans,
    }


def report(*, gateways=100, miners_per_gateway=1, refresh_seconds=40,
           block_interval_seconds=600, duration_seconds=86400,
           illustrative_submissions_per_minute_per_miner=8):
    sample = read_sample()
    options = dict(gateways=gateways, miners_per_gateway=miners_per_gateway,
                   refresh_seconds=refresh_seconds, block_interval_seconds=block_interval_seconds,
                   duration_seconds=duration_seconds,
                   illustrative_submissions_per_minute_per_miner=illustrative_submissions_per_minute_per_miner)
    return {
        "scope": "Analytical payload projection using preserved encoder measurements; "
                 "not live traffic, throughput, validation, retention or mainnet activation evidence.",
        "measurement": sample,
        "limitations": [
            "All noncoinbase transactions shared; 100 recipients and one synthetic proof record per job.",
            "100-job batching is optimistic across independently refreshed gateways; no cross-version deltas.",
            "Residual gateways are conservatively charged using measured one-job snapshots.",
            "Excludes dependencies/history, extra share records, protocol framing, request duplication and outbound relay.",
            "Poisson average block interval is a scenario, not a hard arrival bound; additive allowance counts timer resets twice.",
            "Refreshing local jobs does not mean every unworked job is relayed by the current evidence protocol.",
            "No CPU, RAM, disk retention or sustained capacity minimum follows from these payload bytes.",
        ],
        "selected_scenario": estimate(sample=sample, **options),
        "default_comparisons": [estimate(gateways=g, miners_per_gateway=m, sample=sample)
                                for g, m in ((1, 100), (100, 1), (100, 10), (1000, 1))],
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateways", type=int, default=100)
    parser.add_argument("--miners-per-gateway", type=int, default=1)
    parser.add_argument("--refresh-seconds", type=float, default=40)
    parser.add_argument("--block-interval-seconds", type=float, default=600)
    parser.add_argument("--duration-seconds", type=float, default=86400)
    parser.add_argument("--illustrative-submissions-per-minute-per-miner", type=float, default=8)
    parser.add_argument("--output", type=Path)
    args = vars(parser.parse_args())
    output = args.pop("output")
    try:
        result = report(**args)
    except ValueError as error:
        parser.error(str(error))
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        print(encoded, end="")
    else:
        output.write_text(encoded)


if __name__ == "__main__":
    main()
