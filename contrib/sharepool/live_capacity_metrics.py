#!/usr/bin/env python3
"""Measured-phase accounting for the finite live native capacity fixture."""
import math
from collections import defaultdict

from capacity_metrics import distribution


def owner_slots(*, miners, planned, workers, owner):
    """Partition the original absolute schedule without moving an identity.

    One worker serially owns each assigned gateway for its entire lifetime.
    Selecting one worker per miner removes coupling between gateway schedules;
    fewer workers intentionally retain coupling within each reported shard.
    """
    if (type(miners) is not int or not 2 <= miners <= 100 or
            type(planned) is not int or not miners <= planned <= 10000 or
            type(workers) is not int or not 1 <= workers <= miners or
            type(owner) is not int or not 0 <= owner < workers):
        raise ValueError("invalid bounded source ownership")
    return (slot for slot in range(planned) if (slot % miners) % workers == owner)


def merge_measurements(measurements):
    """Merge completed owner samples, never averages of their percentiles.

    Call only after every owner has stopped: Measurements is owner-local and
    deliberately has no shared hot-path lock. Intervals may overlap in time.
    """
    values, failures = defaultdict(list), defaultdict(int)
    for measurement in measurements:
        for name, samples in measurement.values.items():
            values[name].extend(samples)
            failures[name] += measurement.failures[name]
    return {name: dict(distribution(samples), failures=failures[name])
            for name, samples in sorted(values.items())}


def phase_counts(events, *, seconds):
    """Count completed events at the fixed cutoff, never credit later draining.

    Events contain unique proof IDs. Native admission and peer confirmation can
    contain several IDs but must follow local durable acknowledgement/admission.
    Rejected offers never become acknowledgements. This is measurement accounting,
    not proof validation or a prediction of maximum sustainable service rate.
    """
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("phase duration must be positive and finite")
    stages = {name: set() for name in ("offered", "acknowledged", "admitted", "peer_verified", "rejected", "admission_refused")}
    previous = {"acknowledged": "offered", "admitted": "acknowledged", "peer_verified": "admitted",
                "rejected": "offered", "admission_refused": "offered"}
    refused, offered_slots = set(), set()
    ordered = sorted(events, key=lambda event: event["seconds"])
    for event in ordered:
        when, stage = event["seconds"], event["stage"]
        if stage == "capacity_refused":
            slot, miner, identity = event.get("slot"), event.get("miner"), event.get("identity")
            if (type(when) not in (int, float) or not math.isfinite(when) or when < 0 or
                    type(slot) is not int or not 0 <= slot < 10000 or
                    type(miner) is not int or not 0 <= miner < 100 or
                    type(identity) is not str or len(identity) != 64 or
                    any(char not in "0123456789abcdef" for char in identity) or
                    "proof_ids" in event):
                raise ValueError("invalid pre-dispatch capacity refusal")
            if when <= seconds:
                if slot in refused or slot in offered_slots:
                    raise ValueError("duplicate scheduled capacity refusal")
                refused.add(slot)
            continue
        identities = event["proof_ids"]
        if (type(when) not in (int, float) or not math.isfinite(when) or when < 0 or
                stage not in stages or type(identities) not in (list, tuple) or
                any(type(identity) is not str or len(identity) != 64 or
                    any(char not in "0123456789abcdef" for char in identity) for identity in identities)):
            raise ValueError("invalid live capacity event")
        if when > seconds:
            continue
        if stage == "offered" and "slot" in event:
            slot = event["slot"]
            if type(slot) is not int or not 0 <= slot < 10000 or slot in refused or slot in offered_slots:
                raise ValueError("scheduled work cannot be offered twice or after refusal")
            offered_slots.add(slot)
        ids = set(identities)
        if len(ids) != len(identities) or ids & stages[stage]:
            raise ValueError("duplicate stage completion")
        if stage in previous and not ids <= stages[previous[stage]]:
            raise ValueError("capacity event precedes required stage")
        outcomes = ("acknowledged", "rejected", "admission_refused")
        if stage in outcomes and any(ids & stages[other] for other in outcomes if other != stage):
            raise ValueError("offer cannot have conflicting acknowledgement/refusal outcomes")
        stages[stage].update(ids)
    counts = {name: len(ids) for name, ids in stages.items()}
    return dict(counts, seconds=seconds, capacity_refused=len(refused),
        unacknowledged_queue=counts["offered"] - counts["acknowledged"] - counts["rejected"] - counts["admission_refused"],
        acknowledged_backlog=counts["acknowledged"] - counts["admitted"],
        peer_backlog=counts["admitted"] - counts["peer_verified"],
        observed_admitted_per_second=counts["admitted"] / seconds,
        observed_peer_verified_per_second=counts["peer_verified"] / seconds)
