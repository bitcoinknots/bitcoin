#!/usr/bin/env python3
"""Measured-phase accounting for the finite live native capacity fixture."""
import math


def phase_counts(events, *, seconds):
    """Count completed events at the fixed cutoff, never credit later draining.

    Events contain unique proof IDs. Native admission and peer confirmation can
    contain several IDs but must follow local durable acknowledgement/admission.
    Rejected offers never become acknowledgements. This is measurement accounting,
    not proof validation or a prediction of maximum sustainable service rate.
    """
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("phase duration must be positive and finite")
    stages = {name: set() for name in ("offered", "acknowledged", "admitted", "peer_verified", "rejected")}
    previous = {"acknowledged": "offered", "admitted": "acknowledged", "peer_verified": "admitted", "rejected": "offered"}
    ordered = sorted(events, key=lambda event: event["seconds"])
    for event in ordered:
        when, stage, identities = event["seconds"], event["stage"], event["proof_ids"]
        if (type(when) not in (int, float) or not math.isfinite(when) or when < 0 or
                stage not in stages or type(identities) not in (list, tuple) or
                any(type(identity) is not str or len(identity) != 64 or
                    any(char not in "0123456789abcdef" for char in identity) for identity in identities)):
            raise ValueError("invalid live capacity event")
        if when > seconds:
            continue
        ids = set(identities)
        if len(ids) != len(identities) or ids & stages[stage]:
            raise ValueError("duplicate stage completion")
        if stage in previous and not ids <= stages[previous[stage]]:
            raise ValueError("capacity event precedes required stage")
        if stage == "acknowledged" and ids & stages["rejected"] or stage == "rejected" and ids & stages["acknowledged"]:
            raise ValueError("offer cannot be both rejected and acknowledged")
        stages[stage].update(ids)
    counts = {name: len(ids) for name, ids in stages.items()}
    return dict(counts, seconds=seconds,
        unacknowledged_queue=counts["offered"] - counts["acknowledged"] - counts["rejected"],
        acknowledged_backlog=counts["acknowledged"] - counts["admitted"],
        peer_backlog=counts["admitted"] - counts["peer_verified"],
        observed_admitted_per_second=counts["admitted"] / seconds,
        observed_peer_verified_per_second=counts["peer_verified"] / seconds)
