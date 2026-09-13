#!/usr/bin/env python3
"""CPU/wall comparison of exact-prefix state reuse on synthetic signed jobs.

Run with PYTHONPATH=contrib/sharepool:test/functional. Both modes use the same
runtime code and fixtures; only state_cache=None versus CompactStateCache differs.
This benchmark excludes fixture creation and native validation, networking,
disk/archive reads and proof-of-work verification. It is not mining throughput.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import time
from unittest.mock import patch

import hash_snapshot as codec
from hash_state_cache import CompactStateCache
from test_hash_compact import compact_fixture


def workload(jobs=100, shares_per_block=100):
    chain, historical = {}, []
    previous = None
    for height in range(1, 4):
        options = {"height": height, "parent_snapshot": previous}
        if previous is not None:
            options["native_parent"] = native_parent
        origin, opening = compact_fixture(**options)
        proofs, nonce = [], 0
        for _ in range(shares_per_block):
            proof = codec.solve_share(origin, opening, start_nonce=nonce)
            proofs.append(proof)
            nonce = proof.header.nNonce + 1
        block, previous = compact_fixture(templates=(origin,), shares=tuple(proofs), **options)
        native_parent = block.sha256
        chain[native_parent] = previous
        historical.append(previous)
    targets = []
    for index in range(jobs):
        _, target = compact_fixture(height=4, native_parent=native_parent, parent_snapshot=previous,
            pool=1000 + index, ntime=1700001000 + index)
        targets.append(target)
    return tuple(targets), chain, tuple(historical)


def result_fingerprint(value):
    return (value.history_head,
            tuple((entry.origin_height, entry.proof_id) for entry in value.post_state),
            tuple((cert.origin_height, cert.native_parent, cert.identity, cert.snapshot_hash)
                  for cert in value.certificates))


def sweep(targets, chain, enabled):
    cache = CompactStateCache() if enabled else None
    reads, observed, results = [], [], []
    def parent(identity, height):
        reads.append((identity, height))
        value = chain[identity]
        if value.envelope.height != height:
            raise AssertionError("changed native ancestry binding")
        return value
    def observer(value, raw):
        observed.append((value.envelope.height, raw))
    wall, cpu = time.perf_counter(), time.process_time()
    for target in targets:
        results.append(codec.materialize_compact_state(target, parent_snapshot=parent,
            on_snapshot=observer, state_cache=cache))
    timing = {"cpu_seconds": time.process_time() - cpu, "wall_seconds": time.perf_counter() - wall}
    # All equality and digest work below is outside the measured interval.
    values = tuple(result_fingerprint(value) for value in results)
    if len(reads) != len(targets) * 3 or len(observed) != len(targets) * 4:
        raise AssertionError("materializer skipped ancestry reads or resource observers")
    callback_digest = hashlib.sha256()
    for height, raw in observed:
        callback_digest.update(height.to_bytes(4, "little"))
        callback_digest.update(len(raw).to_bytes(8, "little"))
        callback_digest.update(raw)
    metadata = {"ancestry_callbacks": len(reads), "snapshot_observers": len(observed),
                "observed_bytes": sum(len(raw) for _, raw in observed),
                "callback_sha256": callback_digest.hexdigest(),
                "cache": cache.stats() if cache is not None else None}
    return timing, values, tuple(reads), metadata


def benchmark(output, jobs=100, shares_per_block=100, repeats=3):
    targets, chain, historical = workload(jobs, shares_per_block)
    raw_targets = tuple(value.serialize() for value in targets)
    if len(set(raw_targets)) != jobs:
        raise AssertionError("target jobs must be distinct")
    fixtures_digest = hashlib.sha256()
    for raw in tuple(value.serialize() for value in historical) + raw_targets:
        fixtures_digest.update(len(raw).to_bytes(8, "little"))
        fixtures_digest.update(raw)
    modes = {"disabled": {"samples": []}, "enabled": {"samples": []}}
    expected = None
    for repeat in range(repeats):
        # Alternate ordering to avoid assigning all first-run effects to one
        # mode. Every sweep starts with a new cache, never a warmed target memo.
        for enabled in ((False, True) if repeat % 2 == 0 else (True, False)):
            timing, values, reads, metadata = sweep(targets, chain, enabled)
            current = values, reads, metadata["callback_sha256"], metadata["observed_bytes"]
            if expected is None:
                expected = current
            elif current != expected:
                raise AssertionError("derived heads/state/certificates or callback evidence changed")
            modes["enabled" if enabled else "disabled"]["samples"].append({"repeat": repeat + 1, **timing})
    # Instrumentation is a separate sweep: mock overhead does not affect the
    # reported CPU/wall samples. Results and callback bytes are still compared.
    for enabled in (False, True):
        with patch.object(codec, "apply_tides_state", wraps=codec.apply_tides_state) as apply, \
                patch.object(codec, "verify_schnorr", wraps=codec.verify_schnorr) as verify:
            _, values, reads, metadata = sweep(targets, chain, enabled)
        if (values, reads, metadata["callback_sha256"], metadata["observed_bytes"]) != expected:
            raise AssertionError("instrumented materialization changed the result")
        required_calls = jobs + 3 if enabled else jobs * 4
        if (apply.call_count, verify.call_count) != (required_calls, required_calls):
            raise AssertionError("unexpected deterministic prefix replay count")
        mode = modes["enabled" if enabled else "disabled"]
        mode["instrumentation"] = {"separate_from_timing": True, "apply_tides_state_calls": apply.call_count,
            "verify_schnorr_calls": verify.call_count, **metadata}
        mode["median_cpu_seconds"] = statistics.median(sample["cpu_seconds"] for sample in mode["samples"])
        mode["median_wall_seconds"] = statistics.median(sample["wall_seconds"] for sample in mode["samples"])
    sources = ("hash_snapshot.py", "hash_state_cache.py", "benchmark_hash_state.py")
    report = {
        "scope": "Synthetic signed state replay, capture and resource callbacks; excludes native validation, networking, archive I/O, PoW verification and fixture creation",
        "clock_sources": {"cpu": "time.process_time", "wall": "time.perf_counter"},
        "python": platform.python_version(), "platform": platform.platform(), "repeats": repeats,
        "workload": {"distinct_jobs": jobs, "target_height": 4, "native_history_snapshots": 3,
                     "shares_per_history_snapshot": shares_per_block, "total_history_shares": 3 * shares_per_block,
                     "new_shares_per_target": 0, "fixtures_sha256": fixtures_digest.hexdigest()},
        "same_runtime_only_cache_argument_differs": True, "fresh_cache_per_sweep": True,
        "all_derived_heads_states_certificates_equal": True, "all_ancestry_and_observer_evidence_equal": True,
        "source_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in sources},
        "modes": modes,
        "cpu_speedup_ratio": modes["disabled"]["median_cpu_seconds"] / modes["enabled"]["median_cpu_seconds"],
        "wall_speedup_ratio": modes["disabled"]["median_wall_seconds"] / modes["enabled"]["median_wall_seconds"],
    }
    Path(output).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--jobs", type=int, default=100)
    parser.add_argument("--shares-per-block", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not (1 <= args.jobs <= 100 and 1 <= args.shares_per_block <= 100 and 1 <= args.repeats <= 3):
        parser.error("bounded benchmark requires jobs/shares 1..100 and repeats 1..3")
    benchmark(args.output, args.jobs, args.shares_per_block, args.repeats)
