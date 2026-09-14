#!/usr/bin/env python3
"""Finite same-evidence archive verification/rollover comparison.

Supply the pre-change hash_mining_gate.py as --baseline-source. Only its three
archive methods are compiled; no top-level code in that file is executed.
This measures local archive I/O and canonical authentication, not native mining.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
from types import MethodType
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))
from capacity_metrics import distribution
import hash_mining_gate
from hash_mining_gate import HashMiningGate, PROOF
from hash_snapshot import solve_share
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


def baseline_methods(source):
    parsed = ast.parse(source)
    container = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "HashMiningGate")
    names = {"_verify_store", "rotate_archive", "export_archive"}
    selected = [node for node in container.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != names:
        raise ValueError("baseline source must contain the three original archive methods")
    namespace = dict(vars(hash_mining_gate))
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<baseline archive methods>", "exec"), namespace)
    return {name: namespace[name] for name in names}


def measure(gate, function, cold_path):
    # Drop only bounded derived metadata, just as a new gate instance starts.
    for name, value in vars(gate).items():
        if name.endswith("_cache") and hasattr(value, "clear"):
            value.clear()
    original_open, original_read = os.open, gate._read
    counts = {"cold_file_opens": 0, "point_evidence_reads": 0}

    def opened(path, *args, **kwargs):
        if Path(path) == cold_path:
            counts["cold_file_opens"] += 1
        return original_open(path, *args, **kwargs)

    def read(*args, **kwargs):
        counts["point_evidence_reads"] += 1
        return original_read(*args, **kwargs)

    gate._read = read
    try:
        with patch.object(os, "open", opened):
            started, cpu = time.monotonic(), time.process_time()
            function()
            counts.update(wall_seconds=time.monotonic() - started, cpu_seconds=time.process_time() - cpu)
    finally:
        gate._read = original_read
    return counts


def run_case(directory, count, methods, repeats):
    origin, opening = fixture()
    proofs, nonce = [], 0
    for _ in range(count):
        proof = solve_share(origin, opening, start_nonce=nonce)
        nonce = proof.header.nNonce + 1
        proofs.append(proof)
    result = {"receipts": count, "modes": {}}
    head = None
    for mode in ("legacy", "streaming"):
        rpc = FakeRPC()
        gate = HashMiningGate(directory / f"{mode}-{count}.sqlite", rpc=rpc,
            pool=3, public_key=opening.envelope.public_key, payout_script=SCRIPT)
        rpc.gate = gate
        try:
            gate.register_snapshot(opening.serialize())
            gate.register_template(origin.serialize())
            # Exact valid PoW proof bodies, one common valid canonical origin.
            # Fixture admission is outside measurement and bypasses RPC so this
            # remains an archive benchmark, with no native-validity assertion.
            gate._persist([(PROOF, proof.serialize()) for proof in proofs])
            current = gate.archive_head()
            if head is None:
                head = current
            if current != head:
                raise AssertionError("comparison gates do not contain identical authenticated evidence")
            if mode == "legacy":
                for name, function in methods.items():
                    setattr(gate, name, MethodType(function, gate))
            path = directory / f"{mode}-{count}.spharc"
            rollover = measure(gate, lambda: gate.rotate_archive(path), path)
            if gate.archive_head() != head or gate.resident_bytes() != 0:
                raise AssertionError("rollover changed head or left resident evidence")
            verification = [measure(gate, lambda: gate._verify_store(head), path) for _ in range(repeats)]
            result["modes"][mode] = {"rollover": rollover, "verification_runs": verification,
                "verification_wall": distribution([row["wall_seconds"] for row in verification]),
                "verification_cpu": distribution([row["cpu_seconds"] for row in verification]),
                "cold_file_bytes": path.stat().st_size, "exact_head_preserved": True}
        finally:
            gate.close()
    result["journal_events"], result["journal_bytes"] = head["events"], head["bytes"]
    result["comparison"] = {}
    old, new = result["modes"]["legacy"], result["modes"]["streaming"]
    for metric in ("verification_wall", "verification_cpu"):
        result["comparison"][metric + "_p50_reduction_fraction"] = 1 - new[metric]["p50_seconds"] / old[metric]["p50_seconds"]
    result["comparison"]["rollover_wall_reduction_fraction"] = 1 - new["rollover"]["wall_seconds"] / old["rollover"]["wall_seconds"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument("--counts", type=int, nargs="+", default=[100, 1000, 5000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--results", type=Path, required=True)
    options = parser.parse_args()
    if (not 1 <= len(options.counts) <= 6 or any(not 1 <= count <= 20_000 for count in options.counts)
            or not 1 <= options.repeats <= 5):
        parser.error("use one to six sizes of 1..20000 receipts and one to five repeats")
    source = options.baseline_source.read_text()
    methods = baseline_methods(source)
    report = {"schema": 1, "result": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, *sys.argv], "platform": platform.platform(),
        "baseline_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "current_source_sha256": {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
            for name in ("hash_mining_gate.py", "hash_gate_startup.py", "hash_gate_archive.py", "benchmark_archive_startup.py")},
        "cases": [], "limitations": [
            "Archive-only canonical/hash-chain benchmark; native validity, Stratum, mainnet difficulty and payouts are outside its scope",
            "Exact solved regtest proof bodies share one origin; setup directly persists these fixture bodies outside measurement",
            "Every verification still reads all lifetime bytes and authenticates proof origins; no incremental skip or trusted timestamp",
            "Methods are compared on identical checkpoint/evidence with fresh bounded metadata caches, but OS file cache remains warm",
            "Fixed legacy-first order and finite repeats are descriptive measurements, not statistical confidence intervals",
            "Local filesystem and small shared-origin proofs do not characterize large snapshots, many origins or WAN archive recovery",
            "Point-read and file-open accounting adds a small amount of Python overhead proportional to those operations"]}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="sharepool-archive-scaling-") as temporary:
            for count in options.counts:
                report["cases"].append(run_case(Path(temporary), count, methods, options.repeats))
        report["result"] = "passed"
    finally:
        report["wall_seconds"] = time.monotonic() - started
        options.results.parent.mkdir(parents=True, exist_ok=True)
        options.results.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": report["result"], "cases": [{"receipts": row["receipts"], **row["comparison"]}
                          for row in report["cases"]], "wall_seconds": report["wall_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
