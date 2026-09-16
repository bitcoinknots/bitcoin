#!/usr/bin/env python3
"""Small stdlib-only measurements for finite, isolated native workloads."""
from collections import defaultdict
from contextlib import contextmanager
import hashlib
import math
from pathlib import Path
import subprocess
import threading
import time


def distribution(values, unit="seconds"):
    values = sorted(values)
    if not values:
        return {"count": 0}
    def percentile(fraction):
        return values[max(0, math.ceil(len(values) * fraction) - 1)]
    return {"count": len(values), f"total_{unit}": sum(values), f"min_{unit}": values[0],
            f"p50_{unit}": percentile(.50), f"p95_{unit}": percentile(.95),
            f"p99_{unit}": percentile(.99), f"max_{unit}": values[-1]}


def resource_utilization(values, limits):
    """Report independent dimensions, including over-budget proposals without clamping."""
    result = {}
    for name, value in values.items():
        limit = limits[name]
        if type(value) is not int or value < 0 or type(limit) is not int or limit <= 0:
            raise ValueError("resource measurements and limits must be nonnegative/positive integers")
        result[name] = {"used": value, "limit": limit, "fraction": value / limit,
                        "remaining": limit - value, "within_limit": value <= limit}
    return result


def pipeline_progress(epochs):
    """Keep durable ACKs, local native admission and peer confirmation separate."""
    offered = sum(epoch.get("offered", 0) for epoch in epochs)
    acknowledged = sum(epoch.get("acknowledged", 0) for epoch in epochs)
    blocks = [block for epoch in epochs for block in epoch.get("blocks", ())]
    admitted = sum(block.get("admitted", 0) for block in blocks if block.get("native_accepted") is True)
    peer_verified = sum(block.get("admitted", 0) for block in blocks
                        if block.get("native_accepted") is True and block.get("peer_ready") is True)
    if not 0 <= peer_verified <= admitted <= acknowledged <= offered:
        raise ValueError("inconsistent capacity pipeline counters")
    return {"offered": offered, "acknowledged": acknowledged, "admitted": admitted,
            "peer_verified_admitted": peer_verified,
            "current_acknowledged_backlog": acknowledged - admitted,
            "peer_verification_backlog": admitted - peer_verified}


def template_geometry(templates, *, max_templates=100, max_references=20_000,
                      max_expanded_bytes=128 * 1024 * 1024):
    """Account actual serialized bodies without retaining duplicate transaction bytes.

    Each input is (full body bytes count, native weight, iterable of serialized
    transactions in block order). The first transaction is the coinbase. Work
    stays bounded independently of native consensus limits; this helper measures
    the finite capacity fixture, not arbitrary network input or native validity.
    """
    sizes, weights, references, sets = [], [], [], set()
    unique, noncoinbase_unique = {}, {}
    expanded, referenced_bytes, noncoinbase_bytes, noncoinbase_references, total_references = 0, 0, 0, 0, 0
    for size, weight, transactions in templates:
        if (len(sizes) >= max_templates or type(size) is not int or size <= 0 or
                type(weight) is not int or weight <= 0 or size > max_expanded_bytes - expanded):
            raise ValueError("finite template geometry budget exceeded")
        expanded += size
        sizes.append(size)
        weights.append(weight)
        identities, count, body_transaction_bytes = [], 0, 0
        for index, raw in enumerate(transactions):
            if (type(raw) is not bytes or not raw or
                    total_references >= max_references or len(raw) > size - body_transaction_bytes):
                raise ValueError("finite transaction geometry budget exceeded")
            body_transaction_bytes += len(raw)
            identity = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
            if identity in unique and unique[identity] != len(raw):
                raise ValueError("transaction identity has inconsistent serialized size")
            unique[identity] = len(raw)
            count += 1
            total_references += 1
            referenced_bytes += len(raw)
            if index:
                noncoinbase_unique[identity] = len(raw)
                noncoinbase_bytes += len(raw)
                noncoinbase_references += 1
                identities.append(identity)
        if count == 0:
            raise ValueError("template geometry requires a coinbase transaction")
        references.append(count)
        sets.add(tuple(sorted(identities)))
    unique_bytes, unique_noncoinbase_bytes = sum(unique.values()), sum(noncoinbase_unique.values())
    return {"template_count": len(sizes), "expanded_template_bytes": expanded,
        "transaction_references": total_references, "referenced_transaction_bytes": referenced_bytes,
        "unique_transactions": len(unique), "unique_transaction_bytes": unique_bytes,
        "noncoinbase_transaction_references": noncoinbase_references,
        "noncoinbase_referenced_bytes": noncoinbase_bytes,
        "unique_noncoinbase_transactions": len(noncoinbase_unique),
        "unique_noncoinbase_transaction_bytes": unique_noncoinbase_bytes,
        "distinct_noncoinbase_transaction_sets": len(sets),
        "noncoinbase_byte_reuse_factor": noncoinbase_bytes / unique_noncoinbase_bytes if unique_noncoinbase_bytes else None,
        "transaction_bytes_eliminated_by_dictionary": referenced_bytes - unique_bytes,
        "template_bytes": distribution(sizes, "bytes"),
        "template_weight": distribution(weights, "weight_units"),
        "template_transaction_references": distribution(references, "references")}


def cpu_seconds(value):
    days, _, value = value.rpartition("-") if "-" in value else ("0", "", value)
    pieces = [float(piece) for piece in value.split(":")]
    if not 1 <= len(pieces) <= 3:
        raise ValueError("unsupported ps CPU time")
    return int(days) * 86400 + sum(piece * 60 ** index for index, piece in enumerate(reversed(pieces)))


def logical_bytes(path):
    total = 0
    for entry in Path(path).rglob("*"):
        try:
            if not entry.is_symlink() and entry.is_file():
                total += entry.stat().st_size
        except FileNotFoundError:
            pass  # Atomic rename/removal during observation.
    return total


class Measurements:
    def __init__(self):
        self.values = defaultdict(list)
        self.failures = defaultdict(int)

    @contextmanager
    def measure(self, name):
        started = time.monotonic()
        try:
            yield
        except BaseException:
            self.failures[name] += 1
            raise
        finally:
            self.values[name].append(time.monotonic() - started)

    def call(self, name, function, *args, **kwargs):
        with self.measure(name):
            return function(*args, **kwargs)

    def report(self):
        return {name: dict(distribution(values), failures=self.failures[name])
                for name, values in sorted(self.values.items())}


class ResourceSampler:
    """Sample cumulative ps CPU, RSS, and logical file lengths; never RPC state."""
    def __init__(self, processes, directories, interval=5):
        self.processes, self.directories = processes, directories
        self.interval, self.samples, self.errors = interval, [], []
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def sample(self):
        row = {"elapsed_seconds": time.monotonic() - self.started, "processes": {}, "disk_bytes": {}}
        for name, pid in self.processes.items():
            result = subprocess.run(["ps", "-p", str(pid), "-o", "rss=", "-o", "time="],
                                    capture_output=True, text=True, timeout=5, check=True)
            rss, cpu = result.stdout.split()
            row["processes"][name] = {"rss_bytes": int(rss) * 1024, "cpu_seconds": cpu_seconds(cpu)}
        row["disk_bytes"] = {name: logical_bytes(path) for name, path in self.directories.items()}
        self.samples.append(row)

    def _run(self):
        while not self.stop.wait(self.interval):
            try:
                self.sample()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.errors.append(type(error).__name__)

    def start(self):
        self.sample()
        self.thread.start()

    def finish(self):
        self.stop.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=10)
        try:
            self.sample()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.errors.append(type(error).__name__)
        if not self.samples:
            return {"interval_seconds": self.interval, "samples": [], "errors": self.errors,
                    "processes": {}, "logical_disk_growth_bytes": {}, "sampling_complete": False}
        first, last = self.samples[0], self.samples[-1]
        elapsed = last["elapsed_seconds"] - first["elapsed_seconds"]
        processes = {}
        for name in self.processes:
            delta = last["processes"][name]["cpu_seconds"] - first["processes"][name]["cpu_seconds"]
            processes[name] = {"cpu_seconds": delta, "average_cpu_cores": delta / elapsed if elapsed else None,
                "max_sampled_rss_bytes": max(row["processes"][name]["rss_bytes"] for row in self.samples)}
        return {"interval_seconds": self.interval, "samples": self.samples, "errors": self.errors,
                "processes": processes, "logical_disk_growth_bytes": {
                    name: last["disk_bytes"][name] - first["disk_bytes"][name] for name in self.directories}}
