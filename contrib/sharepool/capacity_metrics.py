#!/usr/bin/env python3
"""Small stdlib-only measurements for finite, isolated native workloads."""
from collections import defaultdict
from contextlib import contextmanager
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
