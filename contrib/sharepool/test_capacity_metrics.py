#!/usr/bin/env python3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from capacity_metrics import Measurements, ResourceSampler, cpu_seconds, distribution, logical_bytes


class CapacityMetricsTests(unittest.TestCase):
    def test_nearest_rank_and_empty(self):
        self.assertEqual(distribution([]), {"count": 0})
        result = distribution(range(1, 101))
        self.assertEqual((result["p50_seconds"], result["p95_seconds"], result["p99_seconds"]), (50, 95, 99))
        self.assertEqual(distribution([7])["p99_seconds"], 7)

    def test_cpu_formats(self):
        self.assertEqual(cpu_seconds("1:23.45"), 83.45)
        self.assertEqual(cpu_seconds("02:01:03"), 7263)
        self.assertEqual(cpu_seconds("1-02:01:03"), 93663)

    def test_failures_remain_timed(self):
        measurements = Measurements()
        with self.assertRaises(ValueError):
            measurements.call("rejection", int, "bad")
        result = measurements.report()["rejection"]
        self.assertEqual((result["count"], result["failures"]), (1, 1))
        self.assertGreaterEqual(result["max_seconds"], 0)

    def test_disk_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "body").write_bytes(b"abc")
            (path / "link").symlink_to(path / "body")
            self.assertEqual(logical_bytes(path), 3)

    def test_final_sample_failure_preserves_report_and_cleanup(self):
        sampler = ResourceSampler({}, {})
        sampler.start()
        with patch.object(sampler, "sample", side_effect=ValueError("process disappeared")):
            report = sampler.finish()
        self.assertEqual(report["errors"], ["ValueError"])
        self.assertEqual(len(report["samples"]), 1)
        self.assertFalse(sampler.thread.is_alive())

    def test_failed_start_cannot_prevent_final_cleanup(self):
        sampler = ResourceSampler({}, {})
        with patch.object(sampler, "sample", side_effect=OSError("process unavailable")):
            with self.assertRaises(OSError):
                sampler.start()
            report = sampler.finish()
        self.assertEqual(report["errors"], ["OSError"])
        self.assertEqual(report["samples"], [])
        self.assertFalse(report["sampling_complete"])


if __name__ == "__main__":
    unittest.main()
