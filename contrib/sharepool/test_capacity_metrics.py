#!/usr/bin/env python3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from capacity_metrics import (Measurements, ResourceSampler, cpu_seconds, distribution,
                              logical_bytes, pipeline_progress, resource_utilization, template_geometry)


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

    def test_shared_and_disjoint_transactions_have_distinct_geometry(self):
        shared = template_geometry([(100, 400, [b"coinbase-a", b"common"]),
                                    (100, 400, [b"coinbase-b", b"common"])])
        disjoint = template_geometry([(100, 400, [b"coinbase-a", b"unique-a"]),
                                      (100, 400, [b"coinbase-b", b"unique-b"])])
        self.assertEqual(shared["transaction_references"], 4)
        self.assertEqual(shared["unique_transactions"], 3)
        self.assertEqual(shared["distinct_noncoinbase_transaction_sets"], 1)
        self.assertEqual(shared["noncoinbase_byte_reuse_factor"], 2)
        self.assertEqual(shared["transaction_bytes_eliminated_by_dictionary"], 6)
        self.assertEqual(disjoint["distinct_noncoinbase_transaction_sets"], 2)
        self.assertEqual(disjoint["noncoinbase_byte_reuse_factor"], 1)
        self.assertEqual(disjoint["transaction_bytes_eliminated_by_dictionary"], 0)

    def test_geometry_uses_full_witness_bytes_and_separates_coinbase(self):
        result = template_geometry([(100, 150, [b"cb-a", b"tx-witness-a"]),
                                    (100, 150, [b"cb-b", b"tx-witness-b"])])
        self.assertEqual(result["unique_noncoinbase_transactions"], 2)
        self.assertEqual(result["expanded_template_bytes"], 200)
        self.assertEqual(result["template_weight"]["total_weight_units"], 300)
        self.assertEqual(template_geometry([(100, 400, [b"coinbase"])])["noncoinbase_byte_reuse_factor"], None)

    def test_geometry_stops_at_finite_limits(self):
        for kwargs in ({"max_templates": 0}, {"max_references": 1}, {"max_expanded_bytes": 99}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                template_geometry([(100, 400, [b"cb", b"tx"])], **kwargs)
        with self.assertRaises(ValueError):
            template_geometry([(3, 12, [b"cb", b"tx"])])
        with self.assertRaises(ValueError):
            template_geometry([(100, 400, [])])

    def test_resource_dimensions_are_not_clamped_or_combined(self):
        result = resource_utilization({"wire": 10, "expanded": 201}, {"wire": 100, "expanded": 200})
        self.assertEqual(result["wire"]["fraction"], .1)
        self.assertFalse(result["expanded"]["within_limit"])
        self.assertEqual(result["expanded"]["remaining"], -1)
        self.assertGreater(result["expanded"]["fraction"], 1)
        for value, limit in ((-1, 10), (True, 10), (0, 0), (1, False)):
            with self.subTest(value=value, limit=limit), self.assertRaises(ValueError):
                resource_utilization({"x": value}, {"x": limit})

    def test_failed_peer_recovery_preserves_actual_local_admission(self):
        block = {"admitted": 201, "native_accepted": True, "peer_ready": False}
        epochs = [{"offered": 300, "acknowledged": 300, "blocks": [block]}]
        result = pipeline_progress(epochs)
        self.assertEqual(result["admitted"], 201)
        self.assertEqual(result["current_acknowledged_backlog"], 99)
        self.assertEqual(result["peer_verified_admitted"], 0)
        self.assertEqual(result["peer_verification_backlog"], 201)
        block["peer_ready"] = True
        self.assertEqual(pipeline_progress(epochs)["peer_verified_admitted"], 201)

    def test_proposed_or_rejected_blocks_are_not_counted_as_native_admission(self):
        result = pipeline_progress([{"offered": 10, "acknowledged": 6,
            "blocks": [{"admitted": 6, "native_accepted": False, "peer_ready": False}]}])
        self.assertEqual(result["admitted"], 0)
        self.assertEqual(result["current_acknowledged_backlog"], 6)
        self.assertEqual(pipeline_progress([])["offered"], 0)
        with self.assertRaises(ValueError):
            pipeline_progress([{"offered": 3, "acknowledged": 4}])


if __name__ == "__main__":
    unittest.main()
