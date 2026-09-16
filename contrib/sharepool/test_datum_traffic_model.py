#!/usr/bin/env python3
"""Check gateway/client separation and payload arithmetic without a native node."""
import math
import unittest

from datum_traffic_model import estimate, read_sample, report


class DatumTrafficModelTests(unittest.TestCase):
    def test_preserved_measurements(self):
        sample = read_sample()
        self.assertEqual(sample["full_template_bytes"], 1_644_881)
        self.assertEqual(sample["one_job_snapshot_bytes"], 1_664_368)
        self.assertEqual(sample["batch_snapshot_bytes"], 3_056_407)
        self.assertEqual(sample["source"]["transaction_count"], 3547)

    def test_default_additive_payload(self):
        result = estimate()
        plan = result["plans"]["conservative_additive_allowance"]
        self.assertAlmostEqual(plan["refreshes_per_gateway"], 2160 + 144)
        shared = plan["optimistic_shared_batches"]
        self.assertAlmostEqual(shared["received_payload_bytes"], 7_041_961_728)
        self.assertAlmostEqual(shared["mean_inbound_Mbps"], 0.6520334933333334)
        full = plan["separate_full_templates"]
        self.assertAlmostEqual(full["received_payload_bytes"], 378_980_582_400)

    def test_timer_resets_reduce_expected_refreshes(self):
        result = estimate()
        renewal = result["plans"]["steady_state_expected"]["refreshes_per_gateway"]
        additive = result["plans"]["conservative_additive_allowance"]["refreshes_per_gateway"]
        self.assertGreater(renewal, 2160)
        self.assertLess(renewal, additive)
        # E[min(block wait, 40s)] = integral_0^40 P(wait>t) dt.
        # Independent midpoint integration checks the renewal expression.
        steps = 10_000
        interval_mean = sum(math.exp(-((i + 0.5) * 40 / steps) / 600)
                            for i in range(steps)) * 40 / steps
        self.assertAlmostEqual(renewal, 86400 / interval_mean, places=6)

    def test_asic_count_does_not_multiply_template_streams(self):
        one = estimate(gateways=100, miners_per_gateway=1)
        ten = estimate(gateways=100, miners_per_gateway=10)
        self.assertEqual(one["plans"], ten["plans"])
        self.assertEqual(ten["total_miners"], 1000)
        self.assertEqual(ten["illustrative_submissions"]["total_count"],
                         10 * one["illustrative_submissions"]["total_count"])
        self.assertFalse(ten["illustrative_submissions"]["included_in_payload_estimate"])
        self.assertFalse(ten["illustrative_submissions"]["changes_active_share_difficulty"])

    def test_independent_gateways_multiply_template_streams(self):
        hundred = estimate(gateways=100)
        thousand = estimate(gateways=1000)
        for mode in hundred["plans"]:
            for transport in ("separate_full_templates", "optimistic_shared_batches"):
                first = hundred["plans"][mode][transport]["received_payload_bytes"]
                second = thousand["plans"][mode][transport]["received_payload_bytes"]
                self.assertAlmostEqual(second / first, 10)

    def test_remainder_does_not_invent_unmeasured_compression(self):
        result = estimate(gateways=101)
        self.assertEqual(result["batching"]["full_100_job_batches"], 1)
        self.assertEqual(result["batching"]["residual_jobs_costed_as_separate_one_job_snapshots"], 1)
        payload = result["plans"]["steady_state_expected"]["optimistic_shared_batches"]
        self.assertEqual(payload["payload_bytes_per_refresh_wave"], 3_056_407 + 1_664_368)
        one = estimate(gateways=1, miners_per_gateway=100)
        payload = one["plans"]["steady_state_expected"]["optimistic_shared_batches"]
        self.assertEqual(payload["payload_bytes_per_refresh_wave"], 1_664_368)

    def test_duration_scales_bytes_not_average_bandwidth(self):
        day = estimate()
        week = estimate(duration_seconds=7 * 86400)
        for mode in day["plans"]:
            first = day["plans"][mode]["optimistic_shared_batches"]
            second = week["plans"][mode]["optimistic_shared_batches"]
            self.assertAlmostEqual(second["received_payload_bytes"] / first["received_payload_bytes"], 7)
            self.assertAlmostEqual(second["mean_inbound_Mbps"], first["mean_inbound_Mbps"])

    def test_refresh_bounds_and_rare_block_limit(self):
        for seconds in (5, 40, 120):
            result = estimate(refresh_seconds=seconds, block_interval_seconds=1e15)
            self.assertAlmostEqual(result["plans"]["steady_state_expected"]["refreshes_per_gateway"],
                                   86400 / seconds, places=6)
        fastest = estimate(refresh_seconds=5)["plans"]["steady_state_expected"]["changed_jobs_per_second"]
        slowest = estimate(refresh_seconds=120)["plans"]["steady_state_expected"]["changed_jobs_per_second"]
        self.assertGreater(fastest, slowest)

    def test_invalid_parameters(self):
        for name in ("gateways", "miners_per_gateway", "refresh_seconds", "block_interval_seconds",
                     "duration_seconds", "illustrative_submissions_per_minute_per_miner"):
            for value in (0, -1, True, None, "40", float("nan"), float("inf")):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    estimate(**{name: value})
        for name in ("gateways", "miners_per_gateway"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                estimate(**{name: 1.5})
        for seconds in (4.99, 120.01):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                estimate(refresh_seconds=seconds)

    def test_report_preserves_scope_and_selected_inputs(self):
        result = report(gateways=1000, miners_per_gateway=2, refresh_seconds=120)
        self.assertEqual(result["selected_scenario"]["total_miners"], 2000)
        self.assertEqual(result["selected_scenario"]["refresh_seconds"], 120)
        self.assertEqual(len(result["default_comparisons"]), 4)
        self.assertIn("not live traffic", result["scope"])
        self.assertEqual(len(result["measurement"]["sha256"]), 64)

    def test_extreme_finite_inputs_fail_before_reporting_overflow(self):
        cases = (
            {"gateways": 10 ** 400},
            {"gateways": 10 ** 300},
            {"block_interval_seconds": 5e-324},
            {"duration_seconds": 1e308},
            {"miners_per_gateway": 10 ** 306},
            {"illustrative_submissions_per_minute_per_miner": 1e308},
        )
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                estimate(**options)


if __name__ == "__main__":
    unittest.main()
