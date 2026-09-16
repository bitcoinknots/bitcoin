#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent forward-interval oracle for the zero-fee accounting reference.

The oracle intersects every contribution's cumulative-work interval with the
selected suffix. It does not walk backwards or call reference window helpers.
This verifies arithmetic only, not authenticated history, membership or mining.
"""
from collections import defaultdict
from itertools import product
import json
from pathlib import Path
import unittest

from tides_accounting import IssuedJob, Share, evaluate_job


POOL = b"P" * 32
JOB = b"J" * 32
SCRIPTS = (
    b"\x76\xa9\x14" + b"a" * 20 + b"\x88\xac",
    b"\xa9\x14" + b"b" * 20 + b"\x87",
    b"\x00\x14" + b"c" * 20,
    b"\x00\x20" + b"d" * 32,
    b"\x51\x20" + b"e" * 32,
)


def interval_answer(entries, network_work, reward):
    """Intersect [start,end) share intervals with [total-8D,total)."""
    upper = sum(entry.work for entry in entries)
    lower = max(0, upper - 8 * network_work)
    denominator = upper - lower
    assert denominator > 0
    weights = defaultdict(int)
    intervals, position = [], 0
    for entry in entries:
        start, end = position, position + entry.work
        overlap = max(0, min(end, upper) - max(start, lower))
        if overlap:
            weights[entry.payout_script] += overlap
            intervals.append((entry.sequence, overlap))
        position = end
    payouts = {script: reward * amount // denominator for script, amount in weights.items()}
    return {
        "window_work": 8 * network_work,
        "eligible_work": denominator,
        "weights": dict(weights),
        "payouts": {script: amount for script, amount in payouts.items() if amount},
        "rounding_residue": reward - sum(payouts.values()),
        "oldest_sequence": intervals[0][0],
        "oldest_work": intervals[0][1],
    }


def observed(job):
    result = evaluate_job(job)
    return {
        "window_work": result.requested_work,
        "eligible_work": result.counted_work,
        "weights": {value.payout_script: value.work for value in result.address_rewards},
        "payouts": dict(result.outputs),
        "rounding_residue": result.rounding_residue,
        "oldest_sequence": result.contributions[0].share.sequence,
        "oldest_work": result.contributions[0].included_work,
    }


class TidesAccountingOracleTests(unittest.TestCase):
    def test_small_exact_windows_match_forward_interval_oracle(self):
        # A finite table of 340 histories exercises startup, exact boundaries,
        # clipping inside a share, nonadjacent same-address aggregation and
        # zero/sub-satoshi payouts. This is a deterministic arithmetic check.
        for length in range(1, 5):
            for rows in product(product(range(2), (3, 5)), repeat=length):
                entries = tuple(Share(index, index.to_bytes(32, "big"), POOL,
                    SCRIPTS[owner], work) for index, (owner, work) in enumerate(rows, 1))
                for difficulty in (1, 2):
                    for reward in (0, 1, 7, 101):
                        with self.subTest(rows=rows, difficulty=difficulty, reward=reward):
                            job = IssuedJob(JOB, POOL, entries, difficulty, reward, 0)
                            self.assertEqual(observed(job), interval_answer(entries, difficulty, reward))

    def test_shared_cpp_vectors_match_independent_oracle(self):
        path = Path(__file__).resolve().parents[2] / "src" / "test" / "data" / "sharepool_tides.json"
        vectors = json.loads(path.read_text())
        for case in vectors["cases"]:
            with self.subTest(case=case["name"]):
                pool = bytes.fromhex(case["pool_id"])
                entries = tuple(Share(value["sequence"], bytes.fromhex(value["proof_id"]), pool,
                    bytes.fromhex(value["payout_script"]), int(value["work"])) for value in case["shares"])
                reward = case["subsidy"] + case["transaction_fees"]
                expected = dict(case["expected"])
                for name in ("window_work", "eligible_work", "oldest_work"):
                    expected[name] = int(expected[name])
                expected["weights"] = {bytes.fromhex(script): int(work) for script, work in expected["weights"].items()}
                expected["payouts"] = {bytes.fromhex(script): amount for script, amount in expected["payouts"].items()}
                self.assertEqual(expected, interval_answer(entries, int(case["network_work"]), reward))

    def test_all_native_script_shapes_and_zero_fee_reward_partition(self):
        entries = tuple(Share(index, index.to_bytes(32, "big"), POOL, script, index * 3)
                        for index, script in enumerate(SCRIPTS, 1))
        job = IssuedJob(JOB, POOL, entries, 6, 100, 23)
        self.assertEqual(observed(job), interval_answer(entries, 6, 123))
        result = evaluate_job(job)
        self.assertEqual(tuple(script for script, amount in result.outputs), tuple(sorted(SCRIPTS)))
        self.assertEqual(sum(amount for script, amount in result.outputs) + result.rounding_residue, 123)


if __name__ == "__main__":
    unittest.main()
