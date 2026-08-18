#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Park competing chains that would rewind more than -parkreorgdepth blocks.

Deep-reorg parking is a node-local chain-selection policy, not consensus.
The default threshold is 6: a 6-block reorg proceeds automatically, a
7-block reorg is parked for manual review.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class ParkDeepReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-parkdeepreorg=1", "-parkreorgdepth=6"],
            ["-parkdeepreorg=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def _build_fork(self, short_idx, long_idx, rewind, extra=1):
        """Mine a competing fork that would rewind `rewind` blocks on short_idx."""
        self.disconnect_nodes(short_idx, long_idx)
        fork_height = self.nodes[short_idx].getblockcount()
        self.generate(self.nodes[short_idx], rewind, sync_fun=self.no_op)
        self.generate(self.nodes[long_idx], rewind + extra, sync_fun=self.no_op)
        fork_hash = self.nodes[long_idx].getblockhash(fork_height + 1)
        return fork_hash, self.nodes[short_idx].getblockcount(), self.nodes[long_idx].getblockcount()

    def _connect_expect_follow(self, short_idx, long_idx, expected_height):
        self.connect_nodes(short_idx, long_idx)
        self.wait_until(lambda: self.nodes[short_idx].getblockcount() == expected_height, timeout=10)
        assert_equal(self.nodes[short_idx].getbestblockhash(), self.nodes[long_idx].getbestblockhash())

    def _connect_expect_parked(self, short_idx, long_idx, expected_height, competing_tip):
        with self.nodes[short_idx].assert_debug_log(["Parking block"], timeout=10):
            self.connect_nodes(short_idx, long_idx)
        self.wait_until(lambda: any(t["hash"] == competing_tip for t in self.nodes[short_idx].getchaintips()), timeout=10)
        assert_equal(self.nodes[short_idx].getblockcount(), expected_height)

    def test_invalid_parkreorgdepth(self):
        self.log.info("Reject -parkreorgdepth values below 1")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-parkreorgdepth=0"],
            expected_msg="Error: -parkreorgdepth must be at least 1 (got 0); use -parkdeepreorg=0 to disable parking",
            match=ErrorMatch.FULL_TEXT,
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-parkreorgdepth=-1"],
            expected_msg="Error: -parkreorgdepth must be at least 1 (got -1); use -parkdeepreorg=0 to disable parking",
            match=ErrorMatch.FULL_TEXT,
        )
        self.start_node(0)
        self.connect_nodes(0, 1)

    def test_default_boundary(self):
        self.log.info("Default parkreorgdepth=6: 6-block reorg is not parked")
        _, _, long_height = self._build_fork(0, 1, rewind=6)
        self._connect_expect_follow(0, 1, long_height)

        self.log.info("Default parkreorgdepth=6: 7-block reorg is parked")
        fork_hash, short_height, _ = self._build_fork(0, 1, rewind=7)
        competing_tip = self.nodes[1].getbestblockhash()
        self._connect_expect_parked(0, 1, short_height, competing_tip)
        self.nodes[0].unparkblock(fork_hash)
        self.wait_until(lambda: self.nodes[0].getblockcount() == self.nodes[1].getblockcount(), timeout=10)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())

    def test_custom_threshold(self):
        self.log.info("Custom parkreorgdepth=4: 4-block reorg is not parked")
        self.restart_node(0, extra_args=["-parkdeepreorg=1", "-parkreorgdepth=4"])
        self.connect_nodes(0, 1)
        self.sync_all()
        _, _, long_height = self._build_fork(0, 1, rewind=4)
        self._connect_expect_follow(0, 1, long_height)

        self.log.info("Custom parkreorgdepth=4: 5-block reorg is parked")
        fork_hash, short_height, _ = self._build_fork(0, 1, rewind=5)
        competing_tip = self.nodes[1].getbestblockhash()
        self._connect_expect_parked(0, 1, short_height, competing_tip)
        self.nodes[0].unparkblock(fork_hash)
        self.wait_until(lambda: self.nodes[0].getblockcount() == self.nodes[1].getblockcount(), timeout=10)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())

    def test_parking_disabled(self):
        self.log.info("parkdeepreorg=0: a deep competing chain is not parked")
        # Node 1 has -parkdeepreorg=0. Give it the shorter chain so it would
        # rewind more than the default depth if parking were enabled.
        _, short_height, long_height = self._build_fork(1, 0, rewind=7)
        self._connect_expect_follow(1, 0, long_height)
        assert_equal(self.nodes[1].getblockcount(), long_height)
        assert short_height < long_height

    def run_test(self):
        self.test_invalid_parkreorgdepth()
        self.generate(self.nodes[0], 10, sync_fun=self.sync_all)
        assert_equal(self.nodes[0].getblockcount(), 10)
        self.test_default_boundary()
        self.test_custom_threshold()
        self.test_parking_disabled()


if __name__ == "__main__":
    ParkDeepReorgTest(__file__).main()
