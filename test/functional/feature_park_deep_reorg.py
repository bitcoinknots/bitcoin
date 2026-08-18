#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Park competing chains that would rewind more than 6 blocks."""

from test_framework.test_framework import BitcoinTestFramework
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

    def run_test(self):
        self.generate(self.nodes[0], 10, sync_fun=self.sync_all)
        assert_equal(self.nodes[0].getblockcount(), 10)

        self.disconnect_nodes(0, 1)
        self.generate(self.nodes[0], 8, sync_fun=self.no_op)
        self.generate(self.nodes[1], 10, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), 18)
        assert_equal(self.nodes[1].getblockcount(), 20)

        fork_hash = self.nodes[1].getblockhash(11)
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[1:], timeout=10)

        # Node 0 keeps its tip; the heavier chain is parked.
        self.wait_until(lambda: any(t["status"] != "active" for t in self.nodes[0].getchaintips()), timeout=10)
        assert_equal(self.nodes[0].getblockcount(), 18)

        self.nodes[0].unparkblock(fork_hash)
        self.wait_until(lambda: self.nodes[0].getblockcount() == 20, timeout=10)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())


if __name__ == "__main__":
    ParkDeepReorgTest(__file__).main()
