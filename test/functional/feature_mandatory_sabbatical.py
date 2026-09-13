#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Mandatory Sabbatical: the same identity (coinbase primary payout
script) may mine at most sabbatical_max of the last sabbatical_window blocks,
from a configured activation height."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SABBATICAL_HEIGHT = 110
WINDOW = 6
MAX = 2
MINER_A = CScript([OP_TRUE, OP_TRUE])
MINER_B = CScript([OP_TRUE, OP_TRUE, OP_TRUE])


class MandatorySabbaticalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-sabbaticalheight={SABBATICAL_HEIGHT}",
            f"-sabbaticalwindow={WINDOW}",
            f"-sabbaticalmax={MAX}",
        ]]

    def mine(self, node, script_pubkey, *, expect_reject=None):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=script_pubkey),
                             node.getblock(tip)["time"] + 1)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        assert_equal(result, expect_reject)
        return result is None

    def run_test(self):
        node = self.nodes[0]

        self.log.info("mine up to just before the rule activates")
        self.generatetoaddress(node, SABBATICAL_HEIGHT - 1, ADDRESS_BCRT1_UNSPENDABLE)

        self.log.info("miner A takes its allowed share of the window")
        for _ in range(MAX):
            assert self.mine(node, MINER_A)

        self.log.info("one more block from miner A, still within the window, is rejected")
        assert not self.mine(node, MINER_A, expect_reject="bad-cb-sabbatical")

        self.log.info("a different identity is unaffected by A's count")
        assert self.mine(node, MINER_B)

        self.log.info("miner A is still over its share of the window")
        assert not self.mine(node, MINER_A, expect_reject="bad-cb-sabbatical")

        self.log.info("mining enough other blocks rolls A's earlier blocks out of the window")
        # Window is WINDOW=6 blocks. A has 2 blocks sitting inside it. Once
        # enough blocks from OTHER identities are mined that A's blocks fall
        # outside the trailing window, A can mine again. Each padding block
        # uses its own distinct identity, since B is subject to the same
        # sabbatical limit as A and can't absorb them all itself.
        for i in range(WINDOW - MAX):
            padding_identity = CScript([OP_TRUE] * (10 + i))  # unique per iteration
            assert self.mine(node, padding_identity)
        assert self.mine(node, MINER_A)


if __name__ == '__main__':
    MandatorySabbaticalTest(__file__).main()
