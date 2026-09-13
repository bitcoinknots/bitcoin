#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Austerity Mode: zero block subsidy from an activation height."""

from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

AUSTERITY_HEIGHT = 130


class AusterityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-austerityheight={AUSTERITY_HEIGHT}"]]

    def run_test(self):
        node = self.nodes[0]
        addr = ADDRESS_BCRT1_UNSPENDABLE

        self.log.info("before activation, blocks pay the normal subsidy")
        self.generatetoaddress(node, AUSTERITY_HEIGHT - 1, addr)
        cb = node.getblock(node.getblockhash(AUSTERITY_HEIGHT - 1), 2)["tx"][0]
        assert_equal(Decimal(str(cb["vout"][0]["value"])), Decimal("50"))

        self.log.info("from the activation height the subsidy is zero")
        self.generatetoaddress(node, 1, addr)  # height == AUSTERITY_HEIGHT
        cb = node.getblock(node.getblockhash(AUSTERITY_HEIGHT), 2)["tx"][0]
        assert_equal(sum(Decimal(str(o["value"])) for o in cb["vout"]), Decimal("0"))

        self.log.info("a block that still claims the subsidy is rejected")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        greedy = create_block(int(tip, 16), create_coinbase(height, nValue=50, script_pubkey=CScript([OP_TRUE])),
                              node.getblock(tip)["time"] + 1)
        greedy.solve()
        assert_equal(node.submitblock(greedy.serialize().hex()), "bad-cb-amount")


if __name__ == '__main__':
    AusterityTest(__file__).main()
