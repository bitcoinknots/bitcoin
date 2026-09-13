#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Pool Blocklist (Solo Salvation): reject blocks whose coinbase pays a
blocklisted output script, from a configured activation height."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

BLOCKLIST_HEIGHT = 110
BLOCKED_SCRIPT = CScript([OP_TRUE, OP_TRUE])  # stand-in for a known pool's payout script
ALLOWED_SCRIPT = CScript([OP_TRUE])


class PoolBlocklistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-blocklistheight={BLOCKLIST_HEIGHT}",
            f"-blocklistscript={BLOCKED_SCRIPT.hex()}",
        ]]

    def submit(self, node, tip, height, script_pubkey, *, expect_reject=None):
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=script_pubkey),
                             node.getblock(tip)["time"] + 1)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        assert_equal(result, expect_reject)
        return block

    def run_test(self):
        node = self.nodes[0]

        self.log.info("before activation, a block paying the blocklisted script is fine")
        self.generatetoaddress(node, BLOCKLIST_HEIGHT - 2, ADDRESS_BCRT1_UNSPENDABLE)
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        self.submit(node, tip, height, BLOCKED_SCRIPT)  # accepted, still pre-activation
        assert_equal(node.getblockcount(), BLOCKLIST_HEIGHT - 1)

        self.log.info("at activation, a block paying the blocklisted script is rejected")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        assert_equal(height, BLOCKLIST_HEIGHT)
        self.submit(node, tip, height, BLOCKED_SCRIPT, expect_reject="bad-cb-blocklisted")
        assert_equal(node.getblockcount(), BLOCKLIST_HEIGHT - 1)  # rejected, chain didn't move

        self.log.info("a block paying any other script at the same height is accepted")
        self.submit(node, tip, height, ALLOWED_SCRIPT)
        assert_equal(node.getblockcount(), BLOCKLIST_HEIGHT)


if __name__ == '__main__':
    PoolBlocklistTest(__file__).main()
