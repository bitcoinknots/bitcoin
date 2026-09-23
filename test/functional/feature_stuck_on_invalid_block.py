#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the warning for a block marked invalid that holds the chain back.

A block marked invalid that builds directly on the tip stops the node for good:
every peer's chain runs through it, so no headers are ever accepted again. The
node is expected to validate the block again, at startup and when peers keep
serving it, and to say either how to accept it (a stale mark) or why it is still
rejected (a block that really is invalid).
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

INVALID_HEIGHT = 11


class StuckOnInvalidBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def stuck_warnings(self, node):
        return [w for w in node.getblockchaininfo()["warnings"] if "marked invalid" in w]

    def run_test(self):
        node0, node1 = self.nodes
        self.generate(node0, 30)
        invalid_hash = node0.getblockhash(INVALID_HEIGHT)
        tip_below = node0.getblockhash(INVALID_HEIGHT - 1)
        self.disconnect_nodes(0, 1)

        self.log.info("A stale mark: a valid block marked invalid by hand")
        node1.invalidateblock(invalid_hash)
        assert_equal(node1.getbestblockhash(), tip_below)
        assert_equal(self.stuck_warnings(node1), [])

        stale_log = f"Block {invalid_hash} at height {INVALID_HEIGHT} is marked invalid but passes validation under the current rules, so this node cannot advance past height {INVALID_HEIGHT - 1}. If the block should be accepted, run: bitcoin-cli reconsiderblock {invalid_hash}"
        stale_warning = f"reconsiderblock {invalid_hash}"

        self.log.info("Peers serving that chain trigger the check on a running node")
        with node1.assert_debug_log(expected_msgs=[stale_log], timeout=10):
            self.connect_nodes(0, 1)
            self.generate(node0, 1, sync_fun=self.no_op)
        warnings = self.stuck_warnings(node1)
        assert_equal(len(warnings), 1)
        assert stale_warning in warnings[0], warnings

        self.log.info("Further headers do not repeat the report")
        with node1.assert_debug_log(expected_msgs=[], unexpected_msgs=["is marked invalid but passes validation"]):
            self.generate(node0, 1, sync_fun=self.no_op)
            node1.ping()
        assert_equal(len(self.stuck_warnings(node1)), 1)

        self.log.info("A restart reports it again, before any peer is involved")
        self.disconnect_nodes(0, 1)
        with node1.assert_debug_log(expected_msgs=[stale_log]):
            self.restart_node(1)
        assert_equal(node1.getbestblockhash(), tip_below)
        assert stale_warning in self.stuck_warnings(node1)[0]

        self.log.info("Following the advice clears the warning and the node syncs")
        node1.reconsiderblock(invalid_hash)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_equal(self.stuck_warnings(node1), [])
        assert_equal(self.stuck_warnings(node0), [])

        self.log.info("A block that really is invalid: the report gives the reason instead")
        self.disconnect_nodes(0, 1)
        tip = node1.getbestblockhash()
        height = node1.getblockcount() + 1
        bad_tx = CTransaction()
        bad_tx.vin = [CTxIn(COutPoint(int(invalid_hash, 16), 0), b"")]  # not an existing output
        bad_tx.vout = [CTxOut(COIN, CScript([OP_TRUE]))]
        block = create_block(int(tip, 16), create_coinbase(height), node1.getblock(tip)["time"] + 1, txlist=[bad_tx])
        block.solve()
        assert_equal(node1.submitblock(block.serialize().hex()), "bad-txns-inputs-missingorspent")
        bad_hash = block.hash
        assert_equal(node1.getbestblockhash(), tip)

        # The reason is rendered as "<reject reason>, <debug message>", so match its start.
        invalid_log = f"Block {bad_hash} at height {height} is marked invalid and fails validation again (bad-txns-inputs-missingorspent"
        with node1.assert_debug_log(expected_msgs=[invalid_log, f"so this node cannot advance past height {height - 1}. If the block is known to be valid, the chain state may be damaged; -reindex-chainstate rebuilds it"], unexpected_msgs=["reconsiderblock"]):
            self.restart_node(1)
        warnings = self.stuck_warnings(node1)
        assert_equal(len(warnings), 1)
        assert "fails validation again (bad-txns-inputs-missingorspent" in warnings[0], warnings
        assert "reconsiderblock" not in warnings[0], warnings

        self.log.info("The warning goes away once the chain moves on")
        self.connect_nodes(0, 1)
        self.generate(node0, 1)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_equal(self.stuck_warnings(node1), [])


if __name__ == '__main__':
    StuckOnInvalidBlockTest(__file__).main()
