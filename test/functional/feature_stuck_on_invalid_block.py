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

An invalid block on a fresh tip is ordinary (an old-rule miner, a broken miner)
and a valid block normally replaces it within minutes, so a block that fails
again is only reported once the tip is older than -maxtipage. The check starts
from the header the peer sent, or at startup from a flagged child of the tip,
so an unrelated invalid branch with more work cannot hide the block that holds
the node back.
"""

import os

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COIN,
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE

INVALID_HEIGHT = 11


class StuckOnInvalidBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def stuck_warnings(self, node):
        return [w for w in node.getblockchaininfo()["warnings"] if "marked invalid" in w]

    def alert_args(self, name):
        """Args for a restart that records -alertnotify calls in a fresh file."""
        self.alert_file = os.path.join(self.options.tmpdir, f"alerts_{name}.txt")
        return [f"-alertnotify=echo %s >> {self.alert_file}"]

    def invalid_block_on(self, node, spend_hash):
        """A block on the tip spending an output that does not exist (fails ConnectBlock, data is stored)."""
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        bad_tx = CTransaction()
        bad_tx.vin = [CTxIn(COutPoint(int(spend_hash, 16), 0), b"")]
        bad_tx.vout = [CTxOut(COIN, CScript([OP_TRUE]))]
        block = create_block(int(tip, 16), create_coinbase(height), node.getblock(tip)["time"] + 1, txlist=[bad_tx])
        block.solve()
        return block, height

    def announce(self, node, block):
        """A second, inbound peer announces the header of a block the node rejected."""
        node.add_p2p_connection(P2PInterface()).send_message(msg_headers([CBlockHeader(block)]))

    def run_test(self):
        self.test_stale_and_invalid_marks()
        self.test_fresh_tip_is_not_reported()
        self.test_block_without_data()
        self.test_hidden_culprit()
        self.test_presync_path()
        self.test_pruned_advice()

    def test_stale_and_invalid_marks(self):
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
            # Only a tip older than -maxtipage is held back; a fresh one expects a valid sibling.
            self.restart_node(1, extra_args=[f"-mocktime={node1.getblock(tip)['time'] + 25 * 3600}"])
        warnings = self.stuck_warnings(node1)
        assert_equal(len(warnings), 1)
        assert "fails validation again (bad-txns-inputs-missingorspent" in warnings[0], warnings
        assert "reconsiderblock" not in warnings[0], warnings

        self.log.info("The warning goes away once the chain moves on")
        self.connect_nodes(0, 1)
        self.generate(node0, 1)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_equal(self.stuck_warnings(node1), [])

    def test_fresh_tip_is_not_reported(self):
        node0, node1 = self.nodes
        self.log.info("An invalid block on a fresh tip is ordinary and is not reported")
        self.disconnect_nodes(0, 1)
        self.restart_node(1, extra_args=self.alert_args("fresh"))
        tip_time = node1.getblock(node1.getbestblockhash())["time"]
        node1.setmocktime(tip_time + 60)
        bad, height = self.invalid_block_on(node1, node1.getblockhash(1))
        assert_equal(node1.submitblock(bad.serialize().hex()), "bad-txns-inputs-missingorspent")
        assert_equal(self.stuck_warnings(node1), [])
        checked_log = f"Block {bad.hash} at height {height} is marked invalid and fails validation again (bad-txns-inputs-missingorspent"
        with node1.assert_debug_log(expected_msgs=[checked_log], unexpected_msgs=["cannot advance"], timeout=10):
            self.announce(node1, bad)
        assert_equal(self.stuck_warnings(node1), [])
        assert not os.path.exists(self.alert_file)

        self.log.info("Once the tip is older than -maxtipage, the same block is reported")
        node1.setmocktime(tip_time + 25 * 3600)
        with node1.assert_debug_log(expected_msgs=[checked_log, f"so this node cannot advance past height {height - 1}"], timeout=10):
            self.announce(node1, bad)
        assert_equal(len(self.stuck_warnings(node1)), 1)
        self.wait_until(lambda: os.path.exists(self.alert_file))
        node1.disconnect_p2ps()

        self.log.info("The next valid block clears it")
        self.connect_nodes(0, 1)
        self.generate(node0, 1)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_equal(self.stuck_warnings(node1), [])

    def test_block_without_data(self):
        node0, node1 = self.nodes
        self.log.info("A block rejected before its data was stored follows the same rule")
        self.disconnect_nodes(0, 1)
        self.restart_node(1, extra_args=self.alert_args("nodata"))
        tip = node1.getbestblockhash()
        height = node1.getblockcount() + 1
        tip_time = node1.getblock(tip)["time"]
        node1.setmocktime(tip_time + 60)
        # The coinbase commits to the wrong height: rejected by ContextualCheckBlock, before the data is written
        bad = create_block(int(tip, 16), create_coinbase(height + 1), tip_time + 1)
        bad.solve()
        assert_equal(node1.submitblock(bad.serialize().hex()), "bad-cb-height")
        with node1.assert_debug_log(expected_msgs=[f"Block {bad.hash} at height {height} is marked invalid and its data is not available"], unexpected_msgs=["cannot advance"], timeout=10):
            self.announce(node1, bad)
        assert_equal(self.stuck_warnings(node1), [])
        assert not os.path.exists(self.alert_file)

        node1.setmocktime(tip_time + 25 * 3600)
        with node1.assert_debug_log(expected_msgs=[f"Block {bad.hash} at height {height} is marked invalid, so this node cannot advance past height {height - 1}, and its data is not available to check it again"], timeout=10):
            self.announce(node1, bad)
        assert_equal(len(self.stuck_warnings(node1)), 1)
        assert "reconsiderblock" not in self.stuck_warnings(node1)[0]
        self.wait_until(lambda: os.path.exists(self.alert_file))
        node1.disconnect_p2ps()

        self.connect_nodes(0, 1)
        self.generate(node0, 1)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_equal(self.stuck_warnings(node1), [])

    def test_hidden_culprit(self):
        node0, node1 = self.nodes
        self.log.info("An invalid branch with more work elsewhere does not hide a stale mark on the tip's child")
        self.restart_node(1)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        top = node0.getblockcount()
        main = {h: node0.getblockhash(h) for h in range(top - 4, top + 1)}

        # Branch X forks five blocks below the tip and is twenty blocks long: more work than anything after it
        self.disconnect_nodes(0, 1)
        node0.invalidateblock(main[top - 4])
        self.generatetoaddress(node0, 20, ADDRESS_BCRT1_P2WSH_OP_TRUE, sync_fun=self.no_op)
        x_first = node0.getblockhash(top - 4)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        # Both nodes reject X and return to the main line, which node0 extends by three (less work than X)
        node1.invalidateblock(x_first)
        assert_equal(node1.getbestblockhash(), main[top])
        node0.invalidateblock(x_first)
        node0.reconsiderblock(main[top - 4])
        assert_equal(node0.getbestblockhash(), main[top])
        self.generate(node0, 3, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        # The stale mark: the block right above node1's tip. X is still the most-work invalid branch node1 knows.
        culprit = node1.getblockhash(top + 1)
        node1.invalidateblock(culprit)
        assert_equal(node1.getblockcount(), top)
        stale_log = f"Block {culprit} at height {top + 1} is marked invalid but passes validation under the current rules"

        self.log.info("Peers serving the chain report the block on the tip, not the branch with the most work")
        with node1.assert_debug_log(expected_msgs=[stale_log], timeout=10):
            self.connect_nodes(0, 1)
            self.generate(node0, 1, sync_fun=self.no_op)
        assert any(f"reconsiderblock {culprit}" in w for w in self.stuck_warnings(node1)), self.stuck_warnings(node1)

        self.log.info("...and so does a restart")
        self.disconnect_nodes(0, 1)
        with node1.assert_debug_log(expected_msgs=[stale_log]):
            self.restart_node(1)
        assert any(f"reconsiderblock {culprit}" in w for w in self.stuck_warnings(node1)), self.stuck_warnings(node1)

        node1.reconsiderblock(culprit)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(self.stuck_warnings(node1), [])

    def test_presync_path(self):
        node0, node1 = self.nodes
        self.log.info("The check also fires when the headers come through low-work presync")
        self.generate(node0, 2600)
        min_work = node0.getblockheader(node0.getblockhash(node0.getblockcount() - 200))["chainwork"]
        self.restart_node(1, extra_args=[f"-minimumchainwork={min_work}"])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        stale = node1.getblockhash(101)
        self.disconnect_nodes(0, 1)
        node1.invalidateblock(stale)
        assert_equal(node1.getblockcount(), 100)
        stale_log = f"Block {stale} at height 101 is marked invalid but passes validation under the current rules"
        with node1.assert_debug_log(expected_msgs=["Initial headers sync started with peer", "redownload phase", stale_log], timeout=60):
            self.connect_nodes(0, 1)
        assert any(f"reconsiderblock {stale}" in w for w in self.stuck_warnings(node1)), self.stuck_warnings(node1)
        node1.reconsiderblock(stale)
        self.sync_blocks()
        assert_equal(self.stuck_warnings(node1), [])

    def test_pruned_advice(self):
        node0, node1 = self.nodes
        self.log.info("A pruned node is told to -reindex, since it cannot -reindex-chainstate")
        self.disconnect_nodes(0, 1)
        self.restart_node(1)
        tip_time = node1.getblock(node1.getbestblockhash())["time"]
        bad, height = self.invalid_block_on(node1, node1.getblockhash(2))
        assert_equal(node1.submitblock(bad.serialize().hex()), "bad-txns-inputs-missingorspent")
        # Last step of the test: the datadir stays pruned from here on
        with node1.assert_debug_log(expected_msgs=[f"Block {bad.hash} at height {height} is marked invalid and fails validation again (bad-txns-inputs-missingorspent", "-reindex rebuilds it (a pruned node downloads the chain again)"], unexpected_msgs=["-reindex-chainstate"]):
            self.restart_node(1, extra_args=[f"-mocktime={tip_time + 25 * 3600}", "-prune=1"])
        assert_equal(len(self.stuck_warnings(node1)), 1)


if __name__ == '__main__':
    StuckOnInvalidBlockTest(__file__).main()
