#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test long coinbase maturity policy and consensus."""

import time

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_node import ErrorMatch
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

LONG_START_HEIGHT = 2
LONG_ENFORCE_HEIGHT = LONG_START_HEIGHT + COINBASE_MATURITY + 2
DEPLOYMENT = "long_coinbase_maturity"
REJECT_REASON = "bad-txns-premature-spend-of-coinbase"


class LongCoinbaseMaturityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.start_time = int(time.time())
        self.release_time = self.start_time + 10000
        self.extra_args = [[
            f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:{self.release_time}",
            "-checkmempool=1",
        ]]

    def create_next_block(self, txs=None):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(height),
            node.getblockheader(tip)["time"] + 1,
            height=height,
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def assert_deployment(self, active):
        node = self.nodes[0]
        deployment = node.getdeploymentinfo()["deployments"][DEPLOYMENT]
        assert_equal(deployment["type"], "flagday")
        assert_equal(deployment["height"], LONG_ENFORCE_HEIGHT)
        assert_equal(deployment["coinbase_start_height"], LONG_START_HEIGHT)
        assert_equal(deployment["expiry_time"], self.release_time)
        assert_equal(deployment["active"], active)
        assert "height_end" not in deployment
        assert "maturity" not in deployment
        assert_equal(DEPLOYMENT in node.getblocktemplate({"rules": ["segwit"]})["rules"], active)

    def check_rejected_schedules(self):
        node = self.nodes[0]
        self.stop_node(0)
        for args, msg in [
            (["-testcoinbasematuritylong=1:2"], "Invalid format"),
            (["-testcoinbasematuritylong=-1:2:3"], "Invalid start height"),
            (["-testcoinbasematuritylong=1:-2:3"], "Invalid enforce height"),
            (["-testcoinbasematuritylong=1:2:0"], "Invalid release time"),
            (["-testcoinbasematuritylong=99999999999999999999:2:3"], "Invalid start height"),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=msg, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=self.extra_args[0].copy())

    def run_test(self):
        self.check_rejected_schedules()
        node = self.nodes[0]
        node.setmocktime(self.start_time)
        wallet = MiniWallet(node)

        self.generate(wallet, COINBASE_MATURITY)
        self.assert_deployment(active=False)

        self.log.info("Before enforcement, generation spends are relayed at ordinary maturity")
        coinbase_txid = node.getblock(node.getblockhash(1))["tx"][0]
        coinbase_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid))
        node.sendrawtransaction(coinbase_spend["hex"])

        self.log.info("Consensus accepts pre-window rewards at ordinary maturity")
        block = self.create_next_block([coinbase_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT - 3)

        block = self.create_next_block()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT - 2)

        self.log.info("Consensus still accepts covered rewards before the enforcement block")
        coinbase_txid = node.getblock(node.getblockhash(3))["tx"][0]
        coinbase_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid))
        block = self.create_next_block([coinbase_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT - 1)
        self.assert_deployment(active=True)

        self.log.info("From enforcement, covered rewards are held at any depth until release")
        coinbase_txid = node.getblock(node.getblockhash(4))["tx"][0]
        coinbase_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid))
        assert_raises_rpc_error(-26, REJECT_REASON, node.sendrawtransaction, coinbase_spend["hex"])
        block = self.create_next_block([coinbase_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), REJECT_REASON)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT - 1)

        node.setmocktime(self.release_time + 100)
        self.generate(wallet, 5)
        assert node.getblockheader(node.getbestblockhash())["mediantime"] < self.release_time
        self.assert_deployment(active=True)
        assert_raises_rpc_error(-26, REJECT_REASON, node.sendrawtransaction, coinbase_spend["hex"])
        block = self.create_next_block([coinbase_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), REJECT_REASON)

        self.log.info("The rule is released once the parent's median time past reaches the release time")
        release_block = self.generate(wallet, 1)[0]
        assert node.getblockheader(release_block)["mediantime"] >= self.release_time
        self.assert_deployment(active=False)
        coinbase_txid = node.getblock(node.getblockhash(LONG_START_HEIGHT))["tx"][0]
        release_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid))
        node.sendrawtransaction(release_spend["hex"])
        node.sendrawtransaction(coinbase_spend["hex"])
        block = self.create_next_block([release_spend["tx"], coinbase_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    LongCoinbaseMaturityTest(__file__).main()
