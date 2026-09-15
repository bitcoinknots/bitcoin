#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Coinbase Curfew: a coinbase created at or after the activation height
stays unspendable until the spending block's parent median-time-past is
curfew_seconds past its own block's, however many blocks that takes."""

import time

from test_framework.blocktools import COINBASE_MATURITY, add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

CURFEW_HEIGHT = 150
CURFEW_SECONDS = 20000
FAST = 60    # block spacing well under the curfew's calendar assumptions
SLOW = 600


class CoinbaseCurfewTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-curfewheight={CURFEW_HEIGHT}", f"-curfewseconds={CURFEW_SECONDS}"]]

    def mine(self, wallet, count, spacing):
        for _ in range(count):
            self.mocktime += spacing
            self.nodes[0].setmocktime(self.mocktime)
            self.generate(wallet, 1, sync_fun=self.no_op)

    def mediantime(self, node, height):
        return node.getblockheader(node.getblockhash(height))["mediantime"]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        coinbase_txid = lambda h: node.getblock(node.getblockhash(h))["tx"][0]
        self.mocktime = int(time.time())

        self.log.info("mine to just below activation at 10-minute spacing, then 99 blocks at 1-minute spacing")
        self.mine(wallet, CURFEW_HEIGHT - 1, SLOW)
        self.mine(wallet, COINBASE_MATURITY - 1, FAST)
        assert_equal(node.getblockcount(), CURFEW_HEIGHT + COINBASE_MATURITY - 2)

        self.log.info("a coinbase created before activation needs only ordinary maturity: the curfew is not retroactive")
        pre_utxo = wallet.get_utxo(txid=coinbase_txid(CURFEW_HEIGHT - 1))
        wallet.send_self_transfer(from_node=node, utxo_to_spend=pre_utxo)
        self.mine(wallet, 1, FAST)

        self.log.info("a coinbase created at activation reaches ordinary maturity but is still under curfew")
        created = CURFEW_HEIGHT
        assert_equal(node.getblockcount() + 1 - created, COINBASE_MATURITY)
        curfew_tx = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid(created)))
        assert_raises_rpc_error(-26, "bad-txns-coinbase-curfew", node.sendrawtransaction, curfew_tx["hex"])

        self.log.info("a block including that spend is invalid")
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1),
                             node.getblockheader(tip)["time"] + 1, txlist=[curfew_tx["tx"]])
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "bad-txns-coinbase-curfew")

        self.log.info("it unlocks once the parent's median-time-past reaches the coinbase's plus the curfew, and not before")
        target = self.mediantime(node, created) + CURFEW_SECONDS
        blocks_waited = 0
        while self.mediantime(node, node.getblockcount()) < target:
            assert_raises_rpc_error(-26, "bad-txns-coinbase-curfew", node.sendrawtransaction, curfew_tx["hex"])
            self.mine(wallet, 1, SLOW)
            blocks_waited += 1
        assert blocks_waited > 0
        txid = node.sendrawtransaction(curfew_tx["hex"])
        assert_equal(node.getrawmempool(), [txid])

        self.log.info("and a block including it is valid")
        self.mine(wallet, 1, SLOW)
        assert txid in node.getblock(node.getbestblockhash())["tx"]


if __name__ == '__main__':
    CoinbaseCurfewTest(__file__).main()
