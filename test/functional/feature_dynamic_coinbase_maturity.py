#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""Verify dynamic coinbase maturity after RDTS expiry."""

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

EXPIRY = 1819756800
MATURITY = 150


class DynamicCoinbaseMaturityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-testcoinbasematuritylong=2:2:122",
            f"-testcoinbasematuritylongexpiry={EXPIRY}",
            "-testdynamiccbm=1",
            f"-testdynamiccbminitial={MATURITY}",
            "-checkmempool=1",
            f"-mocktime={EXPIRY + 3600}",
        ]]

    def next_block(self, txs=None):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        block = create_block(
            int(tip, 16),
            create_coinbase(height, script_pubkey=self.wallet.get_output_script()),
            max(EXPIRY + 3600, node.getblockheader(tip)["time"] + 1),
            height=height,
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def submit(self, block, expected=None):
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), expected)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        node.setmocktime(EXPIRY + 3600)

        self.log.info("Advance median time past RDTS expiry")
        for _ in range(14):
            self.submit(self.next_block())

        assert node.getblockheader(node.getbestblockhash())["mediantime"] >= EXPIRY

        self.log.info("Mine a post-expiry coinbase")
        coinbase_height = node.getblockcount() + 1
        self.submit(self.next_block())
        coinbase_txid = node.getblock(node.getblockhash(coinbase_height))["tx"][0]

        self.log.info("Advance beyond ordinary 100-block maturity")
        for _ in range(120):
            self.submit(self.next_block())

        self.wallet.rescan_utxos()
        spend = self.wallet.create_self_transfer(
            utxo_to_spend=self.wallet.get_utxo(txid=coinbase_txid)
        )

        self.log.info("Verify mempool rejects immature DCBM reward")
        assert_raises_rpc_error(
            -26,
            "bad-txns-premature-spend-of-coinbase",
            node.sendrawtransaction,
            spend["hex"],
        )

        self.log.info("Verify block consensus rejects immature DCBM reward")
        self.submit(
            self.next_block([spend["tx"]]),
            "bad-txns-premature-spend-of-coinbase",
        )

        assert_equal(node.getblockcount(), coinbase_height + 120)
        self.log.info("Advance to one block before maturity")
        for _ in range(MATURITY - 122):
            self.submit(self.next_block())

        assert_equal(node.getblockcount(), coinbase_height + MATURITY - 2)

        self.log.info("Verify depth 149 is rejected")
        assert_raises_rpc_error(
            -26, "bad-txns-premature-spend-of-coinbase",
            node.sendrawtransaction, spend["hex"],
        )
        self.submit(
            self.next_block([spend["tx"]]),
            "bad-txns-premature-spend-of-coinbase",
        )

        self.log.info("Advance to maturity boundary")
        self.submit(self.next_block())

        assert_equal(node.getblockcount(), coinbase_height + MATURITY - 1)

        self.log.info("Verify depth 150 is accepted")
        node.sendrawtransaction(spend["hex"])
        self.submit(self.next_block([spend["tx"]]))
        assert_equal(node.getblockcount(), coinbase_height + MATURITY)

        self.log.info("DCBM functional boundary checks passed")


if __name__ == "__main__":
    DynamicCoinbaseMaturityTest(__file__).main()
