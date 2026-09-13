#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Coinbase Curfew: an extra lock depth on coinbase outputs, beyond
ordinary coinbase maturity, enforced from a configured activation height."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# Short values so the test doesn't need to mine tens of thousands of blocks.
CURFEW_HEIGHT = 250
CURFEW_DEPTH = 20  # additional confirmations beyond ordinary 100-block maturity


class CoinbaseCurfewTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-curfewheight={CURFEW_HEIGHT}", f"-curfewdepth={CURFEW_DEPTH}"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        coinbase_txid = lambda h: node.getblock(node.getblockhash(h))['tx'][0]

        self.log.info("mine coinbases the wallet can track, up to just before curfew activates")
        self.generate(wallet, CURFEW_HEIGHT - 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), CURFEW_HEIGHT - 1)

        self.log.info("before curfew activation, ordinary 100-block maturity is enough")
        pre_curfew_utxo = wallet.get_utxo(txid=coinbase_txid(1))
        wallet.send_self_transfer(from_node=node, utxo_to_spend=pre_curfew_utxo)
        self.generate(wallet, 1, sync_fun=self.no_op)  # confirms at CURFEW_HEIGHT
        assert_equal(node.getblockcount(), CURFEW_HEIGHT)

        self.log.info("past curfew activation, a coinbase that just met ordinary maturity is still locked")
        # Mine until a coinbase minted right at the last pre-curfew height has
        # exactly 100 confirmations: mature under ordinary rules, but not yet
        # under Coinbase Curfew, which additionally requires CURFEW_DEPTH more.
        target_coinbase_height = CURFEW_HEIGHT - 1
        blocks_to_100_confs = 100 - (node.getblockcount() - target_coinbase_height + 1)
        self.generate(wallet, blocks_to_100_confs, sync_fun=self.no_op)

        curfew_utxo = wallet.get_utxo(txid=coinbase_txid(target_coinbase_height))
        curfew_tx = wallet.create_self_transfer(utxo_to_spend=curfew_utxo)
        assert_raises_rpc_error(-26, "bad-txns-coinbase-curfew",
                                node.sendrawtransaction, curfew_tx['hex'])

        self.log.info("one block short of the full curfew depth, it is still locked")
        self.generate(wallet, CURFEW_DEPTH - 1, sync_fun=self.no_op)
        assert_raises_rpc_error(-26, "bad-txns-coinbase-curfew",
                                node.sendrawtransaction, curfew_tx['hex'])

        self.log.info("once the full curfew depth passes, the coinbase spends normally")
        self.generate(wallet, 1, sync_fun=self.no_op)
        txid = node.sendrawtransaction(curfew_tx['hex'])
        assert_equal(node.getrawmempool(), [txid])


if __name__ == '__main__':
    CoinbaseCurfewTest(__file__).main()
