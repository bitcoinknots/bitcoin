#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep relocked coinbase payouts out of wallet selection until they mature."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class WalletCoinbaseRelockTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-testactivationheight=coinbaserelock@1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = MiniWallet(node)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(miner, 101)
        recipient = wallet.getnewaddress()
        script = bytes.fromhex(wallet.getaddressinfo(recipient)["scriptPubKey"])
        payout = miner.send_to(from_node=node, scriptPubKey=script, amount=COIN)
        prevout = {"txid": payout["txid"], "vout": payout["sent_vout"]}
        destination = miner.get_address()

        def assert_locked():
            coins = wallet.listunspent(0)
            assert_equal(len(coins), 1)
            assert_equal(coins[0]["txid"], payout["txid"])
            assert_equal(coins[0]["spendable"], False)
            balances = wallet.getbalances()["mine"]
            assert_equal(balances["trusted"], 0)
            assert_equal(balances["immature"], 1)
            assert_raises_rpc_error(-6, "Insufficient funds", wallet.sendtoaddress, destination, Decimal("0.1"), fee_rate=1)
            assert_raises_rpc_error(
                -4, "is a locked coinbase payout", wallet.walletcreatefundedpsbt,
                [prevout], {destination: Decimal("0.1")}, 0,
                {"add_inputs": False, "fee_rate": 1},
            )

        self.log.info("Pending early payouts are visible but unavailable to coin selection")
        assert_locked()
        self.generate(miner, 1)
        payout_height = node.getblockcount()
        assert_locked()

        self.log.info("Wallet restart preserves the payout's balance classification")
        self.restart_node(0)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_locked()

        self.log.info("Wallet selection unlocks at the exact next-block consensus boundary")
        self.generate(miner, 998)
        assert_equal(node.getblockcount(), payout_height + 998)
        assert_locked()
        self.generate(miner, 1)
        assert_equal(node.getblockcount(), payout_height + 999)
        assert_equal(wallet.listunspent()[0]["spendable"], True)
        assert_equal(wallet.getbalances()["mine"]["trusted"], 1)
        assert_equal(wallet.getbalances()["mine"]["immature"], 0)
        txid = wallet.sendtoaddress(destination, Decimal("0.5"), fee_rate=1)
        assert txid in node.getrawmempool()
        self.generate(miner, 1)

        self.log.info("Ordinary change after the payout matures is immediately spendable")
        change = wallet.listunspent()
        assert_equal(len(change), 1)
        assert_equal(change[0]["spendable"], True)
        assert_equal(node.gettxout(change[0]["txid"], change[0]["vout"])["coinbase_relocked"], False)
        child = wallet.sendtoaddress(destination, Decimal("0.1"), fee_rate=1)
        assert child in node.getrawmempool()


if __name__ == "__main__":
    WalletCoinbaseRelockTest(__file__).main()
