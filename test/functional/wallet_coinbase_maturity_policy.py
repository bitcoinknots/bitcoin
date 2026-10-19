#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pre-start wallet rewards must respect the unchanged long-maturity policy."""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class CoinbaseMaturityPolicyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--after-expiry", action="store_true")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-testcoinbasematuritylong=2:2:122:120"]]
        if self.options.after_expiry:
            self.extra_args[0] += ["-testcoinbasematuritylongexpiry=1800000000", "-mocktime=1800010000"]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("pre_start")
        wallet = node.get_wallet_rpc("pre_start")
        miner = MiniWallet(node)
        if self.options.after_expiry:
            # Move beyond both activation and the time expiry, then mine a covered wallet reward.
            self.generate(miner, 11)
            assert node.getblockheader(node.getbestblockhash())["mediantime"] >= 1800000000
            assert_equal(node.getdeploymentinfo()["deployments"]["long_coinbase_maturity"]["active"], False)
        reward = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]
        coinbase = node.getblock(reward)["tx"][0]
        self.generate(miner, 100)
        target = wallet.getnewaddress()
        raw = wallet.createrawtransaction([{"txid": coinbase, "vout": 0}], {target: Decimal("49.999")})
        signed = wallet.signrawtransactionwithwallet(raw)["hex"]

        self.log.info("At depth 101, pre-start reward stays immature while policy rejects it")
        assert_equal(wallet.getbalances()["mine"]["trusted"], 0)
        assert_equal(wallet.getbalances()["mine"]["immature"], 50)
        assert_equal(wallet.listunspent(), [])
        assert_equal(node.testmempoolaccept([signed])[0]["allowed"], False)
        assert_raises_rpc_error(-6, "Insufficient funds", wallet.sendtoaddress, target, 1)
        assert_equal(node.getrawmempool(), [])
        assert_equal(wallet.getbalances()["mine"]["immature"], 50)

        self.generate(miner, 19)
        assert_equal(node.testmempoolaccept([signed])[0]["allowed"], True)
        assert_equal(wallet.getbalances()["mine"]["trusted"], 0)
        self.generate(miner, 1)
        self.log.info("At depth 121, every available reward can enter the mempool")
        assert_equal(wallet.getbalances()["mine"]["trusted"], 50)
        assert_equal(wallet.getbalances()["mine"]["immature"], 0)
        coins = wallet.listunspent()
        assert_equal(len(coins), 1)
        assert_equal(coins[0]["spendable"], True)
        assert_equal(node.testmempoolaccept([signed])[0]["allowed"], True)
        txid = wallet.sendtoaddress(target, 1)
        assert_equal(node.getrawmempool(), [txid])


if __name__ == "__main__":
    CoinbaseMaturityPolicyTest(__file__).main()
