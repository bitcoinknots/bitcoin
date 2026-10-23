#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A legacy maturity marker cannot certify the rolling rule, even after expiry."""
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

EXPIRY = 1819756800
LEGACY = ["-testcoinbasematuritylong=2:2:122", "-checkmempool=1", f"-mocktime={EXPIRY + 1000}"]
ROLLING = LEGACY + [f"-testcoinbasematuritylongexpiry={EXPIRY}"]


class RollingCoinbaseUpgradeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [LEGACY]

    def run_test(self):
        node = self.nodes[0]
        node.setmocktime(EXPIRY + 1000)
        wallet = MiniWallet(node)

        def block(txs=None, timestamp=EXPIRY - 10000):
            tip = node.getbestblockhash()
            height = node.getblockcount() + 1
            result = create_block(int(tip, 16), create_coinbase(height, script_pubkey=wallet.get_output_script()),
                                  max(timestamp, node.getblockheader(tip)["time"] + 1), height=height, txlist=txs)
            add_witness_commitment(result)
            result.solve()
            assert_equal(node.submitblock(result.serialize().hex()), None)
            return result

        for _ in range(130):
            block()
        for _ in range(6):
            block(timestamp=EXPIRY)
        while node.getblockcount() < 234:
            block(timestamp=EXPIRY + 100)
        wallet.rescan_utxos()
        reward = node.getblock(node.getblockhash(135))["tx"][0]
        spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=reward))
        self.log.info("Legacy consensus accepts a depth-100 pre-expiry reward after expiry")
        invalid = block([spend["tx"]], EXPIRY + 100)
        invalid_tip = block(timestamp=EXPIRY + 100)
        node.invalidateblock(invalid.hash)
        valid = block(timestamp=EXPIRY + 101)
        node.reconsiderblock(invalid.hash)
        assert_equal(node.getbestblockhash(), invalid_tip.hash)

        self.log.info("The new marker forces validation of history already certified by the old marker")
        with node.assert_debug_log(["Chainstate revalidation: rewinding 235 block(s)"]):
            self.restart_node(0, extra_args=ROLLING)
        assert_equal(node.getbestblockhash(), valid.hash)
        assert_equal(node.getrawmempool(), [])
        tips = {tip["hash"]: tip["status"] for tip in node.getchaintips()}
        assert_equal(tips[invalid_tip.hash], "invalid")
        self.restart_node(0, extra_args=ROLLING)
        assert_equal(node.getbestblockhash(), valid.hash)


if __name__ == "__main__":
    RollingCoinbaseUpgradeTest(__file__).main()
