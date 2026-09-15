#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getcoinbasepayouts: coinbase value by output count, and block
concentration on primary payout scripts."""

from decimal import Decimal

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, create_coinbase, script_BIP34_coinbase_height
from test_framework.messages import COIN, CTxOut
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

POOL_B = CScript([OP_TRUE, OP_TRUE])
POOL_C = CScript([OP_TRUE, OP_TRUE, OP_TRUE])


class CoinbasePayoutsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def submit(self, node, outputs, tag):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        coinbase = create_coinbase(height)
        coinbase.vout = [CTxOut(value, script) for value, script in outputs]
        coinbase.vin[0].scriptSig = CScript(bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([tag])))
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("20 blocks paying one address, 10 paying pool B across 10 outputs, 5 paying mostly pool C")
        self.generatetoaddress(node, 20, ADDRESS_BCRT1_UNSPENDABLE)
        for _ in range(10):
            self.submit(node, [(5 * COIN, POOL_B)] * 10, b"/PoolB/")
        for _ in range(5):
            others = [(5 * COIN, CScript([OP_TRUE] * (4 + i))) for i in range(4)]
            self.submit(node, [(30 * COIN, POOL_C)] + others, b"/PoolC/")

        result = node.getcoinbasepayouts(35)
        assert_equal(result["blocks"], 35)
        assert_equal(result["first_height"], 1)
        assert_equal(result["last_height"], 35)
        assert_equal(result["total_value"], 35 * 50 * COIN)

        self.log.info("coinbase value grouped by payout output count")
        buckets = {b["outputs"]: b for b in result["by_output_count"]}
        assert_equal(list(buckets), ["0-1", "2-9", "10-49", "50+"])
        assert_equal((buckets["0-1"]["blocks"], buckets["0-1"]["value"]), (20, 1000 * COIN))
        assert_equal((buckets["2-9"]["blocks"], buckets["2-9"]["value"]), (5, 250 * COIN))
        assert_equal((buckets["10-49"]["blocks"], buckets["10-49"]["value"]), (10, 500 * COIN))
        assert_equal((buckets["50+"]["blocks"], buckets["50+"]["value"]), (0, 0))
        # RPC numbers arrive as Decimal, which never compares equal to a float literal.
        assert_equal(buckets["0-1"]["value_share_pct"], Decimal("57.14"))
        assert_equal(buckets["10-49"]["value_share_pct"], Decimal("28.57"))
        assert_equal(buckets["2-9"]["value_share_pct"], Decimal("14.28"))

        self.log.info("blocks grouped by primary payout script, most blocks first")
        assert_equal(result["distinct_primary_scripts"], 3)
        assert_equal(result["effective_primary_scripts"], Decimal("2.33"))
        assert_equal(result["largest_primary_share_pct"], Decimal("57.14"))
        a, b, c = result["primary_scripts"]
        assert_equal(a["address"], ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal((a["blocks"], a["share_pct"], a["mean_outputs"], a["top_tag"]), (20, Decimal("57.14"), 1, ""))
        assert_equal((b["script"], b["blocks"], b["mean_outputs"], b["top_tag"]), (POOL_B.hex(), 10, 10, "/PoolB/"))
        assert "address" not in b
        assert_equal((c["script"], c["blocks"], c["mean_outputs"], c["top_tag"]), (POOL_C.hex(), 5, 5, "/PoolC/"))
        assert_equal(b["value"], 500 * COIN)

        self.log.info("nblocks is capped at the chain length")
        assert_equal(node.getcoinbasepayouts(100000)["blocks"], node.getblockcount() + 1)

        self.log.info("nblocks must be positive")
        assert_raises_rpc_error(-8, "nblocks must be at least 1", node.getcoinbasepayouts, 0)


if __name__ == '__main__':
    CoinbasePayoutsTest(__file__).main()
