#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getminerrevenue: how much of recent miner revenue came from the
subsidy and how much from fees, checked against getblockstats."""

from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COIN
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


def to_sat(btc):
    return int(Decimal(str(btc)) * COIN)


class MinerRevenueTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def expected(self, node, nblocks):
        tip = node.getblockcount()
        heights = range(max(0, tip - min(nblocks, 2016) + 1), tip + 1)
        subsidy = fees = claimed = exceed = 0
        shares = []
        for h in heights:
            stats = node.getblockstats(h, ["subsidy", "totalfee"])
            coinbase = node.getblock(node.getblockhash(h), 2)["tx"][0]
            subsidy += stats["subsidy"]
            fees += stats["totalfee"]
            claimed += sum(to_sat(o["value"]) for o in coinbase["vout"])
            if stats["totalfee"] > stats["subsidy"]:
                exceed += 1
            reward = stats["subsidy"] + stats["totalfee"]
            shares.append(stats["totalfee"] * 10000 // reward if reward else 0)
        ordered = sorted(shares)
        n = len(ordered)
        median = ordered[n // 2] if n % 2 else (ordered[n // 2 - 1] + ordered[n // 2]) // 2
        return {
            "blocks": len(heights),
            "first_height": heights[0],
            "last_height": heights[-1],
            "total_subsidy": subsidy,
            "total_fees": fees,
            "total_claimed": claimed,
            "unclaimed": subsidy + fees - claimed,
            "fee_share_pct": Decimal(fees * 10000 // (subsidy + fees)) / 100 if subsidy + fees else Decimal(0),
            "per_block_fee_share_pct": {
                "min": Decimal(min(shares)) / 100,
                "median": Decimal(median) / 100,
                "max": Decimal(max(shares)) / 100,
            },
            "blocks_fees_exceed_subsidy": exceed,
        }

    def check(self, node, nblocks):
        assert_equal(node.getminerrevenue(nblocks), self.expected(node, nblocks))

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("blocks paid only by the subsidy report a zero fee share")
        self.generate(wallet, 110)
        result = node.getminerrevenue(20)
        assert_equal(result["total_fees"], 0)
        assert_equal(result["fee_share_pct"], 0)
        assert_equal(result["unclaimed"], 0)
        self.check(node, 20)

        self.log.info("a block whose fees exceed its subsidy is counted")
        for _ in range(2):
            tx = wallet.create_self_transfer(fee=Decimal("30"))
            node.sendrawtransaction(tx["hex"], 0)
        self.generate(node, 1)
        result = node.getminerrevenue(1)
        assert_equal(result["total_fees"], 60 * COIN)
        assert_equal(result["blocks_fees_exceed_subsidy"], 1)
        self.check(node, 1)
        self.check(node, 3)

        self.log.info("reward a miner leaves unclaimed is reported, not counted as paid")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=CScript([OP_TRUE]), nValue=25),
                             node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        result = node.getminerrevenue(1)
        assert_equal(result["unclaimed"], 25 * COIN)
        self.check(node, 1)
        self.check(node, 5)

        self.log.info("nblocks is capped at the chain length")
        result = node.getminerrevenue(100000)
        assert_equal(result["blocks"], node.getblockcount() + 1)
        self.check(node, 100000)

        self.log.info("nblocks must be positive")
        assert_raises_rpc_error(-8, "nblocks must be at least 1", node.getminerrevenue, 0)


if __name__ == '__main__':
    MinerRevenueTest(__file__).main()
