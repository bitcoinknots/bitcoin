#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that reported vsize accounts for the -datacarriercost policy.

The policy-adjusted vsize must be reported for both unconfirmed transactions
(from the mempool entry) and confirmed ones (from block undo data).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class PolicyVSizeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-datacarriercost=2', '-datacarriersize=1000', '-txindex']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def base_vsize(self, weight):
        return (weight + 3) // 4

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        data = 'ff' * 80
        funded = node.fundrawtransaction(node.createrawtransaction([], [{'data': data}]))
        signed = node.signrawtransactionwithwallet(funded['hex'])
        txid = node.sendrawtransaction(signed['hex'])

        raw = node.getrawtransaction(txid, True)
        policy_vsize = node.getmempoolentry(txid)['vsize']
        assert_greater_than(policy_vsize, self.base_vsize(raw['weight']))

        self.log.info("Unconfirmed: policy vsize is reported everywhere")
        assert_equal(raw['vsize'], policy_vsize)
        assert_equal(node.getrawmempool(True)[txid]['vsize'], policy_vsize)
        assert_equal(node.gettransaction(txid, True, True)['decoded']['vsize'], policy_vsize)

        self.log.info("Confirmed: policy vsize comes from block undo data")
        self.generate(node, 1)
        assert_equal(node.getrawtransaction(txid, True)['vsize'], policy_vsize)
        assert_equal(node.getrawtransaction(txid, 2)['vsize'], policy_vsize)
        assert_equal(node.gettransaction(txid, True, True)['decoded']['vsize'], policy_vsize)

        self.log.info("signrawtransactionwithwallet feerate uses policy vsize")
        funded2 = node.fundrawtransaction(node.createrawtransaction([], [{'data': data}]))
        signed2 = node.signrawtransactionwithwallet(funded2['hex'])
        base_feerate = funded2['fee'] * 1000 / self.base_vsize(node.decoderawtransaction(signed2['hex'])['weight'])
        assert_greater_than(base_feerate, signed2['feerate'])

        self.log.info("getrawtransaction reports unreadable undo data")

        def move_block_file(old, new):
            (node.blocks_path / old).rename(node.blocks_path / new)

        move_block_file('rev00000.dat', 'rev_wrong')
        assert_raises_rpc_error(-32603, "Undo data expected but can't be read.", node.getrawtransaction, txid, 2)

        self.log.info("vsize is omitted rather than reported without policy weight")
        assert 'vsize' not in node.getrawtransaction(txid, True)
        assert 'vsize' not in node.gettransaction(txid, True, True)['decoded']
        move_block_file('rev_wrong', 'rev00000.dat')

        assert_equal(node.getrawtransaction(txid, True)['vsize'], policy_vsize)


if __name__ == '__main__':
    PolicyVSizeTest(__file__).main()
