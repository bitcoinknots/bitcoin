#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify analyzepsbt's estimated vsize follows -scriptsigcost.

node/psbt.cpp calls CalculateExtraTxWeight() for its size/feerate estimate, so a
scriptSig discount has to show up there too. rpc_psbt.py only ever runs with the
neutral default, so that call site is otherwise untested with a real discount.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class PsbtScriptSigCostTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def analyze(self):
        node = self.nodes[0]
        addr = node.getnewaddress(address_type='legacy')
        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        ins = [{'txid': u['txid'], 'vout': u['vout']} for u in utxos[:3]]
        total = sum(u['amount'] for u in utxos[:3])
        psbt = node.createpsbt(ins, [{addr: total - 1}])
        filled = node.walletprocesspsbt(psbt)['psbt']
        res = node.analyzepsbt(filled)
        return res['estimated_vsize']

    def run_test(self):
        node = self.nodes[0]
        # legacy address so the spends carry a scriptSig
        addr = node.getnewaddress(address_type='legacy')
        self.generatetoaddress(node, 110, addr)

        self.restart_node(0, extra_args=['-scriptsigcost=1.0'])
        base = self.analyze()
        self.log.info(f"estimated_vsize at -scriptsigcost=1.0  : {base}")

        self.restart_node(0, extra_args=['-scriptsigcost=0.25'])
        disc = self.analyze()
        self.log.info(f"estimated_vsize at -scriptsigcost=0.25 : {disc}")

        self.restart_node(0, extra_args=['-scriptsigcost=2.0'])
        sur = self.analyze()
        self.log.info(f"estimated_vsize at -scriptsigcost=2.0  : {sur}")

        assert_greater_than(base, disc)
        assert_greater_than(sur, base)
        self.log.info("analyzepsbt estimate tracks -scriptsigcost")


if __name__ == '__main__':
    PsbtScriptSigCostTest(__file__).main()
