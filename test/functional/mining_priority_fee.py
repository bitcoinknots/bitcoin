#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Test the mining fee floor in priority space and CPFP package selection."""

from decimal import Decimal
import time

from test_framework.messages import COIN, COutPoint, CTxIn, CTxInWitness, CTxOut
from test_framework.script_util import PAY_TO_ANCHOR
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet import MiniWallet


MIN_FEE_RATE = 10  # sat/vB


class PriorityFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=0", "-persistmempool=0",
            "-blockprioritysize=1000000", "-blockmaxsize=1000000",
            f"-blockmintxfee={Decimal(MIN_FEE_RATE) / 100000:.8f}",
        ]]

    def template_txids(self):
        # Invalidate the five-second mempool-change template cache.
        self.mock_time += 10
        self.nodes[0].setmocktime(self.mock_time)
        return [tx["txid"] for tx in self.nodes[0].getblocktemplate({"rules": ["segwit"]})["transactions"]]

    def run_test(self):
        self.mock_time = int(time.time())
        self.test_priority_floor()
        self.test_anchor_package()

    def test_priority_floor(self):
        self.log.info("Test the priority fee boundary and ordering")
        node = self.nodes[0]
        wallet = MiniWallet(node)
        payments = []
        for adjustment in (-1, 0, 1):
            tx = wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
            tx.vout[0].nValue -= MIN_FEE_RATE * tx.get_vsize() + adjustment
            tx.rehash()
            node.sendrawtransaction(tx.serialize().hex())
            payments.append(tx)
        below, exact, above = payments
        # MiniWallet selects the oldest equal-value confirmed coins first.
        priorities = [node.getmempoolentry(tx.hash)["currentpriority"] for tx in payments]
        assert_greater_than(priorities[0], priorities[1])
        assert_greater_than(priorities[1], priorities[2])
        template = self.template_txids()
        assert below.hash not in template, "Priority selection bypassed the mining fee floor"
        # Priority order is the opposite of fee order for these same-size txs.
        assert_equal(template, [exact.hash, above.hash])

        self.log.info("Test modified fees, including zero and negative values")
        node.prioritisetransaction(txid=below.hash, fee_delta=1)
        node.prioritisetransaction(txid=exact.hash, fee_delta=-1)
        node.prioritisetransaction(txid=above.hash, fee_delta=-(MIN_FEE_RATE * above.get_vsize() + 2))
        assert_equal(self.template_txids(), [below.hash])

        self.log.info("Test an explicitly configured zero mining fee floor")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-blockmintxfee=0"])
        for tx in payments:
            node.sendrawtransaction(tx.serialize().hex())
        assert_equal(self.template_txids(), [tx.hash for tx in payments])
        node.prioritisetransaction(txid=exact.hash, fee_delta=-(MIN_FEE_RATE * exact.get_vsize()))
        node.prioritisetransaction(txid=above.hash, fee_delta=-(MIN_FEE_RATE * above.get_vsize() + 2))
        assert_equal(self.template_txids(), [below.hash, exact.hash])

    def test_anchor_package(self):
        self.log.info("Test anchor CPFP package selection")
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        wallet = MiniWallet(node)
        parent = wallet.create_self_transfer(version=3, fee_rate=0, confirmed_only=True)["tx"]
        parent.vout.append(CTxOut(0, PAY_TO_ANCHOR))
        parent.rehash()
        sponsor = wallet.get_utxo(confirmed_only=True)

        def make_child(utxo):
            child = wallet.create_self_transfer(version=3, fee_rate=0, utxo_to_spend=utxo)["tx"]
            child.vin.append(CTxIn(COutPoint(parent.sha256, 1)))
            child.wit.vtxinwit.append(CTxInWitness())
            return child

        child = make_child(sponsor)
        required_fee = MIN_FEE_RATE * (parent.get_vsize() + child.get_vsize())
        child.vout[0].nValue -= required_fee - 1
        child.rehash()
        assert_equal(node.submitpackage([parent.serialize().hex(), child.serialize().hex()])["package_msg"], "success")
        assert_equal(node.getmempoolentry(parent.hash)["fees"]["modified"], 0)
        assert_equal(self.template_txids(), [])

        # Replacing the child's independent sponsor spend can leave the parent
        # in the mempool. Priority cannot bypass a positive mining fee floor.
        conflict = wallet.create_self_transfer(utxo_to_spend=sponsor, version=3,
                                               fee=Decimal(required_fee + 1000) / COIN)["tx"]
        node.sendrawtransaction(conflict.serialize().hex())
        assert_equal(set(node.getrawmempool()), {parent.hash, conflict.hash})
        assert_equal(self.template_txids(), [conflict.hash])

        # A new sponsor funds the exact package floor.
        restored = make_child(wallet.get_utxo(confirmed_only=True))
        assert_equal(restored.get_vsize(), child.get_vsize())
        restored.vout[0].nValue -= required_fee
        restored.rehash()
        node.sendrawtransaction(restored.serialize().hex())
        template = self.template_txids()
        assert {parent.hash, restored.hash}.issubset(template)
        assert template.index(parent.hash) < template.index(restored.hash)
        block = node.getblock(self.generate(node, 1)[0])
        assert {parent.hash, restored.hash}.issubset(block["tx"])
        assert_equal(node.gettxout(parent.hash, 1), None)


if __name__ == '__main__':
    PriorityFeeTest(__file__).main()
