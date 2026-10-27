#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Persist explicit fee deltas, never automatic sub-dust penalties."""

from decimal import Decimal

from test_framework.messages import COIN, COutPoint, CTxIn, CTxInWitness, CTxOut
from test_framework.script_util import PAY_TO_ANCHOR
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class SubDustPersistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1", "-subdustfeepenalty=1"]]

    def restart_policy(self, *, legacy, standard=False, rate=3, enabled=True):
        self.restart_node(0, extra_args=[
            f"-acceptnonstdtxn={int(not standard)}", "-persistmempool=1",
            f"-persistmempoolv1={int(legacy)}", "-mempooltruc=enforce",
            "-minrelaytxfee=0.00001000",
            f"-dustrelayfee={Decimal(rate) / 100000:.8f}",
            f"-subdustfeepenalty={int(enabled)}",
        ])

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        for legacy in [False, True]:
            self.log.info(f"Test ordinary dust persistence, legacy format={legacy}")
            self.restart_policy(legacy=legacy)
            wallet.rescan_utxos()
            # Both signs, and both in-mempool and absent transactions, must
            # retain their explicit deltas without accumulating the penalty.
            submitted = []
            absent = []
            for delta in [-100, 100]:
                tx = wallet.create_self_transfer(fee_rate=Decimal("0.001"), confirmed_only=True)["tx"]
                tx.vout.append(CTxOut(0, PAY_TO_ANCHOR))
                tx.rehash()
                node.prioritisetransaction(txid=tx.hash, fee_delta=delta)
                node.sendrawtransaction(tx.serialize().hex())
                submitted.append((tx.hash, delta))
                other = wallet.create_self_transfer(confirmed_only=True)["txid"]
                node.prioritisetransaction(txid=other, fee_delta=delta)
                absent.append((other, delta))

            for rate, enabled in [(3, True), (3, True), (6, True), (3, False), (3, True)]:
                self.restart_policy(legacy=legacy, rate=rate, enabled=enabled)
                penalty = 80 * rate if enabled else 0
                for txid, delta in submitted:
                    fees = node.getmempoolentry(txid)["fees"]
                    assert_equal(fees["modified"] - fees["base"], Decimal(delta - penalty) / COIN)
                priorities = node.getprioritisedtransactions()
                for txid, delta in submitted + absent:
                    assert_equal(priorities[txid]["fee_delta"], delta)
                for txid, _ in absent:
                    assert_equal(priorities[txid]["in_mempool"], False)
            self.generate(node, 1)
            for txid, delta in absent:
                node.prioritisetransaction(txid=txid, fee_delta=-delta)

            self.log.info(f"Test ephemeral package resubmission, legacy format={legacy}")
            self.restart_policy(legacy=legacy, standard=True)
            wallet.rescan_utxos()
            parent = wallet.create_self_transfer(version=3, fee_rate=0, confirmed_only=True)["tx"]
            parent.vout.append(CTxOut(0, PAY_TO_ANCHOR))
            parent.rehash()
            child = wallet.create_self_transfer_multi(version=3, fee_per_output=10000, confirmed_only=True)["tx"]
            child.vin.append(CTxIn(COutPoint(parent.sha256, 1)))
            child.wit.vtxinwit.append(CTxInWitness())
            child.rehash()
            package = [parent.serialize().hex(), child.serialize().hex()]
            assert_equal(node.submitpackage(package)["package_msg"], "success")
            for rate, enabled in [(3, True), (3, True), (6, True), (3, False), (3, True)]:
                self.restart_policy(legacy=legacy, standard=True, rate=rate, enabled=enabled)
                # Reload evaluates transactions individually: the zero-fee
                # parent cannot reload, but must not acquire a manual delta.
                assert_equal(node.getrawmempool(), [])
                assert_equal(node.getprioritisedtransactions(), {})
                for delta in [-1, 1]:
                    node.prioritisetransaction(txid=parent.hash, fee_delta=delta)
                    self.restart_policy(legacy=legacy, standard=True, rate=rate, enabled=enabled)
                    assert_equal(node.getprioritisedtransactions()[parent.hash]["fee_delta"], delta)
                    assert node.submitpackage(package)["package_msg"] != "success"
                    assert_equal(node.getrawmempool(), [])
                    node.prioritisetransaction(txid=parent.hash, fee_delta=-delta)
                assert_equal(node.submitpackage(package)["package_msg"], "success")
                penalty = 80 * rate if enabled else 0
                assert_equal(node.getmempoolentry(parent.hash)["fees"]["modified"], -Decimal(penalty) / COIN)
            self.generate(node, 1)


if __name__ == '__main__':
    SubDustPersistTest(__file__).main()
