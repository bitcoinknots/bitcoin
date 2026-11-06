#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test replaced_by_txid on malleated transactions in a wallet from an older version.

Older versions stored replaced_by_txid only on the bumped transaction, and
copied it to its malleations in memory on every load. Loading such a wallet
must give the malleations the marker, so they cannot be bumped again.
"""

import shutil

from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletMalleatedUpgradeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, versions=[None, 280000])
        self.start_nodes()

    def malleate_tx(self, wallet, txid):
        tx = tx_from_hex(wallet.getrawtransaction(txid))
        for txin in tx.vin:
            txin.scriptSig = b""
        for wit in tx.wit.vtxinwit:
            wit.scriptWitness.stack.clear()
        unsigned_tx = tx.serialize_without_witness().hex()
        malleated_tx = wallet.signrawtransactionwithwallet(hexstring=unsigned_tx, sighashtype="ALL|ANYONECANPAY")["hex"]
        malleated_txid = wallet.decoderawtransaction(malleated_tx)["txid"]
        assert malleated_txid != txid
        return malleated_tx, malleated_txid

    def send_and_malleate(self, wallet, miner, utxos):
        """Send a transaction, then put a malleation of it into the wallet and back into the mempool"""
        node = self.nodes[1]
        txid = wallet.send(outputs=[{miner.getnewaddress(): 0.4 * len(utxos)}], inputs=utxos, add_inputs=False, fee_rate=1)["txid"]
        malleated_tx, malleated_txid = self.malleate_tx(wallet, txid)
        blockhash = self.generateblock(node, miner.getnewaddress(), [malleated_tx], sync_fun=self.no_op)["hash"]
        # The wallet must see the malleation before the bump, as in a real wallet
        node.syncwithvalidationinterfacequeue()
        node.invalidateblock(blockhash)
        node.syncwithvalidationinterfacequeue()
        return txid, malleated_txid

    def run_test(self):
        node, old_node = self.nodes

        old_node.createwallet(wallet_name="miner", descriptors=self.options.descriptors)
        miner = old_node.get_wallet_rpc("miner")
        old_node.createwallet(wallet_name="w", descriptors=self.options.descriptors)
        wallet = old_node.get_wallet_rpc("w")

        self.generatetoaddress(old_node, 101, miner.getnewaddress())
        # Only transactions with non-witness inputs can be malleated
        for _ in range(3):
            miner.sendtoaddress(wallet.getnewaddress(address_type="legacy"), 0.5)
        self.generate(old_node, 1)
        utxos = [{"txid": u["txid"], "vout": u["vout"]} for u in wallet.listunspent()]
        assert_equal(len(utxos), 3)

        # The new node only needs the chain up to here
        self.disconnect_nodes(0, 1)

        self.log.info("With the old version, bump a transaction that has a malleation")
        txid, malleated_txid = self.send_and_malleate(wallet, miner, utxos[:2])
        bumped_txid = wallet.bumpfee(txid, fee_rate=10)["txid"]
        assert "replaced_by_txid" not in wallet.gettransaction(malleated_txid)

        self.log.info("With the old version, bump the malleation instead of the original")
        txid2, malleated_txid2 = self.send_and_malleate(wallet, miner, utxos[2:])
        bumped_txid2 = wallet.bumpfee(malleated_txid2, fee_rate=10)["txid"]
        assert "replaced_by_txid" not in wallet.gettransaction(txid2)

        old_node.unloadwallet("w")
        self.stop_node(1)

        self.log.info("Load the wallet with the new version")
        shutil.copytree(old_node.wallets_path / "w", node.wallets_path / "w")
        node.loadwallet("w")
        wallet = node.get_wallet_rpc("w")
        assert_equal(wallet.gettransaction(txid)["replaced_by_txid"], bumped_txid)
        assert_equal(wallet.gettransaction(malleated_txid)["replaced_by_txid"], bumped_txid)
        assert_equal(wallet.gettransaction(malleated_txid2)["replaced_by_txid"], bumped_txid2)
        assert_equal(wallet.gettransaction(txid2)["replaced_by_txid"], bumped_txid2)

        self.log.info("Bumping either variant again is refused")
        assert_raises_rpc_error(-4, f"Cannot bump transaction {malleated_txid} which was already bumped by transaction {bumped_txid}",
                                wallet.bumpfee, malleated_txid, fee_rate=20)
        assert_raises_rpc_error(-4, f"Cannot bump transaction {txid2} which was already bumped by transaction {bumped_txid2}",
                                wallet.bumpfee, txid2, fee_rate=20)


if __name__ == '__main__':
    WalletMalleatedUpgradeTest(__file__).main()
