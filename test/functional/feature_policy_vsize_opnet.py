#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Policy vsize must match before and after confirmation for witness datacarrier.

The mempool computes datacarrier bytes with the input witness available, which
lets OPNet spends be recognised. The confirmed path reconstructs the same value
from block undo data. Both must agree.
"""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_2DROP,
    OP_DROP,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class PolicyVSizeOPNetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            '-datacarriercost=2',
            '-acceptnonstddatacarrier=1',
            '-datacarrierfullcount',
            '-txindex',
        ]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)

        minimal_script = CScript([OP_2DROP, OP_DROP, b'op', OP_DROP, OP_1])
        internal_key = b'\x01' * 32
        tap = taproot_construct(internal_key, [("leaf", minimal_script), ("dummy", CScript([OP_1]))])
        leaf = tap.leaves["leaf"]
        control_block = bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch
        assert_equal(len(control_block), 65)

        utxo = self.wallet.get_utxo()
        funding_tx = CTransaction()
        funding_tx.vin = [CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout']))]
        funding_value = int(utxo['value'] * 100_000_000) - 1000
        funding_tx.vout = [CTxOut(funding_value, tap.scriptPubKey)]
        funding_tx.version = 2
        self.wallet.sign_tx(funding_tx)
        funding_tx.rehash()
        node.sendrawtransaction(funding_tx.serialize().hex())
        self.generate(node, 1)

        spend_tx = CTransaction()
        spend_tx.version = 2
        spend_tx.vin = [CTxIn(COutPoint(int(funding_tx.hash, 16), 0))]
        spend_tx.vout = [CTxOut(funding_value - 1000, tap.scriptPubKey)]
        spend_tx.wit.vtxinwit = [CTxInWitness()]
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [
            b'',
            b'',
            b'',
            bytes(minimal_script),
            control_block,
        ]
        txid = node.sendrawtransaction(spend_tx.serialize().hex())

        unconfirmed_vsize = node.getrawtransaction(txid, True)['vsize']
        mempool_vsize = node.getmempoolentry(txid)['vsize']
        self.log.info(f"unconfirmed getrawtransaction vsize={unconfirmed_vsize} mempoolentry vsize={mempool_vsize}")
        assert_equal(unconfirmed_vsize, mempool_vsize)

        self.generate(node, 1)
        confirmed_vsize = node.getrawtransaction(txid, True)['vsize']
        self.log.info(f"confirmed getrawtransaction vsize={confirmed_vsize}")

        assert_equal(confirmed_vsize, unconfirmed_vsize)


if __name__ == '__main__':
    PolicyVSizeOPNetTest(__file__).main()
