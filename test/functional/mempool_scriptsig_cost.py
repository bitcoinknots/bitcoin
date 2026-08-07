#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -scriptsigcost, which reprices scriptSig bytes for policy purposes.

scriptSig bytes live in the non-witness part of a transaction, so consensus
charges them WITNESS_SCALE_FACTOR weight per byte. -scriptsigcost lets a node
price them differently for policy, e.g. 0.25 vB/B extends the witness discount
to pre-segwit inputs.

The critical invariant is that this is policy-only: the reported vsize changes,
the consensus weight never does.
"""

from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, OP_0, OP_DUP, sign_input_legacy
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet import MiniWallet, MiniWalletMode

WITNESS_SCALE_FACTOR = 4
PAD_SPK = CScript([OP_0, b'\x00' * 20])  # zero-sigop outputs, keeps vsize weight-bound
NUM_INPUTS = 5
NUM_OUTPUTS = 50


def vsize_from_weight(weight):
    return (weight + WITNESS_SCALE_FACTOR - 1) // WITNESS_SCALE_FACTOR


class ScriptSigCostTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def build_tx(self, wallet, utxos):
        spk = wallet._scriptPubKey
        priv = wallet._priv_key
        value_in = sum(int(COIN * u['value']) for u in utxos)
        amount = (value_in - 100_000) // NUM_OUTPUTS
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(u['txid'], 16), u['vout'])) for u in utxos]
        tx.vout = [CTxOut(amount, bytearray(PAD_SPK)) for _ in range(NUM_OUTPUTS)]
        # MiniWallet's RAW_P2PK mode uses a P2PKH output script, which needs the
        # pubkey pushed after the signature; a bare P2PK script takes the
        # signature alone. Derive which from the script itself rather than
        # assuming, since it has differed between branches.
        p2pkh = bytes(spk)[:1] == bytes([OP_DUP])
        pub = priv.get_pubkey().get_bytes()
        for i in range(len(tx.vin)):
            tx.vin[i].scriptSig = CScript([pub]) if p2pkh else b''
            sign_input_legacy(tx, i, spk, priv)
        return tx

    def scriptsig_bytes(self, node, raw):
        decoded = node.decoderawtransaction(raw)
        return sum(len(vin['scriptSig']['hex']) // 2 for vin in decoded['vin'])

    def entry(self, raw):
        txid = self.nodes[0].sendrawtransaction(raw)
        return self.nodes[0].getmempoolentry(txid)

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        self.generate(wallet, 150)
        utxos = wallet.get_utxos(mark_as_spent=True, confirmed_only=True)

        raw = self.build_tx(wallet, utxos[:NUM_INPUTS]).serialize().hex()
        sig_bytes = self.scriptsig_bytes(node, raw)
        consensus_weight = node.decoderawtransaction(raw)['weight']
        self.log.info(f"legacy tx: consensus weight={consensus_weight}, "
                      f"scriptSig bytes={sig_bytes}")
        assert_greater_than(sig_bytes, 0)

        self.log.info("default (-scriptsigcost=1.0): no repricing")
        self.restart_node(0, extra_args=['-scriptsigcost=1.0', '-persistmempool=0'])
        e = self.entry(raw)
        assert_equal(e['weight'], consensus_weight)
        assert_equal(e['vsize'], vsize_from_weight(consensus_weight))
        baseline_vsize = e['vsize']

        self.log.info("-scriptsigcost=0.25: witness discount extended to scriptSig")
        self.restart_node(0, extra_args=['-scriptsigcost=0.25', '-persistmempool=0'])
        e = self.entry(raw)
        # Each scriptSig byte drops from 4 weight to 1, ie -3 per byte.
        expected = vsize_from_weight(consensus_weight - 3 * sig_bytes)
        self.log.info(f"   vsize {baseline_vsize} -> {e['vsize']} (expected {expected})")
        assert_equal(e['vsize'], expected)
        assert_greater_than(baseline_vsize, e['vsize'])
        # The whole point: consensus weight is untouched.
        assert_equal(e['weight'], consensus_weight)
        assert_equal(node.decoderawtransaction(raw)['weight'], consensus_weight)

        self.log.info("-scriptsigcost=2.0: scriptSig can also be surcharged")
        self.restart_node(0, extra_args=['-scriptsigcost=2.0', '-persistmempool=0'])
        e = self.entry(raw)
        assert_equal(e['vsize'], vsize_from_weight(consensus_weight + 4 * sig_bytes))
        assert_equal(e['weight'], consensus_weight)

        self.log.info("segwit spends are unaffected (no scriptSig to reprice)")
        sw = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)
        self.generate(sw, 110)
        self.restart_node(0, extra_args=['-scriptsigcost=0.25', '-persistmempool=0'])
        sw.rescan_utxos()
        swtx = sw.create_self_transfer()
        assert_equal(self.scriptsig_bytes(node, swtx['hex']), 0)
        e = self.entry(swtx['hex'])
        assert_equal(e['vsize'], vsize_from_weight(e['weight']))

        # The interaction with -datacarriercost is covered by the unit test
        # policy_tests/calculate_extra_tx_weight_scriptsig: embedded data cannot
        # reach the mempool inside a scriptSig here, because Knots requires
        # scriptSigs to be push-only as a policy rule (scriptsig-not-pushonly).

        self.log.info("all -scriptsigcost behavior verified")


if __name__ == '__main__':
    ScriptSigCostTest(__file__).main()
