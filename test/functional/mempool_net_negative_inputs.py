#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test net-negative input policy (-rejectnetnegativeinputs)."""

from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class TapscriptDustTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-rejectnetnegativeinputs=1"]]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_script_path_dust_rejected()
        self.test_script_path_adequate_value_accepted()
        self.test_key_path_exempt()
        self.test_disabled()

    def sign_tapscript(self, tx):
        """Add MiniWallet tapscript witness to all inputs."""
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        leaf_info = list(self.wallet._taproot_info.leaves.values())[0]
        for w in tx.wit.vtxinwit:
            w.scriptWitness.stack = [
                leaf_info.script,
                bytes([leaf_info.version | self.wallet._taproot_info.negflag]) + self.wallet._taproot_info.internal_pubkey,
            ]

    def fund_tiny_utxo(self, tiny_value=600):
        """Create a confirmed tiny taproot UTXO. Returns (txid, vout)."""
        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        change = int(utxo["value"] * COIN) - tiny_value - 1000
        tx.vout = [
            CTxOut(tiny_value, self.wallet.get_output_script()),
            CTxOut(change, self.wallet.get_output_script()),
        ]
        self.wallet.sign_tx(tx)
        self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        self.generate(self.nodes[0], 1)
        txid = tx.rehash()
        return {"txid": txid, "vout": 0, "value": tiny_value / COIN}

    def test_script_path_dust_rejected(self):
        self.log.info("Test: script-path spend where input cost > input value is rejected")
        # Create a tiny UTXO (600 sats) and a large UTXO
        tiny_utxo = self.fund_tiny_utxo(tiny_value=600)
        large_utxo = self.wallet.get_utxo()

        # Spend both: large input pays a high fee so the per-input cost
        # of the tiny input's witness exceeds 600 sats.
        # Witness per input ~35 bytes, non-witness overhead 41 bytes.
        # Input weight ~199 wu = ~50 vbytes.
        # Need feerate > 600/50 = 12 sat/vB.
        # Use ~100 sat/vB to be safe → fee ~15000 for a ~150 vB tx.
        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(COutPoint(int(tiny_utxo["txid"], 16), tiny_utxo["vout"])),
            CTxIn(COutPoint(int(large_utxo["txid"], 16), large_utxo["vout"])),
        ]
        large_value = int(large_utxo["value"] * COIN)
        total_in = large_value + 600
        fee = 15000  # ~100 sat/vB for a ~150 vB tx
        tx.vout = [CTxOut(total_in - fee, self.wallet.get_output_script())]
        self.sign_tapscript(tx)

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert_equal(result[0]["reject-reason"], "bad-txns-input-netnegative")

    def test_script_path_adequate_value_accepted(self):
        self.log.info("Test: script-path spend with adequate value is accepted")
        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(int(utxo["value"] * COIN) - 1000, self.wallet.get_output_script())]
        self.sign_tapscript(tx)

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_key_path_exempt(self):
        self.log.info("Test: key-path spend is exempt from net-negative check")
        from test_framework.key import compute_xonly_pubkey, ECKey
        from test_framework.script_util import output_key_to_p2tr_script

        privkey = ECKey()
        privkey.set((1).to_bytes(32, 'big'), True)
        xonly_pubkey, _ = compute_xonly_pubkey(privkey.get_pubkey().get_bytes()[1:])
        spk = output_key_to_p2tr_script(xonly_pubkey)

        # Fund a tiny P2TR output
        utxo = self.wallet.get_utxo()
        tx_fund = CTransaction()
        tx_fund.version = 2
        tx_fund.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tiny_value = 600
        tx_fund.vout = [
            CTxOut(tiny_value, spk),
            CTxOut(int(utxo["value"] * COIN) - tiny_value - 1000, self.wallet.get_output_script()),
        ]
        self.wallet.sign_tx(tx_fund)
        self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx_fund.serialize().hex())
        self.generate(self.nodes[0], 1)

        # Key-path spend: 1 witness element (dummy signature)
        large_utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(COutPoint(int(tx_fund.rehash(), 16), 0)),
            CTxIn(COutPoint(int(large_utxo["txid"], 16), large_utxo["vout"])),
        ]
        large_value = int(large_utxo["value"] * COIN)
        fee = 15000
        tx.vout = [CTxOut(large_value + tiny_value - fee, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(64)]  # key-path: 1 element
        leaf_info = list(self.wallet._taproot_info.leaves.values())[0]
        tx.wit.vtxinwit[1].scriptWitness.stack = [
            leaf_info.script,
            bytes([leaf_info.version | self.wallet._taproot_info.negflag]) + self.wallet._taproot_info.internal_pubkey,
        ]

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        # May fail for bad signature, but NOT for netnegative on the key-path input
        if not result[0]["allowed"]:
            assert result[0]["reject-reason"] != "bad-txns-input-netnegative", \
                f"Key-path input incorrectly rejected as net-negative: {result}"

    def test_disabled(self):
        self.log.info("Test: check disabled with -rejectnetnegativeinputs=0")
        self.restart_node(0, extra_args=["-rejectnetnegativeinputs=0"])
        self.wallet.rescan_utxos()

        tiny_utxo = self.fund_tiny_utxo(tiny_value=600)
        large_utxo = self.wallet.get_utxo()

        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(COutPoint(int(tiny_utxo["txid"], 16), tiny_utxo["vout"])),
            CTxIn(COutPoint(int(large_utxo["txid"], 16), large_utxo["vout"])),
        ]
        large_value = int(large_utxo["value"] * COIN)
        fee = 15000
        output_value = large_value + 600 - fee
        tx.vout = [CTxOut(output_value, self.wallet.get_output_script())]
        self.sign_tapscript(tx)

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        # Should not be rejected for tapscript dust when disabled
        if not result[0]["allowed"]:
            assert result[0]["reject-reason"] != "bad-txns-input-netnegative", \
                f"Rejected despite -rejectnetnegativeinputs=0: {result}"


if __name__ == '__main__':
    TapscriptDustTest(__file__).main()
