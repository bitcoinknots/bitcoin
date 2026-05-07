#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sub-dust output fee penalty (-subdustfeepenalty)."""

from math import ceil

from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


DUST_THRESHOLD = 330  # P2TR: (43 + 67) * 3000 / 1000 = 330 sats


class SubDustFeePenaltyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1", "-subdustfeepenalty=1"]]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        info = self.nodes[0].getmempoolinfo()
        self.minrelay_per_kvb = info['minrelaytxfee'] * COIN  # sats per kvB

        self.test_dust_output_increases_required_fee()
        self.test_partial_dust_proportional_penalty()
        self.test_multiple_dust_outputs_stack()
        self.test_penalty_disabled()
        self.test_op_return_not_penalized()
        self.test_above_dust_not_penalized()

    def build_tx_with_dust(self, dust_values, fee):
        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        input_value = int(utxo["value"] * COIN)
        change = input_value - sum(dust_values) - fee
        assert change > 0, f"Not enough funds: input={input_value}, dust={dust_values}, fee={fee}"
        tx.vout = [CTxOut(v, self.wallet.get_output_script()) for v in dust_values]
        tx.vout.append(CTxOut(change, self.wallet.get_output_script()))
        self.wallet.sign_tx(tx)
        return tx

    def get_min_relay_fee(self, tx):
        """Calculate the minimum relay fee for a transaction."""
        decoded = self.nodes[0].decoderawtransaction(tx.serialize().hex())
        return int(ceil(self.minrelay_per_kvb * decoded['vsize'] / 1000))

    def test_dust_output_increases_required_fee(self):
        self.log.info("Test: sub-dust output penalizes effective fee")

        # Build a probe tx to determine the exact min relay fee
        probe = self.build_tx_with_dust([0], fee=1000)
        min_fee = self.get_min_relay_fee(probe)

        # fee just covers min relay + penalty - 1: rejected
        reject_fee = DUST_THRESHOLD + min_fee - 1
        tx_low = self.build_tx_with_dust([0], fee=reject_fee)
        result = self.nodes[0].testmempoolaccept([tx_low.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert_equal(result[0]["reject-reason"], "min relay fee not met")

        # fee covers min relay + penalty: accepted
        accept_fee = DUST_THRESHOLD + min_fee
        tx_high = self.build_tx_with_dust([0], fee=accept_fee)
        result = self.nodes[0].testmempoolaccept([tx_high.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_partial_dust_proportional_penalty(self):
        self.log.info("Test: partial dust value gets proportional penalty")

        partial_value = 100
        penalty = DUST_THRESHOLD - partial_value  # 230 sats

        probe = self.build_tx_with_dust([partial_value], fee=1000)
        min_fee = self.get_min_relay_fee(probe)

        reject_fee = penalty + min_fee - 1
        tx_low = self.build_tx_with_dust([partial_value], fee=reject_fee)
        result = self.nodes[0].testmempoolaccept([tx_low.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert_equal(result[0]["reject-reason"], "min relay fee not met")

        accept_fee = penalty + min_fee
        tx_high = self.build_tx_with_dust([partial_value], fee=accept_fee)
        result = self.nodes[0].testmempoolaccept([tx_high.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_multiple_dust_outputs_stack(self):
        self.log.info("Test: multiple dust outputs stack penalties")

        total_penalty = DUST_THRESHOLD * 2  # 660 sats

        probe = self.build_tx_with_dust([0, 0], fee=1000)
        min_fee = self.get_min_relay_fee(probe)

        reject_fee = total_penalty + min_fee - 1
        tx_low = self.build_tx_with_dust([0, 0], fee=reject_fee)
        result = self.nodes[0].testmempoolaccept([tx_low.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert_equal(result[0]["reject-reason"], "min relay fee not met")

        accept_fee = total_penalty + min_fee
        tx_high = self.build_tx_with_dust([0, 0], fee=accept_fee)
        result = self.nodes[0].testmempoolaccept([tx_high.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_penalty_disabled(self):
        self.log.info("Test: penalty disabled with -subdustfeepenalty=0")
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-subdustfeepenalty=0"])
        self.wallet.rescan_utxos()

        probe = self.build_tx_with_dust([0], fee=1000)
        min_fee = self.get_min_relay_fee(probe)

        # Without penalty, just the min relay fee suffices
        tx = self.build_tx_with_dust([0], fee=min_fee)
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_op_return_not_penalized(self):
        self.log.info("Test: OP_RETURN outputs are not penalized (threshold=0)")
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-subdustfeepenalty=1"])
        self.wallet.rescan_utxos()

        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        input_value = int(utxo["value"] * COIN)
        fee = 400
        tx.vout = [
            CTxOut(0, CScript([OP_RETURN, b"test data"])),
            CTxOut(input_value - fee, self.wallet.get_output_script()),
        ]
        self.wallet.sign_tx(tx)

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)

    def test_above_dust_not_penalized(self):
        self.log.info("Test: outputs above dust threshold are not penalized")

        probe = self.build_tx_with_dust([DUST_THRESHOLD + 100], fee=1000)
        min_fee = self.get_min_relay_fee(probe)

        tx = self.build_tx_with_dust([DUST_THRESHOLD + 100], fee=min_fee)
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)


if __name__ == '__main__':
    SubDustFeePenaltyTest(__file__).main()
