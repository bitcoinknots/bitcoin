#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the minimum fee policy for multisig input sigops."""

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_3, OP_CHECKMULTISIG, OP_ENDIF, OP_FALSE, OP_IF, OP_RETURN, OP_TRUE
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class MultisigSigOpFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Test the new policy even though the framework otherwise selects Core policy.
        self.extra_args = [["-minrelaymultisigsigopfee=500"]]

    def make_spend(self, funding, witness_script, fee):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        # Keep the stripped transaction above MIN_STANDARD_TX_NONWITNESS_SIZE so
        # the multisig fee policy is the first rejection reason being tested.
        tx.vout = [CTxOut(1_000_000 - fee, CScript([OP_RETURN, bytes(20)]))]
        return tx.serialize().hex()

    def check_fee(self, funding, witness_script, fee, allowed):
        result = self.nodes[0].testmempoolaccept([self.make_spend(funding, witness_script, fee)])[0]
        assert_equal(result["allowed"], allowed)
        if not allowed:
            assert_equal(result["reject-reason"], "min multisig sigop fee not met")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        # The branch is not executed, but accurate script counting assigns three
        # sigops to OP_3 OP_CHECKMULTISIG, matching a 1-of-3/2-of-3/3-of-3 script.
        witness_script = CScript([OP_FALSE, OP_IF, OP_3, OP_CHECKMULTISIG, OP_ENDIF, OP_TRUE])
        funding = self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=script_to_p2wsh_script(witness_script),
            amount=1_000_000,
        )
        self.generate(self.wallet, 1)

        self.log.info("Default policy requires 3 * 500 = 1500 sats")
        self.check_fee(funding, witness_script, 1_499, False)
        self.check_fee(funding, witness_script, 1_500, True)

        self.log.info("The per-sigop amount is configurable")
        self.restart_node(0, extra_args=["-minrelaymultisigsigopfee=1000"])
        self.check_fee(funding, witness_script, 2_999, False)
        self.check_fee(funding, witness_script, 3_000, True)

        self.log.info("A value of zero disables the additional policy")
        self.restart_node(0, extra_args=["-minrelaymultisigsigopfee=0"])
        self.check_fee(funding, witness_script, 500, True)


if __name__ == "__main__":
    MultisigSigOpFeeTest(__file__).main()
