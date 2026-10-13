#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the minimum fee policy for excess keys in canonical multisig inputs."""

from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_DROP,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
)
from test_framework.script_util import script_to_p2sh_p2wsh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


FUNDING_VALUE = 1_000_000


class MultisigSigOpFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # The framework selects Core policy by default. Disable it here so this
        # test exercises the Knots default without restating the default value.
        self.extra_args = [["-corepolicy=0"]]

    def create_multisig(self, required, total):
        keys = []
        for _ in range(total):
            key = ECKey()
            key.generate(compressed=True)
            keys.append(key)
        script = CScript([
            OP_2 if required == 2 else required,
            *[key.get_pubkey().get_bytes() for key in keys],
            OP_2 if total == 2 else OP_3 if total == 3 else total,
            OP_CHECKMULTISIG,
        ])
        return keys, script

    def fund(self, script, *, nested=False, count=1):
        script_pubkey = script_to_p2sh_p2wsh_script(script) if nested else script_to_p2wsh_script(script)
        return [
            self.wallet.send_to(
                from_node=self.nodes[0],
                scriptPubKey=script_pubkey,
                amount=FUNDING_VALUE,
            )
            for _ in range(count)
        ]

    def make_spend(self, fundings, script, keys, required, fee, *, nested=False):
        tx = CTransaction()
        tx.vin = [
            CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))
            for funding in fundings
        ]
        tx.vout = [CTxOut(FUNDING_VALUE * len(fundings) - fee, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness() for _ in fundings]

        witness_program = script_to_p2wsh_script(script)
        for index in range(len(fundings)):
            if nested:
                tx.vin[index].scriptSig = CScript([bytes(witness_program)])
            sighash = SegwitV0SignatureHash(script, tx, index, SIGHASH_ALL, FUNDING_VALUE)
            signatures = [
                key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])
                for key in keys[:required]
            ]
            tx.wit.vtxinwit[index].scriptWitness.stack = [b""] + signatures + [bytes(script)]
        tx.rehash()
        return tx.serialize().hex()

    def check_fee(self, fundings, script, keys, required, fee, allowed, *, nested=False, ignore_rejects=None):
        result = self.nodes[0].testmempoolaccept(
            [self.make_spend(fundings, script, keys, required, fee, nested=nested)],
            0,
            ignore_rejects or [],
        )[0]
        assert_equal(result["allowed"], allowed)
        if not allowed:
            assert_equal(result["reject-reason"], "min multisig excess key fee not met")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        keys_2_of_2, script_2_of_2 = self.create_multisig(2, 2)
        keys_2_of_3, script_2_of_3 = self.create_multisig(2, 3)
        keys_3_of_5, script_3_of_5 = self.create_multisig(3, 5)
        keys_2_of_5, script_2_of_5 = self.create_multisig(2, 5)
        keys_1_of_15, script_1_of_15 = self.create_multisig(1, 15)
        dropped_count_script = CScript([
            1, *[key.get_pubkey().get_bytes() for key in keys_1_of_15],
            15, OP_DROP, 15, OP_CHECKMULTISIG,
        ])
        funding_2_of_2 = self.fund(script_2_of_2)
        funding_2_of_3 = self.fund(script_2_of_3)
        funding_3_of_5 = self.fund(script_3_of_5)
        funding_2_of_5 = self.fund(script_2_of_5)
        funding_1_of_15 = self.fund(script_1_of_15)
        dropped_count_funding = self.fund(dropped_count_script)
        nested_funding_1_of_15 = self.fund(script_1_of_15, nested=True)
        multi_funding_2_of_5 = self.fund(script_2_of_5, count=3)
        self.generate(self.wallet, 1)

        self.log.info("Valid signed 2-of-2 and 2-of-3 P2WSH spends have no excess-key floor")
        self.check_fee(funding_2_of_2, script_2_of_2, keys_2_of_2, 2, 500, True)
        self.check_fee(funding_2_of_3, script_2_of_3, keys_2_of_3, 2, 500, True)

        self.log.info("A valid signed 3-of-5 has one charged excess key")
        self.check_fee(funding_3_of_5, script_3_of_5, keys_3_of_5, 3, 999, False)
        self.check_fee(funding_3_of_5, script_3_of_5, keys_3_of_5, 3, 1_000, True)

        self.log.info("A valid signed 2-of-5 has two charged excess keys")
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 1_999, False)
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 2_000, True)

        self.log.info("A valid signed 1-of-15 has thirteen charged excess keys")
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False)
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 13_000, True)

        self.log.info("Dropping and re-pushing the key count cannot bypass the floor")
        self.check_fee(dropped_count_funding, dropped_count_script, keys_1_of_15, 1, 13_999, False)
        self.check_fee(dropped_count_funding, dropped_count_script, keys_1_of_15, 1, 14_000, True)

        self.log.info("A valid signed nested P2SH-P2WSH spend is counted identically")
        self.check_fee(nested_funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False, nested=True)
        self.check_fee(nested_funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 13_000, True, nested=True)

        self.log.info("The floor scales over every input in the complete transaction")
        self.check_fee(multi_funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 5_999, False)
        self.check_fee(multi_funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 6_000, True)

        self.log.info("Only the policy's own reject key bypasses it")
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False, ignore_rejects=["min relay fee not met"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, True, ignore_rejects=["min multisig excess key fee not met"])

        self.log.info("The per-excess-key amount is configurable")
        self.restart_node(0, extra_args=["-minrelaymultisigexcesskeyfee=1500"])
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 2_999, False)
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 3_000, True)

        self.log.info("A value of zero disables the additional policy")
        self.restart_node(0, extra_args=["-minrelaymultisigexcesskeyfee=0"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 500, True)

        self.log.info("Core policy disables the Knots-specific fee floor")
        self.restart_node(0, extra_args=["-corepolicy=1"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 500, True)


if __name__ == "__main__":
    MultisigSigOpFeeTest(__file__).main()
