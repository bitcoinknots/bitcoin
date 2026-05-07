#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test data in a dead conditional branch and -rejectdeadbranches"""
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    OP_NOP,
    OP_NOTIF,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet import MiniWallet


class DeadBranchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.extra_args = [
            [],  # the framework passes -corepolicy, which accepts non-standard carriers
            ["-corepolicy=0"],  # the Knots default
            ["-corepolicy=0", "-rejectdeadbranches=0"],
            ["-corepolicy=0", "-acceptnonstddatacarrier=1"],
            ["-corepolicy=0", "-acceptnonstddatacarrier=1", "-rejectdeadbranches=0"],
        ]

    def spend(self, witness_script):
        """Fund a P2WSH output to witness_script and return its spend, which needs no signature"""
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_to_p2wsh_script(witness_script), amount=100000)
        self.generate(self.nodes[0], 1)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
        tx.vout = [CTxOut(99000, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        return tx.serialize().hex()

    def check(self, node, tx_hex, allowed, reason=None):
        result = node.testmempoolaccept([tx_hex])[0]
        assert_equal(result["allowed"], allowed)
        if reason:
            assert_equal(result["reject-reason"], reason)
        return result

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        corepolicy, default, disabled, costed, costed_disabled = self.nodes

        # OP_1 makes OP_NOTIF skip its branch, so the push cannot affect the
        # spend. This is the JXL-n-hide witness shape; the OP_FALSE OP_IF
        # inscription envelope is the same idea with the constant reversed.
        self.log.info("Data in an OP_1 OP_NOTIF branch is rejected by default")
        dead_notif = self.spend(CScript([OP_1, OP_NOTIF, b'\xab' * 10, OP_ENDIF, OP_1]))
        self.check(default, dead_notif, False, "txn-datacarrier-nonstandard")

        self.log.info("-rejectdeadbranches=0 and -corepolicy accept it")
        self.check(disabled, dead_notif, True)
        self.check(corepolicy, dead_notif, True)

        self.log.info("Data in the else of a branch a constant always takes is rejected too")
        dead_else = self.spend(CScript([OP_1, OP_IF, OP_1, OP_ELSE, b'\xab' * 10, OP_ENDIF]))
        self.check(default, dead_else, False, "txn-datacarrier-nonstandard")
        self.check(disabled, dead_else, True)

        self.log.info("A guard that constants decide is counted however it is computed")
        nop_guard = self.spend(CScript([OP_1, OP_NOP, OP_NOTIF, b'\xab' * 10, OP_ENDIF, OP_1]))
        self.check(default, nop_guard, False, "txn-datacarrier-nonstandard")
        self.check(disabled, nop_guard, True)

        self.log.info("-rejectdeadbranches=0 still counts the OP_FALSE OP_IF envelope")
        envelope = self.spend(CScript([OP_0, OP_IF, b'\xab' * 10, OP_ENDIF, OP_1]))
        self.check(default, envelope, False, "txn-datacarrier-nonstandard")
        self.check(disabled, envelope, False, "txn-datacarrier-nonstandard")

        self.log.info("A branch the guard takes is not counted: its push is the spend's result")
        self.check(default, self.spend(CScript([OP_0, OP_NOTIF, b'\xab' * 10, OP_ENDIF])), True)

        self.log.info("The switch reaches -datacarriercost too")
        counted = self.check(costed, dead_notif, True)
        uncounted = self.check(costed_disabled, dead_notif, True)
        assert_greater_than(counted["vsize"], uncounted["vsize"])


if __name__ == '__main__':
    DeadBranchTest(__file__).main()
