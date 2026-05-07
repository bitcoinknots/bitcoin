#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that ignore_rejects cannot relax reduced-data (RDTS) consensus rules.

PolicyScriptChecks must stay at least as strict as ConsensusScriptChecks: once
DEPLOYMENT_REDUCED_DATA is active its flags are consensus, so a script-verify-flag
ignore_rejects that clears them lets a transaction pass the former and fail the
latter. ConsensusScriptChecks treats that as a bug, logging "BUG! PLEASE REPORT
THIS!" and tripping an Assume() that aborts on ABORT_ON_FAILED_ASSUME builds.

They stay unrelaxable after the deployment EXPIRES too: a release cannot know
what the rules will be beyond its own deployment, so refusing is the safe default.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    CScriptOp,
    OP_1,
    OP_ENDIF,
    OP_IF,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# ConsensusScriptChecks' "policy passed but consensus failed" alarm.
BUG_MSG = "BUG! PLEASE REPORT THIS!"

# Start immediately and expire active_duration (144) blocks after activating, so
# the deployment runs the real DEFINED -> ... -> ACTIVE -> EXPIRED path.
VBPARAMS = "-vbparams=reduced_data:0:999999999999:0:2147483647:144"
ACTIVATION_HEIGHT = 432
EXPIRY_HEIGHT = ACTIVATION_HEIGHT + 144

# Violates SCRIPT_VERIFY_REDUCED_DATA itself, which only the broad token clears.
TAPSCRIPT_OP_IF = CScript([OP_1, OP_IF, OP_1, OP_ENDIF])
# Violates SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, which both tokens clear. Without
# that flag the script succeeds unconditionally, so policy accepts what consensus
# rejects. 0x62 (OP_VER) is one of the OP_SUCCESS opcodes.
TAPSCRIPT_OP_SUCCESS = CScript([CScriptOp(0x62)])

# (ignore_rejects, name, tapscript). OP_IF is not paired with the -upgradable
# token: that token leaves SCRIPT_VERIFY_REDUCED_DATA set, so policy rejects it
# either way and there is nothing for consensus to catch.
CASES = [
    ([], "OP_IF", TAPSCRIPT_OP_IF),
    ([], "OP_SUCCESS", TAPSCRIPT_OP_SUCCESS),
    (["non-mandatory-script-verify-flag"], "OP_IF", TAPSCRIPT_OP_IF),
    (["non-mandatory-script-verify-flag"], "OP_SUCCESS", TAPSCRIPT_OP_SUCCESS),
    (["non-mandatory-script-verify-flag-upgradable"], "OP_SUCCESS", TAPSCRIPT_OP_SUCCESS),
]


class RdtsIgnoreRejectsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[VBPARAMS]]

    def fund_taproot_leaf(self, leaf_script):
        """Mine a Taproot output committing to leaf_script, and return a tx that
        spends it via the script path."""
        node = self.nodes[0]
        internal_pubkey, _ = compute_xonly_pubkey(generate_privkey())
        taproot_info = taproot_construct(internal_pubkey, [("leaf", leaf_script)])

        funding_tx = self.wallet.create_self_transfer()['tx']
        funding_tx.vout[0] = CTxOut(funding_tx.vout[0].nValue, taproot_info.scriptPubKey)
        funding_txid = funding_tx.rehash()

        # Mine the funding tx directly: its own relay is not what is under test.
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1),
                             node.getblockheader(tip)['time'] + 1)
        block.vtx.append(funding_tx)
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)

        spending_tx = CTransaction()
        spending_tx.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0), nSequence=0)]
        # A 34-byte P2WSH output, so rule 1 (output script size) is not what fails.
        spending_tx.vout = [CTxOut(funding_tx.vout[0].nValue - 1000, CScript([OP_1, bytes(32)]))]
        leaf_info = taproot_info.leaves["leaf"]
        control_block = bytes([leaf_info.version + taproot_info.negflag]) + internal_pubkey + leaf_info.merklebranch
        spending_tx.wit.vtxinwit.append(CTxInWitness())
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [leaf_script, control_block]
        spending_tx.rehash()
        return spending_tx

    def check_all_rejected(self):
        node = self.nodes[0]
        for ignore_rejects, name, leaf in CASES:
            tx = self.fund_taproot_leaf(leaf)
            # Reaching ConsensusScriptChecks as a policy pass is what logs BUG_MSG.
            with node.assert_debug_log([], unexpected_msgs=[BUG_MSG]):
                result = node.testmempoolaccept([tx.serialize().hex()], 0, ignore_rejects)[0]
            assert_equal(result['allowed'], False)
            self.log.info(f"  {name} with ignore_rejects={ignore_rejects}: "
                          f"rejected ({result['reject-reason']})")

    def deployment_status(self):
        return self.nodes[0].getdeploymentinfo()['deployments']['reduced_data']['bip9']['status']

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)  # coinbase maturity

        self.generate(self.wallet, ACTIVATION_HEIGHT + 8 - node.getblockcount())
        assert_equal(self.deployment_status(), 'active')
        self.log.info(f"Deployment active at height {node.getblockcount()}")
        self.check_all_rejected()

        self.generate(self.wallet, EXPIRY_HEIGHT + 6 - node.getblockcount())
        assert_equal(self.deployment_status(), 'expired')
        self.log.info(f"Deployment expired at height {node.getblockcount()}")
        self.check_all_rejected()

        self.log.info("Genuinely policy-only flags are still ignorable")
        assert_equal(node.testmempoolaccept(
            [self.wallet.create_self_transfer()['hex']], 0,
            ["non-mandatory-script-verify-flag-cleanstack"])[0]['allowed'], True)


if __name__ == '__main__':
    RdtsIgnoreRejectsTest(__file__).main()
