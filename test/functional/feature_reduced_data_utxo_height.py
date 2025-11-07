#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test REDUCED_DATA soft fork UTXO height checking.

This test verifies that the REDUCED_DATA deployment correctly exempts UTXOs
created before ReducedDataHeightBegin from reduced_data script validation rules,
as implemented in validation.cpp.

Test scenarios:
1. Old UTXO (created before activation) spent during active period with violation - should be ACCEPTED (EXEMPT)
2. New UTXO (created during active period) spent with violation - should be REJECTED
3. Mixed inputs (old + new UTXOs) in same transaction
4. Boundary test: UTXO created at exactly ReducedDataHeightBegin
"""

from io import BytesIO

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    CScript,
    OP_TRUE,
    OP_DROP,
    hash256,
)
from test_framework.script_util import (
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet


# Test parameters
ACTIVATION_HEIGHT = 200

# REDUCED_DATA enforces MAX_SCRIPT_ELEMENT_SIZE_REDUCED (256) instead of MAX_SCRIPT_ELEMENT_SIZE (520)
MAX_ELEMENT_SIZE_STANDARD = 520
MAX_ELEMENT_SIZE_REDUCED = 256
VIOLATION_SIZE = 300  # Violates reduced (256) but OK for standard (520)


class ReducedDataUTXOHeightTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f'-testactivationheight=reduced_data@{ACTIVATION_HEIGHT}',
        ]]

    def create_p2wsh_funding_and_spending_tx(self, wallet, node, witness_element_size):
        """Create a P2WSH output, then a transaction spending it with custom witness size.

        Returns:
            tuple: (funding_tx, spending_tx) where funding_tx creates P2WSH output,
                   spending_tx spends it with witness element of specified size
        """
        # Create a simple witness script: <data> OP_DROP OP_TRUE
        # This allows us to put arbitrary data in the witness
        witness_script = CScript([OP_DROP, OP_TRUE])
        script_pubkey = script_to_p2wsh_script(witness_script)

        # Use MiniWallet to create funding transaction to P2WSH output
        funding_txid = wallet.send_to(from_node=node, scriptPubKey=script_pubkey, amount=100000)['txid']
        funding_tx_hex = node.getrawtransaction(funding_txid)
        funding_tx = CTransaction()
        funding_tx.deserialize(BytesIO(bytes.fromhex(funding_tx_hex)))
        funding_tx.rehash()  # Calculate sha256 hash after deserializing

        # Find the P2WSH output
        p2wsh_vout = None
        for i, vout in enumerate(funding_tx.vout):
            if vout.scriptPubKey == script_pubkey:
                p2wsh_vout = i
                break
        assert p2wsh_vout is not None, "P2WSH output not found"

        # Spending transaction: spend P2WSH output with custom witness
        spending_tx = CTransaction()
        spending_tx.vin = [CTxIn(COutPoint(funding_tx.sha256, p2wsh_vout))]
        spending_tx.vout = [CTxOut(funding_tx.vout[p2wsh_vout].nValue - 1000, CScript([OP_TRUE]))]

        # Create witness with element of specified size
        spending_tx.wit.vtxinwit.append(CTxInWitness())
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [
            b'\x42' * witness_element_size,  # Data element of specified size
            witness_script  # Witness script
        ]
        spending_tx.rehash()

        return funding_tx, spending_tx

    def create_test_block(self, txs):
        """Create a block with the given transactions."""
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height), txlist=txs)
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())

        # Use MiniWallet for easy UTXO management
        wallet = MiniWallet(node)

        self.log.info("Mining blocks to get spendable coins...")
        self.generate(wallet, COINBASE_MATURITY + 1)

        current_height = node.getblockcount()
        self.log.info(f"Current height: {current_height}, activation at: {ACTIVATION_HEIGHT}")

        # ======================================================================
        # Test 1: Create OLD UTXO before activation
        # ======================================================================
        self.log.info("Test 1: Creating P2WSH UTXO before activation height...")

        # Mine to a height well before activation
        target_height = ACTIVATION_HEIGHT - 20
        if current_height < target_height:
            self.generate(wallet, target_height - current_height)

        # Create P2WSH funding transaction for old UTXO (sends to mempool, then confirm in block)
        old_funding_tx, old_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )

        # Confirm the funding transaction in a block
        self.generate(wallet, 1)
        old_utxo_height = node.getblockcount()

        self.log.info(f"Created old P2WSH UTXO at height {old_utxo_height} (< {ACTIVATION_HEIGHT})")

        # ======================================================================
        # Test 2: Mine to activation height
        # ======================================================================
        self.log.info("Test 2: Mining to activation height...")

        current_height = node.getblockcount()
        blocks_to_activation = ACTIVATION_HEIGHT - current_height
        if blocks_to_activation > 0:
            self.generate(wallet, blocks_to_activation)

        current_height = node.getblockcount()
        assert_equal(current_height, ACTIVATION_HEIGHT)
        self.log.info(f"At activation height: {current_height}")

        # ======================================================================
        # Test 3: Create NEW UTXO at/after activation
        # ======================================================================
        self.log.info("Test 3: Creating P2WSH UTXO at activation height...")

        # Create P2WSH funding transaction for new UTXO
        new_funding_tx, new_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )

        # Confirm the funding transaction in a block
        self.generate(wallet, 1)
        new_utxo_height = node.getblockcount()

        self.log.info(f"Created new P2WSH UTXO at height {new_utxo_height} (>= {ACTIVATION_HEIGHT})")

        # Mine a few more blocks
        self.generate(wallet, 5)
        current_height = node.getblockcount()
        self.log.info(f"Current height: {current_height}")

        # ======================================================================
        # Test 4: Spend OLD UTXO with oversized witness - should be ACCEPTED
        # ======================================================================
        self.log.info(f"Test 4: Spending old UTXO (height {old_utxo_height}) with {VIOLATION_SIZE}-byte witness element...")
        self.log.info(f"        This violates REDUCED_DATA ({MAX_ELEMENT_SIZE_REDUCED} limit) but old UTXOs should be EXEMPT")

        # Try to mine block with old_spending_tx (has 300-byte witness element)
        block = self.create_test_block([old_spending_tx])
        peer.send_blocks_and_test([block], node, success=True)

        self.log.info(f"✓ SUCCESS: Old UTXO with {VIOLATION_SIZE}-byte witness element was ACCEPTED (correctly exempt)")

        # ======================================================================
        # Test 5: Spend NEW UTXO with oversized witness - should be REJECTED
        # ======================================================================
        self.log.info(f"Test 5: Spending new UTXO (height {new_utxo_height}) with {VIOLATION_SIZE}-byte witness element...")
        self.log.info(f"        This violates REDUCED_DATA ({MAX_ELEMENT_SIZE_REDUCED} limit) and should be REJECTED")

        # Try to mine block with new_spending_tx (has 300-byte witness element)
        block = self.create_test_block([new_spending_tx])
        peer.send_blocks_and_test([block], node, success=False, reject_reason='mandatory-script-verify-flag-failed')

        self.log.info(f"✓ SUCCESS: New UTXO with {VIOLATION_SIZE}-byte witness element was REJECTED (correctly enforced)")

        # ======================================================================
        # Test 6: Boundary test - UTXO at exactly ReducedDataHeightBegin
        # ======================================================================
        self.log.info(f"Test 6: Boundary test - verifying UTXO at activation height {ACTIVATION_HEIGHT}...")

        # The new_funding_tx was confirmed at height 201, but let's create one AT height 200
        # First, invalidate back to height 199
        current_tip = node.getbestblockhash()
        blocks_to_invalidate = node.getblockcount() - (ACTIVATION_HEIGHT - 1)
        for _ in range(blocks_to_invalidate):
            node.invalidateblock(node.getbestblockhash())

        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        self.log.info(f"        Rewound to height {node.getblockcount()}")

        # Create UTXO exactly at activation height 200
        boundary_funding_tx, boundary_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        self.generate(wallet, 1)  # Confirm at exactly height 200
        boundary_height = node.getblockcount()
        assert_equal(boundary_height, ACTIVATION_HEIGHT)

        self.log.info(f"        Created boundary UTXO at height {boundary_height} (exactly at activation)")

        # Mine a few blocks past activation
        self.generate(wallet, 5)

        # Try to spend boundary UTXO - should be REJECTED (height 200 >= 200)
        self.log.info(f"        Spending boundary UTXO with {VIOLATION_SIZE}-byte witness (should be REJECTED)")
        block = self.create_test_block([boundary_spending_tx])
        peer.send_blocks_and_test([block], node, success=False, reject_reason='mandatory-script-verify-flag-failed')

        self.log.info(f"✓ SUCCESS: UTXO at exactly activation height {ACTIVATION_HEIGHT} is SUBJECT to rules (not exempt)")

        # Restore chain to where we were
        node.reconsiderblock(current_tip)

        # ======================================================================
        # Test 7: Mixed inputs - one old (exempt) + one new (subject to rules)
        # ======================================================================
        self.log.info("Test 7: Creating transaction with mixed inputs (old + new UTXOs)...")

        # We need fresh old and new UTXOs. Rewind to before activation again
        current_tip2 = node.getbestblockhash()
        blocks_to_invalidate = node.getblockcount() - (ACTIVATION_HEIGHT - 20)
        for _ in range(blocks_to_invalidate):
            node.invalidateblock(node.getbestblockhash())

        # Create OLD UTXO at height before activation
        old_mixed_funding, old_mixed_spending = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        self.generate(wallet, 1)
        old_mixed_height = node.getblockcount()
        self.log.info(f"        Created old UTXO at height {old_mixed_height}")

        # Mine to after activation
        self.generate(wallet, ACTIVATION_HEIGHT - node.getblockcount() + 5)

        # Create NEW UTXO at height after activation
        new_mixed_funding, new_mixed_spending = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        self.generate(wallet, 1)
        new_mixed_height = node.getblockcount()
        self.log.info(f"        Created new UTXO at height {new_mixed_height}")

        # Find P2WSH outputs in funding transactions
        witness_script = CScript([OP_DROP, OP_TRUE])
        script_pubkey = script_to_p2wsh_script(witness_script)

        old_p2wsh_vout = None
        for i, vout in enumerate(old_mixed_funding.vout):
            if vout.scriptPubKey == script_pubkey:
                old_p2wsh_vout = i
                break

        new_p2wsh_vout = None
        for i, vout in enumerate(new_mixed_funding.vout):
            if vout.scriptPubKey == script_pubkey:
                new_p2wsh_vout = i
                break

        # Create transaction with BOTH inputs
        mixed_tx = CTransaction()
        mixed_tx.vin = [
            CTxIn(COutPoint(old_mixed_funding.sha256, old_p2wsh_vout)),  # Old UTXO (exempt)
            CTxIn(COutPoint(new_mixed_funding.sha256, new_p2wsh_vout)),  # New UTXO (subject to rules)
        ]
        total_value = (old_mixed_funding.vout[old_p2wsh_vout].nValue +
                      new_mixed_funding.vout[new_p2wsh_vout].nValue - 2000)
        mixed_tx.vout = [CTxOut(total_value, CScript([OP_TRUE]))]

        # Add witness for both inputs - both with 300-byte elements
        mixed_tx.wit.vtxinwit = []

        # Input 0: old UTXO (would pass alone)
        wit0 = CTxInWitness()
        wit0.scriptWitness.stack = [b'\x42' * VIOLATION_SIZE, witness_script]
        mixed_tx.wit.vtxinwit.append(wit0)

        # Input 1: new UTXO (would fail)
        wit1 = CTxInWitness()
        wit1.scriptWitness.stack = [b'\x42' * VIOLATION_SIZE, witness_script]
        mixed_tx.wit.vtxinwit.append(wit1)

        mixed_tx.rehash()

        self.log.info(f"        Mixed tx: old UTXO (height {old_mixed_height}, exempt) + new UTXO (height {new_mixed_height}, subject)")
        self.log.info(f"        Both inputs have {VIOLATION_SIZE}-byte witness elements")

        # Try to mine block - should REJECT because new input violates
        self.generate(wallet, 2)
        block = self.create_test_block([mixed_tx])
        peer.send_blocks_and_test([block], node, success=False, reject_reason='mandatory-script-verify-flag-failed')

        self.log.info(f"✓ SUCCESS: Mixed transaction REJECTED (new input violated rules, even though old input was exempt)")

        # Restore chain
        node.reconsiderblock(current_tip2)

        # ======================================================================
        # Summary
        # ======================================================================
        self.log.info("""
        ============================================================
        TEST SUMMARY - UTXO Height-Based REDUCED_DATA Enforcement
        ============================================================

        ✓ Test 1-3: Setup old and new UTXOs at correct heights
        ✓ Test 4: Old UTXO (height < 200) is EXEMPT - 300-byte witness ACCEPTED
        ✓ Test 5: New UTXO (height >= 200) is SUBJECT - 300-byte witness REJECTED
        ✓ Test 6: Boundary condition - UTXO at exactly height 200 is SUBJECT
        ✓ Test 7: Mixed inputs - transaction rejected if ANY input violates

        Key validations:
        • UTXOs created before ReducedDataHeightBegin are EXEMPT
        • UTXOs created at/after ReducedDataHeightBegin are SUBJECT
        • Per-input validation flags work correctly (validation.cpp:2964)
        • Boundary at activation height uses >= operator (not >)

        This confirms the implementation in commit 233da706cd:
        "Exempt inputs spending UTXOs prior to ReducedDataHeightBegin from
        reduced_data script validation rules"

        All 7 tests passed!
        ============================================================
        """)


if __name__ == '__main__':
    ReducedDataUTXOHeightTest(__file__).main()
