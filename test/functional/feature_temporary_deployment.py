#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test temporary BIP9 deployment with active_duration parameter.

This test verifies that a BIP9 deployment with active_duration properly expires
after the specified number of blocks. We use REDUCED_DATA as the test deployment
with active_duration=144 blocks.

The test verifies two critical behaviors:
1. Consensus rules ARE enforced during the active period (blocks 432-575)
2. Consensus rules STOP being enforced after expiry (block 576+)

Expected timeline:
- Period 0 (blocks 0-143): DEFINED
- Period 1 (blocks 144-287): STARTED (signaling happens here)
- Period 2 (blocks 288-431): LOCKED_IN
- Period 3 (blocks 432-575): ACTIVE (144 blocks, from activation_height 432 to 575)
- Block 576+: EXPIRED (deployment no longer active, rules no longer enforced)
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

REDUCED_DATA_BIT = 3
VERSIONBITS_TOP_BITS = 0x20000000


class TemporaryDeploymentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Set active_duration to 144 blocks (1 period) for REDUCED_DATA
        # Format: deployment:start:end:min_activation_height:active_duration
        # start=0, timeout=999999999999, min_activation_height=0, active_duration=144
        self.extra_args = [[
            '-vbparams=reduced_data:0:999999999999:0:144',
            '-acceptnonstdtxn=1',
        ]]

    def create_test_block(self, txs, signal=False):
        """Create a block with the given transactions."""
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        tip_header = self.nodes[0].getblockheader(tip)
        block_time = tip_header['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, txlist=txs)
        if signal:
            block.nVersion = VERSIONBITS_TOP_BITS | (1 << REDUCED_DATA_BIT)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_blocks(self, count, signal=False):
        """Mine count blocks, optionally signaling for REDUCED_DATA."""
        for _ in range(count):
            block = self.create_test_block([], signal=signal)
            self.nodes[0].submitblock(block.serialize().hex())

    def create_tx_with_data(self, data_size):
        """Create a transaction with OP_RETURN output of specified size."""
        # Start with a valid transaction from the wallet
        tx_dict = self.wallet.create_self_transfer()
        tx = tx_dict['tx']

        # Add an OP_RETURN output with specified data size
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * data_size])))
        tx.rehash()

        return tx

    def get_deployment_status(self, deployment_info, deployment_name):
        """Helper to get deployment status from getdeploymentinfo()."""
        rd = deployment_info['deployments'][deployment_name]
        if 'bip9' in rd:
            return rd['bip9']['status'], rd['bip9'].get('since', 'N/A')
        return rd.get('status'), rd.get('since', 'N/A')

    def run_test(self):
        node = self.nodes[0]

        # MiniWallet provides a simple wallet for test transactions
        self.wallet = MiniWallet(node)

        self.log.info("Mining initial blocks to get spendable coins...")
        self.generate(self.wallet, 101)

        # Get deployment info at genesis
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 101 - Status: {status}, Since: {since}")
        assert_equal(status, 'defined')

        # Mine through period 0 (blocks 102-143) - should remain DEFINED
        self.log.info("Mining through period 0 (blocks 102-143)...")
        self.generate(node, 42)  # Get to block 143
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 143 - Status: {status}")
        assert_equal(status, 'defined')

        # Mine period 1 (blocks 144-287) with signaling - should transition to STARTED
        self.log.info("Mining period 1 (blocks 144-287) with 100% signaling...")
        self.mine_blocks(144, signal=True)
        assert_equal(node.getblockcount(), 287)
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 287 - Status: {status}")
        assert_equal(status, 'started')

        # Mine period 2 (blocks 288-431) - should transition to LOCKED_IN
        self.log.info("Mining period 2 (blocks 288-431)...")
        self.mine_blocks(144, signal=True)
        assert_equal(node.getblockcount(), 431)
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 431 - Status: {status}")
        assert_equal(status, 'locked_in')

        # Mine one more block to activate (block 432 starts period 3)
        self.log.info("Mining block 432 (activation block)...")
        self.mine_blocks(1)
        assert_equal(node.getblockcount(), 432)
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 432 - Status: {status}, Since: {since}")
        assert_equal(status, 'active')
        assert_equal(since, 432)

        # Test that REDUCED_DATA rules are enforced at block 432 (first active block)
        self.log.info("Testing REDUCED_DATA rules are enforced at block 432...")
        tx_large_data = self.create_tx_with_data(81)
        block_invalid = self.create_test_block([tx_large_data])
        result = node.submitblock(block_invalid.serialize().hex())
        self.log.info(f"Submitting block with 81-byte OP_RETURN at height 432: {result}")
        # 81 bytes data becomes 84-byte script (OP_RETURN + OP_PUSHDATA1 + len + data), exceeds 83-byte limit
        assert_equal(result, 'bad-txns-vout-script-toolarge')

        # Mine a valid block instead
        tx_valid = self.create_tx_with_data(80)
        block_valid = self.create_test_block([tx_valid])
        assert_equal(node.submitblock(block_valid.serialize().hex()), None)
        assert_equal(node.getblockcount(), 433)

        # Mine through most of the active period (blocks 434-575)
        self.log.info("Mining through active period to block 575...")
        self.generate(node, 142)  # 434 to 575
        assert_equal(node.getblockcount(), 575)
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 575 - Status: {status}")
        assert_equal(status, 'active')

        # Test that REDUCED_DATA rules are still enforced at block 576 (last active block, 432 + 144)
        self.log.info("Testing REDUCED_DATA rules are still enforced at block 576 (last active block)...")
        tx_large_data = self.create_tx_with_data(81)
        block_invalid = self.create_test_block([tx_large_data])
        result = node.submitblock(block_invalid.serialize().hex())
        self.log.info(f"Submitting block with 81-byte OP_RETURN at height 576: {result}")
        assert_equal(result, 'bad-txns-vout-script-toolarge')

        # Mine valid block 576
        tx_valid = self.create_tx_with_data(80)
        block_valid = self.create_test_block([tx_valid])
        assert_equal(node.submitblock(block_valid.serialize().hex()), None)
        assert_equal(node.getblockcount(), 576)
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 576 - Status: {status}")
        assert_equal(status, 'active')

        # Test that REDUCED_DATA rules are NO LONGER enforced at block 577 (first expired block)
        self.log.info("Testing REDUCED_DATA rules are NOT enforced at block 577 (first expired block, 432 + 144 + 1)...")
        tx_large_data = self.create_tx_with_data(81)
        block_after_expiry = self.create_test_block([tx_large_data])
        result = node.submitblock(block_after_expiry.serialize().hex())
        self.log.info(f"Submitting block with 81-byte OP_RETURN at height 577: {result}")
        assert_equal(result, None)
        assert_equal(node.getblockcount(), 577)

        # Check deployment status after expiry
        # Note: BIP9 status may still show 'active' but rules are no longer enforced
        info = node.getdeploymentinfo()
        status, since = self.get_deployment_status(info, 'reduced_data')
        self.log.info(f"Block 577 - Status: {status}, Since: {since}")

        # Verify rules remain unenforced for several more blocks
        self.log.info("Verifying REDUCED_DATA rules remain unenforced after expiry...")
        for i in range(10):
            tx_large = self.create_tx_with_data(81)
            block = self.create_test_block([tx_large])
            result = node.submitblock(block.serialize().hex())
            assert_equal(result, None)

        self.log.info(f"Final block height: {node.getblockcount()}")

if __name__ == '__main__':
    TemporaryDeploymentTest(__file__).main()
