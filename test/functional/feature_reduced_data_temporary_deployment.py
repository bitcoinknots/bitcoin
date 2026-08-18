#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the temporary RDTS deployment with its median-time-past expiry.

This test verifies that the RDTS deployment activates at the BLAKE2b fork
height and properly expires once the parent block's median-time-past reaches
the expiry time.

The test uses two nodes:
- Node 0: BIP-110 enforcing (fork height + expiry scheduled)
- Node 1: Non-BIP-110 (fork height only, RDTS never active: simulates a node
  that follows the hardfork but not RDTS)

The test verifies:
1. Deployment transitions: inactive -> active (fork height) -> expired (MTP)
2. Consensus rules ARE enforced during the active period (blocks 432-575)
3. Chain split: BIP-110 node rejects invalid blocks, non-BIP-110 accepts
4. Reorg: Longer valid chain wins when nodes reconnect
5. Consensus rules STOP being enforced after expiry (block 576+)
6. Post-expiry convergence: Both nodes accept the same blocks

Expected timeline:
- Blocks 0-431: pre-fork (v1 headers, RDTS inactive)
- Block 432: BLAKE2b fork block (carries the headline; RDTS activates)
- Blocks 432-575: ACTIVE (rules enforced on node0 only)
- Block 576+: EXPIRED once the median-time-past reaches EXPIRY_TIME (both
  nodes' clocks are frozen there so the boundary lands exactly at 576)
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

# RDTS activates at the BLAKE2b fork height (see -testactivationheight below)
ACTIVATION_HEIGHT = 432
EXPIRY_TIME = 2000000000
# The first BLAKE2b block's coinbase must contain the headline; this value
# must match the test framework's default -blake2b_headline argument
HEADLINE = b'BLAKE2b functional test headline'


class TemporaryDeploymentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node 0: BIP-110 enforcing (fork height + RDTS expiry)
        # Node 1: fork height only; with no -rdtsexpiry the deployment is
        # never scheduled, so RDTS is never active (simulates a non-BIP-110
        # node on the same hardfork)
        self.extra_args = [
            [f'-testactivationheight=blake2b@{ACTIVATION_HEIGHT}', f'-rdtsexpiry={EXPIRY_TIME}', '-acceptnonstdtxn=1'],
            [f'-testactivationheight=blake2b@{ACTIVATION_HEIGHT}', '-acceptnonstdtxn=1'],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def create_block_for_node(self, node, txs=None, time_offset=0):
        """Create a block for a specific node, v1 or v2 to match its height."""
        if txs is None:
            txs = []
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        tip_header = node.getblockheader(tip)
        block_time = tip_header['time'] + 1 + time_offset
        coinbase = create_coinbase(height)
        if height == ACTIVATION_HEIGHT:
            # The first BLAKE2b block must carry the headline in its coinbase
            coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + HEADLINE)
            coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, ntime=block_time, txlist=txs,
                             height=height, header_v2=height >= ACTIVATION_HEIGHT)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_blocks_on_node(self, node, count):
        """Mine count blocks on a specific node."""
        for _ in range(count):
            block = self.create_block_for_node(node)
            node.submitblock(block.serialize().hex())

    def create_tx_with_large_output(self, wallet):
        """Create a transaction with 84-byte OP_RETURN (violates BIP-110's 83-byte limit)."""
        tx_dict = wallet.create_self_transfer()
        tx = tx_dict['tx']
        # 81 bytes data = 84-byte script (OP_RETURN + OP_PUSHDATA1 + len + data)
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * 81])))
        tx.rehash()
        return tx

    def rdts_active_for_next_block(self, node):
        """Whether the RDTS rules apply to the next block on node's tip."""
        info = node.getblockchaininfo()
        return info['blocks'] + 1 >= ACTIVATION_HEIGHT and info['mediantime'] < EXPIRY_TIME

    def assert_gbt_rdts(self, node, *, active):
        """Check getblocktemplate's RDTS surface: the rules entry."""
        # 'blake2b' is a client-capability rule: required once the template
        # is a v2 (BLAKE2b) header, ignored before the fork.
        tmpl = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert_equal('reduced_data' in tmpl['rules'], active)

    def assert_rdts_deploymentinfo(self, node, *, active):
        """Check the reduced_data entry in getdeploymentinfo."""
        rd = node.getdeploymentinfo()['deployments']['reduced_data']
        assert_equal(rd['type'], 'flagday')
        assert_equal(rd['height'], ACTIVATION_HEIGHT)
        assert_equal(rd['expiry_time'], EXPIRY_TIME)
        assert_equal(rd['active'], active)

    def run_test(self):
        node_bip110 = self.nodes[0]
        node_core = self.nodes[1]

        wallet = MiniWallet(node_bip110)

        # =====================================================================
        # Phase 1: Build the common pre-fork chain
        # =====================================================================
        self.log.info("Phase 1: Building the common pre-fork chain")

        self.log.info("Mining initial blocks for spendable coins...")
        self.generate(wallet, 101)
        self.sync_all()

        assert_equal(self.rdts_active_for_next_block(node_bip110), False)

        # RPC surface pre-fork: no rules entry, deployment reported inactive.
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)
        # A node without RDTS scheduled reports no reduced_data entry.
        assert 'reduced_data' not in node_core.getdeploymentinfo()['deployments']

        # Mine to just before the fork height
        self.log.info("Mining to just before the fork height...")
        self.generate(node_bip110, ACTIVATION_HEIGHT - 1 - node_bip110.getblockcount())
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 431)

        # =====================================================================
        # Phase 2: Test activation and chain split
        # =====================================================================
        self.log.info("Phase 2: Testing activation and chain split behavior")

        # Mine block 432 (the BLAKE2b fork block: RDTS activates here)
        self.mine_blocks_on_node(node_bip110, 1)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 432)
        assert_equal(self.rdts_active_for_next_block(node_bip110), True)
        self.log.info("Block 432 mined: the deployment is active")

        # RPC surface post-fork: rules entry present, deployment reported active.
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)

        # Disconnect nodes BEFORE creating invalid block to prevent P2P relay
        # (Bitcoin Core relays blocks via compact blocks before full validation completes)
        self.log.info("Disconnecting nodes for chain split test...")
        self.disconnect_nodes(0, 1)

        # Create the invalid block (84-byte OP_RETURN violates BIP-110's 83-byte limit)
        self.log.info("Test: BIP-110 node rejects block with 84-byte OP_RETURN output")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])

        # Submit to BIP-110 node - should be rejected
        result_bip110 = node_bip110.submitblock(block_invalid.serialize().hex())
        assert_equal(result_bip110, 'bad-txns-vout-script-toolarge')
        assert_equal(node_bip110.getblockcount(), 432)

        # Submit to non-BIP-110 node - should be accepted
        self.log.info("Test: Non-BIP-110 node accepts the same block")
        result_core = node_core.submitblock(block_invalid.serialize().hex())
        assert_equal(result_core, None)
        assert_equal(node_core.getblockcount(), 433)

        # Chain split confirmed
        self.log.info(f"Chain split: BIP-110={node_bip110.getblockcount()}, Core={node_core.getblockcount()}")

        # =====================================================================
        # Phase 3: Test reorg behavior
        # =====================================================================
        self.log.info("Phase 3: Testing reorg behavior")

        # Non-BIP-110 extends its chain
        self.log.info("Non-BIP-110 node extends chain with 3 more blocks...")
        for i in range(3):
            block = self.create_block_for_node(node_core, time_offset=i)
            node_core.submitblock(block.serialize().hex())
        assert_equal(node_core.getblockcount(), 436)

        # BIP-110 node builds longer valid chain
        self.log.info("BIP-110 node builds longer valid chain (5 blocks)...")
        for i in range(5):
            block = self.create_block_for_node(node_bip110, time_offset=i+10)
            node_bip110.submitblock(block.serialize().hex())
        assert_equal(node_bip110.getblockcount(), 437)

        # Reconnect - non-BIP-110 should reorg to BIP-110's chain
        self.log.info("Reconnecting nodes - expecting reorg...")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(node_core.getbestblockhash(), node_bip110.getbestblockhash())
        assert_equal(node_core.getblockcount(), 437)
        self.log.info(f"Reorg complete: both nodes at height {node_core.getblockcount()}")

        # =====================================================================
        # Phase 4: Test rules enforced until expiry
        # =====================================================================
        self.log.info("Phase 4: Testing rules enforced until expiry")

        # Mine toward expiry. Freeze both nodes' clocks at EXPIRY_TIME from
        # height 569, so blocks 570-574 are stamped exactly EXPIRY_TIME and the
        # median-time-past reaches it exactly when block 576 is validated:
        # block 575 is the last RDTS block, as in the original schedule.
        blocks_to_569 = 569 - node_bip110.getblockcount()
        self.log.info(f"Mining {blocks_to_569} blocks to reach block 569...")
        self.generate(node_bip110, blocks_to_569)
        self.sync_all()
        node_bip110.setmocktime(EXPIRY_TIME)
        node_core.setmocktime(EXPIRY_TIME)
        self.generate(node_bip110, 5)  # blocks 570-574, all at EXPIRY_TIME
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 574)

        # Disconnect nodes to prevent compact block relay of invalid block
        self.disconnect_nodes(0, 1)

        # Verify rules still enforced at block 575 (last active block)
        self.log.info("Test: Rules still enforced at block 575 (last active block)")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])
        result = node_bip110.submitblock(block_invalid.serialize().hex())
        assert_equal(result, 'bad-txns-vout-script-toolarge')

        # Mine valid block 575 (last active block)
        block_valid = self.create_block_for_node(node_bip110)
        node_bip110.submitblock(block_valid.serialize().hex())
        assert_equal(node_bip110.getblockcount(), 575)

        # Reconnect and sync
        self.connect_nodes(0, 1)
        self.sync_all()

        # =====================================================================
        # Phase 5: Test expiry - rules no longer enforced
        # =====================================================================
        self.log.info("Phase 5: Testing expiry - rules no longer enforced")

        # At block 576, deployment has expired (first expired block = 432 + 144)
        self.log.info("Test: BIP-110 node accepts 'invalid' block at height 576 (expired)")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_after_expiry = self.create_block_for_node(node_bip110, [tx_invalid])
        result = node_bip110.submitblock(block_after_expiry.serialize().hex())
        assert_equal(result, None)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 576)

        # Verify the deployment is over for the next block
        assert_equal(self.rdts_active_for_next_block(node_bip110), False)
        self.log.info("Block 576: the deployment has expired")

        # RPC surface post-expiry: rules entry gone, deployment reported inactive.
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)

        # =====================================================================
        # Phase 6: Test post-expiry convergence
        # =====================================================================
        self.log.info("Phase 6: Testing post-expiry convergence")

        # Both nodes should accept the same "invalid" blocks now
        self.log.info("Test: Both nodes accept 'invalid' blocks after expiry")
        for i in range(5):
            tx = self.create_tx_with_large_output(wallet)
            block = self.create_block_for_node(node_bip110, [tx], time_offset=i)
            result_bip110 = node_bip110.submitblock(block.serialize().hex())
            assert_equal(result_bip110, None)
            self.sync_all()
            assert_equal(node_core.getbestblockhash(), node_bip110.getbestblockhash())

        final_height = node_bip110.getblockcount()
        self.log.info(f"Final height: {final_height}, both nodes synced")

        # =====================================================================
        # Summary
        # =====================================================================
        self.log.info("All tests passed:")
        self.log.info("  - Deployment transitions (inactive -> active at the fork height -> expired by median-time-past)")
        self.log.info("  - Chain split at activation (BIP-110 rejects, Core accepts)")
        self.log.info("  - Reorg to longer valid chain on reconnect")
        self.log.info("  - Rules enforced during active period (432-575)")
        self.log.info("  - Rules not enforced after expiry (576+)")
        self.log.info("  - Post-expiry convergence (both nodes accept same blocks)")


if __name__ == '__main__':
    TemporaryDeploymentTest(__file__).main()
