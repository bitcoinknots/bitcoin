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
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# RDTS activates at the BLAKE2b fork height (see -testactivationheight below)
ACTIVATION_HEIGHT = 432
EXPIRY_TIME = 2000000000
# Consensus weight limits: the reduced one applies while RDTS is active
REDUCED_DATA_MAX_BLOCK_WEIGHT = 800000
MAX_BLOCK_WEIGHT = 4000000
# Weight the assembler keeps free for the header and coinbase (-blockreservedweight)
DEFAULT_BLOCK_RESERVED_WEIGHT = 8000
# A witness element of this size is legal pre-RDTS (520-byte limit) and
# illegal under RDTS (256 bytes) unless the coin spent predates the fork.
VIOLATING_PUSH_SIZE = 300
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

    def create_heavy_block(self, node, num_outputs, txs=None):
        """A block whose coinbase carries num_outputs maximum-size OP_RETURN
        outputs (~368 WU each), RDTS-compliant at any weight: 2200 outputs is
        ~810k WU (over the RDTS cap), 1850 is ~682k WU (under it)."""
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)['time'] + 1
        coinbase = create_coinbase(height)
        if height == ACTIVATION_HEIGHT:
            coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + HEADLINE)
        pad = CScript([OP_RETURN, b'x' * 80])  # 83 bytes, exactly the data cap
        for _ in range(num_outputs):
            coinbase.vout.append(CTxOut(0, pad))
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, ntime=block_time, txlist=txs,
                             height=height, header_v2=height >= ACTIVATION_HEIGHT)
        add_witness_commitment(block)
        block.solve()
        return block

    def create_block_of_weight(self, node, target_weight):
        """A coinbase-only block of exactly target_weight weight units (a
        multiple of 4): maximum-size OP_RETURN outputs plus one sized to fit."""
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)['time'] + 1

        def build(num_full, last_len, sig_pad):
            coinbase = create_coinbase(height)
            sig = bytes(coinbase.vin[0].scriptSig)
            if height == ACTIVATION_HEIGHT:
                sig += HEADLINE
            coinbase.vin[0].scriptSig = CScript(sig + b'\x00' * sig_pad)
            for _ in range(num_full):
                coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * 80])))
            coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * last_len])))
            coinbase.rehash()
            block = create_block(int(tip, 16), coinbase, ntime=block_time,
                                 height=height, header_v2=height >= ACTIVATION_HEIGHT)
            add_witness_commitment(block)
            return block

        # Each full output is 92 bytes (368 WU). The remainder goes into the
        # last output's data (4 WU per byte, up to 75 bytes with a single-byte
        # push) and, beyond that, into coinbase scriptSig padding.
        num_full = (target_weight - build(0, 0, 0).get_weight()) // 368
        remainder = target_weight - build(num_full, 0, 0).get_weight()
        if remainder < 0:  # the vout-count varint grew
            num_full -= 1
            remainder = target_weight - build(num_full, 0, 0).get_weight()
        assert remainder % 4 == 0 and 0 <= remainder <= 364, remainder
        last_len = min(remainder // 4, 75)
        block = build(num_full, last_len, remainder // 4 - last_len)
        assert_equal(block.get_weight(), target_weight)
        block.solve()
        return block

    def create_tx_with_large_output(self, wallet):
        """Create a transaction with 84-byte OP_RETURN (violates BIP-110's 83-byte limit)."""
        tx_dict = wallet.create_self_transfer()
        tx = tx_dict['tx']
        # 81 bytes data = 84-byte script (OP_RETURN + OP_PUSHDATA1 + len + data)
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * 81])))
        tx.rehash()
        return tx

    def create_funding_and_violating_spend(self, wallet):
        """A funding transaction paying to a P2WSH script, and a spend of it
        whose witness carries a VIOLATING_PUSH_SIZE-byte element: valid
        pre-RDTS, invalid under RDTS (the coin is created at or after the
        fork height whenever the funding transaction is mined there, so the
        per-input grandfathering does not apply)."""
        witness_script = CScript([OP_DROP, OP_TRUE])
        funding = wallet.create_self_transfer()['tx']
        funding.vout[0] = CTxOut(funding.vout[0].nValue, script_to_p2wsh_script(witness_script))
        funding.rehash()
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.sha256, 0))]
        spend.vout = [CTxOut(funding.vout[0].nValue - 1000, CScript([OP_TRUE]))]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [b'\x42' * VIOLATING_PUSH_SIZE, witness_script]
        spend.rehash()
        return funding, spend

    def assert_block_rejected_for_push_size(self, node, block):
        result = node.submitblock(block.serialize().hex())
        assert result is not None and 'Push value size limit exceeded' in result, f"Expected push-size rejection, got: {result}"

    def rdts_active_for_next_block(self, node):
        """Whether the RDTS rules apply to the next block on node's tip."""
        info = node.getblockchaininfo()
        return info['blocks'] + 1 >= ACTIVATION_HEIGHT and info['mediantime'] < EXPIRY_TIME

    def assert_gbt_rdts(self, node, *, active):
        """Check getblocktemplate's RDTS surface: the rules entry and the
        advertised weight limit (external miners must see the real cap)."""
        # 'blake2b' is a client-capability rule: required once the template
        # is a v2 (BLAKE2b) header, ignored before the fork.
        tmpl = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert_equal('reduced_data' in tmpl['rules'], active)
        assert_equal(tmpl['weightlimit'],
                     REDUCED_DATA_MAX_BLOCK_WEIGHT if active else MAX_BLOCK_WEIGHT)

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

        # Pre-fork only the 4M weight limit applies: a ~810k WU block connects.
        heavy = self.create_heavy_block(node_bip110, 2200)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()

        # Mine to two blocks before the fork height
        self.log.info("Mining to two blocks before the fork height...")
        self.generate(node_bip110, ACTIVATION_HEIGHT - 2 - node_bip110.getblockcount())
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 430)

        # Block 431 (the last pre-fork block) is outside RDTS: the RPC surface
        # says so at tip 430, and a block breaking every RDTS rule at once
        # (over the weight cap, an 84-byte OP_RETURN, a 300-byte witness
        # push) connects.
        self.log.info("Test: block 431 (the last pre-fork block) is outside RDTS")
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)
        funding, spend = self.create_funding_and_violating_spend(wallet)
        tx_invalid = self.create_tx_with_large_output(wallet)
        heavy = self.create_heavy_block(node_bip110, 2200, txs=[tx_invalid, funding, spend])
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 431)

        # Block 432 (the fork block) is under every RDTS rule: the RPC surface
        # says so at tip 431, and each violation alone rejects the block. The
        # violating spend uses a coin created in the same block, so it is not
        # grandfathered. Disconnected: blocks failing only in ConnectBlock
        # are relayed (compact blocks) before full validation, and the other
        # node would adopt them.
        self.log.info("Test: block 432 (the fork block) is under every RDTS rule")
        self.disconnect_nodes(0, 1)
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)
        heavy = self.create_heavy_block(node_bip110, 2200)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        tx_invalid = self.create_tx_with_large_output(wallet)
        block = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(block.serialize().hex()), 'bad-txns-vout-script-toolarge')
        funding, spend = self.create_funding_and_violating_spend(wallet)
        self.assert_block_rejected_for_push_size(node_bip110, self.create_block_for_node(node_bip110, [funding, spend]))
        assert_equal(node_bip110.getblockcount(), 431)
        self.connect_nodes(0, 1)

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
        # Phase 3b: the RDTS weight limit
        # =====================================================================
        self.log.info("Phase 3b: 800k WU limit enforced while the deployment is active")
        heavy = self.create_heavy_block(node_bip110, 2200)   # ~810k WU, over the cap
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        under = self.create_heavy_block(node_bip110, 1850)   # ~682k WU, under the cap
        assert_equal(node_bip110.submitblock(under.serialize().hex()), None)
        # The boundary itself: exactly 800,000 WU connects, 800,004 does not.
        over = self.create_block_of_weight(node_bip110, REDUCED_DATA_MAX_BLOCK_WEIGHT + 4)
        assert_equal(node_bip110.submitblock(over.serialize().hex()), 'bad-blk-weight-reduced_data')
        exact = self.create_block_of_weight(node_bip110, REDUCED_DATA_MAX_BLOCK_WEIGHT)
        assert_equal(node_bip110.submitblock(exact.serialize().hex()), None)
        self.sync_all()
        self.log.info("  oversize rejected, under-cap accepted, exact boundary pinned")

        # A post-fork coin whose spend violates the push-size rule; kept for
        # the expiry boundary below.
        funding, post_fork_spend = self.create_funding_and_violating_spend(wallet)
        block = self.create_block_for_node(node_bip110, [funding])
        assert_equal(node_bip110.submitblock(block.serialize().hex()), None)
        self.sync_all()

        # =====================================================================
        # Phase 3c: block assembly under the reduced limit
        # =====================================================================
        self.log.info("Phase 3c: the assembler stays within the reduced limit")
        for _ in range(9):
            wallet.send_self_transfer(from_node=node_bip110, target_vsize=25000)  # ~100k WU each
        assert node_bip110.getmempoolinfo()['bytes'] * 4 > REDUCED_DATA_MAX_BLOCK_WEIGHT
        tmpl = node_bip110.getblocktemplate({'rules': ['segwit', 'blake2b']})
        tmpl_weight = sum(tx['weight'] for tx in tmpl['transactions'])
        assert 500000 < tmpl_weight <= REDUCED_DATA_MAX_BLOCK_WEIGHT - DEFAULT_BLOCK_RESERVED_WEIGHT, tmpl_weight
        mined = node_bip110.getblock(self.generate(node_bip110, 1, sync_fun=self.no_op)[0])
        assert 500000 < mined['weight'] <= REDUCED_DATA_MAX_BLOCK_WEIGHT, mined['weight']
        self.sync_all()
        self.log.info(f"  template {tmpl_weight} WU, mined block {mined['weight']} WU")

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

        # Verify rules still enforced at block 575 (last active block): its
        # parent's median-time-past is still below the expiry although its own
        # is not, so every rule site must key on the parent's.
        self.log.info("Test: Rules still enforced at block 575 (last active block)")
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])
        result = node_bip110.submitblock(block_invalid.serialize().hex())
        assert_equal(result, 'bad-txns-vout-script-toolarge')
        heavy = self.create_heavy_block(node_bip110, 2200)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        self.assert_block_rejected_for_push_size(node_bip110, self.create_block_for_node(node_bip110, [post_fork_spend]))
        assert_equal(node_bip110.getblockcount(), 574)

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

        # At block 576, deployment has expired (first expired block = 432 + 144):
        # the RPC surface says so at tip 575, and the same spend and output
        # that were rejected one block earlier now connect.
        self.log.info("Test: BIP-110 node accepts 'invalid' block at height 576 (expired)")
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_after_expiry = self.create_block_for_node(node_bip110, [tx_invalid, post_fork_spend])
        result = node_bip110.submitblock(block_after_expiry.serialize().hex())
        assert_equal(result, None)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 576)
        # So does the heavy shape, at the first expired height after it.
        heavy = self.create_heavy_block(node_bip110, 2200)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 577)

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

        # Past expiry the 4M limit is back: the same heavy shape connects.
        heavy = self.create_heavy_block(node_bip110, 2200)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()

        # The enforcing node never latches the unknown-versionbits warning:
        # v2 headers carry the serialized v2 flag in the version field across
        # the whole post-fork stretch, and it must not read as an unknown
        # versionbits deployment.
        assert 'Unknown new rules' not in ''.join(node_bip110.getblockchaininfo()['warnings'])

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
