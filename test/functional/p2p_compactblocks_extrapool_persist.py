#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test extra pool persistence across node restarts.

Verifies that when rejecttokens=1 is enabled:
  - Transactions rejected by token policy are stored in the extra pool
  - The extra pool is saved to extrapool.dat on shutdown
  - The extra pool is loaded from extrapool.dat on startup
  - Compact block reconstruction succeeds using persisted transactions

Also verifies that with rejecttokens=0:
  - No extrapool.dat is created on shutdown
"""
import os

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    CTxOut,
    HeaderAndShortIDs,
    msg_cmpctblock,
    msg_sendcmpct,
    msg_tx,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_13,
    OP_FALSE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet


class CompactBlockP2PConn(P2PInterface):
    """P2P connection that tracks compact block messages."""
    def __init__(self):
        super().__init__()

    def clear_getblocktxn(self):
        with p2p_lock:
            self.last_message.pop("getblocktxn", None)


class ExtraPoolPersistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-rejecttokens=1",
            "-blockreconstructionextratxn=100",
            "-disablewallet",
            "-persistmempool=0",
        ]]

    def build_block_on_tip(self, node):
        """Build a block on the current tip."""
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)["mediantime"] + 1
        block = create_block(
            hashprev=int(tip, 16),
            tmpl={"height": height, "curtime": block_time},
        )
        return block

    def create_token_tx(self, wallet):
        """Create a transaction with a Runes-style OP_RETURN output.

        Uses MiniWallet to create a valid signed transaction, then appends
        a token output (OP_RETURN OP_13 <data>) which triggers rejection
        by the token policy when rejecttokens=1.

        MiniWallet uses ADDRESS_OP_TRUE mode (taproot script path with OP_TRUE),
        so outputs can be modified after signing without invalidating the witness
        (no signature to invalidate - just a script path spend with OP_TRUE).
        """
        # Create a normal self-transfer transaction via MiniWallet with
        # standard fee to pass minimum relay fee checks
        tx_info = wallet.create_self_transfer()
        tx = tx_info["tx"]

        # Append a Runes-style token output: OP_RETURN OP_13 <data>
        # This triggers "tokens-runes" rejection when rejecttokens=1
        # The output has 0 value so it doesn't affect the fee calculation
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, OP_13, OP_FALSE])))

        tx.rehash()
        return tx

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Generate coins for spending")
        self.generate(wallet, COINBASE_MATURITY + 20)

        self.test_extrapool_persistence(node, wallet)
        self.test_no_persistence_without_rejecttokens(node, wallet)

    def test_extrapool_persistence(self, node, wallet):
        """Test that extrapool.dat is created and loaded correctly."""
        self.log.info("Test 1: Extra pool persistence with rejecttokens=1")

        # Connect a P2P peer for sending transactions
        peer = node.add_p2p_connection(P2PInterface())

        # Create and send token transactions that will be rejected by policy
        # but stored in the extra pool for compact block reconstruction
        self.log.info("Sending token transactions that will be rejected by policy...")
        token_txns = []
        num_token_txs = 10
        for i in range(num_token_txs):
            tx = self.create_token_tx(wallet)
            token_txns.append(tx)
            peer.send_message(msg_tx(tx))

        # Wait for the node to process all messages
        peer.sync_with_ping()

        # Verify the transactions were NOT accepted into the mempool
        # (they should have been rejected by token policy)
        mempool = node.getrawmempool()
        for tx in token_txns:
            assert tx.hash not in mempool, f"Token tx {tx.hash} should not be in mempool"

        self.log.info("Token transactions rejected as expected (stored in extra pool)")

        # Stop the node - this triggers DumpExtraPool since rejecttokens=1
        self.log.info("Stopping node to trigger extra pool save...")
        self.stop_node(0)

        # Verify extrapool.dat exists in the data directory
        extrapool_path = os.path.join(node.chain_path, "extrapool.dat")
        assert os.path.isfile(extrapool_path), \
            f"extrapool.dat should exist at {extrapool_path} after shutdown with rejecttokens=1"
        file_size = os.path.getsize(extrapool_path)
        # File format: version(8) + count(8) + position(8) + transactions
        assert file_size > 24, \
            f"extrapool.dat should contain transaction data (size={file_size}, expected > 24 bytes)"
        self.log.info(f"extrapool.dat exists ({file_size} bytes)")

        # Restart the node - this triggers LoadExtraPool
        self.log.info("Restarting node to test extra pool loading...")
        self.start_node(0, extra_args=[
            "-rejecttokens=1",
            "-blockreconstructionextratxn=100",
            "-disablewallet",
            "-persistmempool=0",
        ])

        # Test compact block reconstruction using the persisted extra pool.
        # Build a block containing token transactions and send it as a compact block.
        # If the extra pool was loaded correctly, the node should reconstruct
        # the block without needing to request all the transactions.
        self.log.info("Testing compact block reconstruction with persisted extra pool...")
        peer2 = node.add_p2p_connection(CompactBlockP2PConn())

        # Request high-bandwidth compact block relay
        peer2.send_and_ping(msg_sendcmpct(announce=True, version=2))

        # Build a block containing our token transactions
        block = self.build_block_on_tip(node)
        for tx in token_txns:
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()

        # Send compact block (only prefilling the coinbase)
        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, prefill_list=[0], use_witness=True)

        peer2.clear_getblocktxn()
        peer2.send_and_ping(msg_cmpctblock(comp_block.to_p2p()))

        # Check whether the node needed to request transactions
        with p2p_lock:
            if "getblocktxn" in peer2.last_message:
                requested = peer2.last_message["getblocktxn"].block_txn_request.to_absolute()
                self.log.info(f"Node requested {len(requested)} transactions "
                              f"(out of {num_token_txs} token txns in block)")
                # The extra pool should have provided at least some transactions,
                # so fewer than all should be requested
                assert len(requested) < num_token_txs, \
                    (f"Expected fewer than {num_token_txs} transaction requests "
                     f"if extra pool was loaded correctly, but got {len(requested)}")
            else:
                # Best case: no requests needed at all, extra pool had everything
                self.log.info("No getblocktxn request - all transactions found "
                              "in persisted extra pool!")

        self.log.info("Extra pool persistence test PASSED")

        # Clean up connections
        node.disconnect_p2ps()

    def test_no_persistence_without_rejecttokens(self, node, wallet):
        """Test that no extrapool.dat is created when rejecttokens=0."""
        self.log.info("Test 2: No persistence with rejecttokens=0")

        # Stop the current node
        self.stop_node(0)

        # Remove any existing extrapool.dat from the previous test
        extrapool_path = os.path.join(node.chain_path, "extrapool.dat")
        if os.path.exists(extrapool_path):
            os.remove(extrapool_path)

        # Restart with rejecttokens=0 (default - no extra pool persistence)
        self.start_node(0, extra_args=[
            "-rejecttokens=0",
            "-blockreconstructionextratxn=100",
            "-disablewallet",
            "-persistmempool=0",
        ])

        # Rescan UTXOs since the node was restarted and token txns from
        # the previous test were never confirmed (UTXOs still available)
        wallet.rescan_utxos()

        # Send a few normal transactions that will be accepted into mempool
        # (with rejecttokens=0, token transactions would also be accepted,
        # but we just use normal txns to populate the extra pool via replacements)
        peer = node.add_p2p_connection(P2PInterface())
        for _ in range(5):
            wallet.send_self_transfer(from_node=node)
        peer.sync_with_ping()

        # Verify transactions are in mempool
        assert len(node.getrawmempool()) >= 5, \
            "Transactions should be in mempool with rejecttokens=0"

        # Stop the node
        self.log.info("Stopping node with rejecttokens=0...")
        self.stop_node(0)

        # Verify no extrapool.dat was created (persistence is gated on rejecttokens=1)
        assert not os.path.exists(extrapool_path), \
            (f"extrapool.dat should NOT exist with rejecttokens=0, "
             f"but found at {extrapool_path}")

        self.log.info("No-persistence test PASSED - extrapool.dat not created "
                      "with rejecttokens=0")


if __name__ == "__main__":
    ExtraPoolPersistTest(__file__).main()
