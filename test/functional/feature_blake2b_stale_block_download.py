#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Confirm a stale (non-NODE_BLAKE2B) outbound peer is still used to download blocks.

A non-NODE_BLAKE2B outbound peer is demoted to stale outbound (it gives up its
outbound slot so we keep seeking a preferred peer), but it stays a full block-relay
peer. This confirms the node still requests and accepts a block announced by such a
peer, i.e. old nodes remain usable for block download.
"""
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    NODE_NETWORK,
    NODE_REDUCED_DATA,
    NODE_WITNESS,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# An unupgraded (eg Knots) node: has data services but not NODE_BLAKE2B.
STALE_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_REDUCED_DATA


class Blake2bStaleBlockDownload(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-maxstaleoutbound=2"]]

    def run_test(self):
        node = self.nodes[0]

        # A valid block on top of the genesis tip.
        tip = int(node.getbestblockhash(), 16)
        block = create_block(tip, create_coinbase(node.getblockcount() + 1), header_v2=False)
        block.solve()

        # A non-NODE_BLAKE2B OUTBOUND peer: the handshake demotes it to stale
        # outbound (DemoteToStaleOutbound), but it stays a block-relay peer.
        with node.assert_debug_log(["connected to stale outbound peer"]):
            peer = node.add_outbound_p2p_connection(
                P2PInterface(), p2p_idx=0, connection_type="outbound-full-relay",
                services=STALE_SERVICES)

        # Announce the block; the node must request it from this stale peer.
        peer.send_and_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_getdata([block.sha256])

        # Serve it; the node accepts it, so the block was downloaded from the stale peer.
        peer.send_and_ping(msg_block(block))
        self.wait_until(lambda: node.getbestblockhash() == block.hash)
        assert_equal(node.getbestblockhash(), block.hash)


if __name__ == '__main__':
    Blake2bStaleBlockDownload(__file__).main()
