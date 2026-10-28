#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the download permission lets a peer without NODE_BLAKE2B past the fork.

A peer that does not advertise NODE_BLAKE2B is served headers, blocks and block
announcements only up to the stale-peer common height. With the download
permission (-whitelist=download@..., or a bare -whitelist entry, whose default
permissions include noban and so download) it is served past the fork anyway.
A whitelist entry without download does not qualify.
"""

from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    NODE_NONE,
    msg_getblocks,
    msg_getdata,
    msg_getheaders,
    msg_sendcmpct,
    msg_sendheaders,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# The cached chain is 200 blocks. Blocks 201 and 202 are still v1 but, as on
# mainnet, already above the common height, so stale peers do not get them either.
COMMON_HEIGHT = 200
FORK_HEIGHT = 203
# What an indexer that does not set the bit advertises (electrs sent no services at all).
INDEXER_SERVICES = NODE_NONE
ANNOUNCEMENTS = ["cmpctblock", "headers", "inv"]


class Blake2bDownloadPermissionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.fork_args = [
            f"-testactivationheight=blake2b@{FORK_HEIGHT}",
            f"-stalepeercommonheight={COMMON_HEIGHT}",
        ]
        self.extra_args = [
            self.fork_args + ["-whitelist=download@127.0.0.1"],
            self.fork_args,
        ]

    def announcement_counts(self, peer):
        with p2p_lock:
            return {msg_type: peer.message_count[msg_type] for msg_type in ANNOUNCEMENTS}

    def check_announcement(self, node, peer, served, msg_type):
        """Mine a block and check that the peer gets it announced as msg_type, or not at all."""
        before = self.announcement_counts(peer)
        block_hash = self.generate(node, 1)[0]
        if served:
            peer.wait_until(lambda: peer.message_count[msg_type] > before[msg_type])
            with p2p_lock:
                announced = peer.last_message[msg_type]
                if msg_type == "inv":
                    assert_equal([inv.hash for inv in announced.inv], [int(block_hash, 16)])
                elif msg_type == "headers":
                    assert_equal([header.rehash() for header in announced.headers], [int(block_hash, 16)])
                else:
                    assert_equal(announced.header_and_shortids.header.rehash(), int(block_hash, 16))
            before[msg_type] += 1
        peer.sync_with_ping()
        assert_equal(self.announcement_counts(peer), before)

    def check_peer(self, node, served):
        """Connect a peer without NODE_BLAKE2B and check what the node serves it past the common height."""
        tip_height = node.getblockcount()
        assert tip_height > FORK_HEIGHT
        common_hash = int(node.getblockhash(COMMON_HEIGHT), 16)
        post_common = [int(node.getblockhash(height), 16) for height in range(COMMON_HEIGHT + 1, tip_height + 1)]
        self.log.info(f"  getheaders, getblocks and getdata past height {COMMON_HEIGHT}: {'served' if served else 'nothing'}")
        peer = node.add_p2p_connection(P2PInterface(), services=INDEXER_SERVICES)

        request = msg_getheaders()
        request.locator.vHave = [common_hash]
        peer.send_and_ping(request)
        with p2p_lock:
            headers = [header.rehash() for header in peer.last_message["headers"].headers]
        assert_equal(headers, post_common if served else [])

        inv_count = peer.message_count["inv"]
        getblocks = msg_getblocks()
        getblocks.locator.vHave = [common_hash]
        if served:
            peer.send_message(getblocks)
            peer.wait_until(lambda: peer.message_count["inv"] > inv_count)
            with p2p_lock:
                assert_equal([inv.hash for inv in peer.last_message["inv"].inv], post_common)
        else:
            peer.send_and_ping(getblocks)
            assert_equal(peer.message_count["inv"], inv_count)

        block_count = peer.message_count["block"]
        peer.send_message(msg_getdata(inv=[CInv(MSG_BLOCK | MSG_WITNESS_FLAG, post_common[-1])]))
        if served:
            peer.wait_for_block(post_common[-1])
        else:
            peer.sync_with_ping()
            assert_equal(peer.message_count["block"], block_count)

        self.log.info(f"  new block announcements: {'inv, headers and cmpctblock' if served else 'none'}")
        self.check_announcement(node, peer, served, "inv")
        # Headers and compact block announcements need the node to know that the
        # peer has the previous block, which a getheaders at the tip tells it.
        request.locator.vHave = [int(node.getbestblockhash(), 16)]
        peer.send_and_ping(request)
        peer.send_and_ping(msg_sendheaders())
        self.check_announcement(node, peer, served, "headers")
        peer.send_and_ping(msg_sendcmpct(announce=True, version=2))
        self.check_announcement(node, peer, served, "cmpctblock")

        node.disconnect_p2ps()

    def run_test(self):
        self.generate(self.nodes[0], FORK_HEIGHT + 2 - COMMON_HEIGHT)
        assert_equal(self.nodes[0].getblockcount(), FORK_HEIGHT + 2)

        self.log.info("A peer without NODE_BLAKE2B gets nothing past the common height")
        self.check_peer(self.nodes[1], served=False)

        self.log.info("Nor with a whitelist entry that lacks the download permission")
        self.restart_node(1, extra_args=self.fork_args + ["-whitelist=relay,mempool@127.0.0.1"])
        self.connect_nodes(0, 1)
        self.check_peer(self.nodes[1], served=False)

        self.log.info("With the download permission it is served past the fork")
        self.check_peer(self.nodes[0], served=True)

        self.log.info("A bare whitelist entry carries noban, and so download")
        self.restart_node(0, extra_args=self.fork_args + ["-whitelist=127.0.0.1"])
        self.connect_nodes(0, 1)
        self.check_peer(self.nodes[0], served=True)


if __name__ == '__main__':
    Blake2bDownloadPermissionTest(__file__).main()
