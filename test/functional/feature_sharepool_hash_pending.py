#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Retained pending block bodies are not repeatedly downloaded for missing data."""
from pathlib import Path
import time

from feature_sharepool_hash_ledger import SharePoolHashLedgerTest
from feature_sharepool_hash_relay import RelayPeer
from hash_snapshot import HashSigner
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.messages import CBlockHeader, MSG_BLOCK, MSG_TYPE_MASK, msg_block, msg_headers
from test_framework.p2p import P2PDataStore, p2p_lock
from test_framework.util import assert_equal


class PendingBlockPeer(P2PDataStore, RelayPeer):
    def on_getdata(self, message):
        for item in message.inv:
            self.getdata_requests.append(item.hash)
            # Serve each body once. A regression records one unanswered retry,
            # so this small fixture cannot create a repeated-response loop.
            if (item.type & MSG_TYPE_MASK == MSG_BLOCK and item.hash in self.block_store and
                    self.getdata_requests.count(item.hash) == 1):
                self.send_message(msg_block(self.block_store[item.hash]))

    def requests(self, block):
        with p2p_lock:
            return self.getdata_requests.count(block.sha256)

    def advertise(self, block):
        with p2p_lock:
            self.block_store[block.sha256] = block
            self.last_block_hash = block.sha256
        self.send_and_ping(msg_headers([CBlockHeader(block)]))


class SharePoolHashPendingTest(SharePoolHashLedgerTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [["-sharepoolheight=2", "-sharepoolhashonly=1", "-sharepooladmittedledger=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(self.num_nodes)]

    def assert_no_refetch(self, peer, block, expected):
        # Exercise several ordinary message/scheduler turns while data remains
        # absent. Fail at the first repeat; do not generate a traffic workload.
        for _ in range(4):
            peer.sync_with_ping()
            assert_equal(peer.requests(block), expected)
            time.sleep(0.25)
        peer.sync_with_ping()
        assert_equal(peer.requests(block), expected)

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        # A recent native tip enables both headers direct fetch and the normal
        # download scheduler. Settlement activation remains the next block.
        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        path = Path(self.options.tmpdir) / "pending-body-owner.key"
        try:
            signer = HashSigner.create(self.signer_binary, path, pool=0x50454e44494e47,
                                       payout_script=b"\x00\x14" + bytes([7]) * 20)
            block, snapshot, _ = self.construct(0, signer)
            block.solve()
            peer = follower.add_p2p_connection(PendingBlockPeer())
            self.log.info("One fetched native body remains pending while its snapshot is withheld")
            peer.advertise(block)
            self.wait_until(lambda: follower.getsharepoolhashstatus()["pending_blocks"] == 1)
            assert_equal(follower.getblockcount(), 1)
            self.assert_no_refetch(peer, block, 1)
            peer.advertise(block)
            self.assert_no_refetch(peer, block, 1)

            self.log.info("Restart retains the pending body; renewed announcements do not download it again")
            follower.disconnect_p2ps()
            self.restart_node(1)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            peer = follower.add_p2p_connection(PendingBlockPeer())
            peer.advertise(block)
            self.assert_no_refetch(peer, block, 0)
            assert_equal(follower.getblockcount(), 1)

            self.log.info("Supplying the opening triggers ordinary full validation and clears pending state")
            self.store(1, snapshot)
            self.wait_until(lambda: follower.getbestblockhash() == block.hash)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 0)
            assert_equal(peer.requests(block), 0)
            assert_equal(follower.verifychain(4, 0), True)
            follower.disconnect_p2ps()
            self.publish(0, block, snapshot)
            self.connect_nodes(0, 1)
            self.wait_tip(block)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashPendingTest(__file__).main()
