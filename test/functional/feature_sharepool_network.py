#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""SPN1 native P2P partition, reorg, restart and adversarial block relay.

All three nodes enforce the experimental regtest profile. Valid blocks enter
only one node through submitblock; the other nodes obtain them through actual
Bitcoin P2P connections. Invalid bodies enter through a P2P test peer. No pool
snapshot transport, hardware, or public network is involved in this test.
"""

from dataclasses import replace
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import apply_to_coinbase, candidate, parse_coinbase, payouts_root, solve_share
from test_framework.messages import CTxOut
from test_framework.p2p import P2PDataStore
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolNetworkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for _ in range(self.num_nodes)]
        self.noban_tx_relay = True

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

    def make(self, node, *, owner=0, parent=None, shares=(), seconds=1):
        parent = node.getbestblockhash() if parent is None else parent
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16),
            height=info["height"] + 1, ntime=max(info["time"] + seconds, self.start_time), pool=self.pool,
            secret=self.keys[owner], payout_script=self.scripts[owner], shares=shares,
            parent_manifest=self.manifests.get(parent))

    def solve(self, block):
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        return block

    def publish(self, node, block, manifest, *, peers):
        self.solve(block)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), block.hash)
        self.manifests[block.hash] = manifest
        self.sync_blocks(nodes=peers)
        for peer in peers:
            assert_equal(peer.getbestblockhash(), block.hash)
            # Each peer independently decodes the full coinbase it received.
            raw = peer.getblock(block.hash, 0)
            assert_equal(raw, block.serialize().hex())
        return block.hash

    def active_manifest(self, node):
        from io import BytesIO
        from test_framework.messages import CBlock
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(node.getblock(node.getbestblockhash(), 0))))
        return parse_coinbase(block.vtx[0])[0]

    def reject_p2p(self, node, block, reason):
        self.solve(block)
        before = node.getbestblockhash()
        peer = node.add_p2p_connection(P2PDataStore())
        peer.send_blocks_and_test([block], node, success=False, force_send=True,
                                  reject_reason=reason, timeout=10)
        assert_equal(node.getbestblockhash(), before)
        peer.peer_disconnect()
        peer.wait_for_disconnect()

    @staticmethod
    def received_block_bytes(node):
        return sum(sum(peer.get("bytesrecv_per_msg", {}).get(message, 0)
                       for message in ("block", "cmpctblock", "blocktxn"))
                   for peer in node.getpeerinfo())

    def run_test(self):
        a, b, c = self.nodes
        self.genesis = int(a.getblockhash(0), 16)
        self.pool = 0xabc123
        self.start_time = int(time.time())
        self.keys = tuple(value.to_bytes(32, "big") for value in (1, 2))
        self.scripts = (b"\x00\x14" + b"A" * 20, b"\x00\x14" + b"B" * 20)
        self.manifests = {}

        self.log.info("Activate all three nodes and verify full native block delivery through P2P")
        before_bytes = self.received_block_bytes(c)
        first, first_manifest = self.make(a)
        common = self.publish(a, first, first_manifest, peers=self.nodes)
        assert self.received_block_bytes(c) > before_bytes

        origin, origin_manifest = self.make(a, owner=1)
        share = solve_share(origin, origin_manifest)
        self.log.info("Partition node 2 before paying a common-ancestor share on nodes 0 and 1")
        self.disconnect_nodes(1, 2)
        assert_equal(c.getconnectioncount(), 0)
        left, left_manifest = self.make(a, shares=(share,))
        left_tip = self.publish(a, left, left_manifest, peers=(a, b))
        assert_equal(c.getbestblockhash(), common)
        for node in (a, b):
            assert_equal([entry.proof_id for entry in self.active_manifest(node).post_state], [share.proof_id])

        self.log.info("The isolated node builds a longer valid branch with a different snapshot")
        right, right_manifest = self.make(c, owner=1, seconds=2)
        self.publish(c, right, right_manifest, peers=(c,))
        right_next, right_next_manifest = self.make(c, owner=1)
        right_tip = self.publish(c, right_next, right_next_manifest, peers=(c,))
        assert_equal(a.getbestblockhash(), left_tip)

        self.log.info("Rejoining actual P2P peers rolls back the orphaned payout state")
        self.connect_nodes(1, 2)
        self.sync_blocks()
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), right_tip)
            assert_equal(self.active_manifest(node).post_state, ())
        assert any(tip["hash"] == left_tip and tip["status"] == "valid-fork" for tip in a.getchaintips())

        self.log.info("A share whose prior payment was orphaned can be paid on the new branch")
        settled, settled_manifest = self.make(c, shares=(share,))
        settled_tip = self.publish(c, settled, settled_manifest, peers=self.nodes)
        for node in self.nodes:
            manifest = self.active_manifest(node)
            assert_equal([entry.proof_id for entry in manifest.post_state], [share.proof_id])
            assert_equal(manifest.envelope.payouts_root, settled_manifest.envelope.payouts_root)

        self.log.info("P2P peers reject replay and a fraudulently recomputed payout commitment")
        for node in self.nodes:
            replay, _ = self.make(node, shares=(share,))
            self.reject_p2p(node, replay, "bad-sharepool-shares")
        wrong, wrong_manifest = self.make(a)
        outputs = [CTxOut(5000000000, CScript(self.scripts[1]))]
        wrong_manifest = replace(wrong_manifest,
            envelope=replace(wrong_manifest.envelope, payouts_root=payouts_root(outputs)))
        apply_to_coinbase(wrong, wrong_manifest, outputs)
        for node in self.nodes:
            self.reject_p2p(node, wrong, "bad-sharepool-payout")

        self.log.info("A stopped node recovers the next native block and its replay state over P2P")
        self.stop_node(0)
        continuation, continuation_manifest = self.make(c)
        continuation_tip = self.publish(c, continuation, continuation_manifest, peers=(b, c))
        self.start_node(0)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(a.getbestblockhash(), continuation_tip)
        assert_equal([entry.proof_id for entry in self.active_manifest(a).post_state], [share.proof_id])
        replay, _ = self.make(a, shares=(share,))
        # At height 6 this origin-height-2 share has expired. A restart cannot
        # resurrect it even after its nullifier no longer needs retention.
        self.reject_p2p(a, replay, "bad-sharepool-proof")

        self.log.info("Full reindex preserves the selected chain and retained payment state")
        self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex"])
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_blocks()
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), continuation_tip)
            assert_equal(self.active_manifest(node), continuation_manifest)
        assert_equal(a.getblockhash(4), settled_tip)


if __name__ == "__main__":
    SharePoolNetworkTest(__file__).main()
