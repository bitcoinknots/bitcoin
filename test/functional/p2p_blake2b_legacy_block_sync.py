#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test downloading common pre-BLAKE2b blocks from legacy Bitcoin implementations."""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlockHeader, NODE_BLAKE2B
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


OLD_RELEASES = [
    ("Bitcoin Core 25.0", "25.0"),
    ("Bitcoin Core 27.2", "27.2"),
    ("Bitcoin Core 28.0", "28.0"),
    ("Bitcoin Core 29.4", "29.4"),
    ("Bitcoin Knots 29.3.knots20260507", "29.3.knots20260507"),
]
COMMON_HEIGHT = len(OLD_RELEASES)
ACTIVATION_HEIGHT = COMMON_HEIGHT + 4
OLD_TIP_HEIGHT = ACTIVATION_HEIGHT + 2


class Blake2bLegacyBlockSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = len(OLD_RELEASES) * 2
        self.setup_clean_chain = True
        self.extra_args = [
            [
                f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}",
                f"-stalepeercommonheight={COMMON_HEIGHT}",
                f"-maxstaleoutbound={len(OLD_RELEASES)}",
            ]
            for _ in OLD_RELEASES
        ] + [[] for _ in OLD_RELEASES]

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            self.extra_args,
            versions=[None for _ in OLD_RELEASES] + [version for _, version in OLD_RELEASES],
        )
        self.start_nodes()

    def create_accepted_fork(self, source):
        previous_hash = int(source.getblockhash(COMMON_HEIGHT), 16)
        previous_time = source.getblockheader(source.getblockhash(COMMON_HEIGHT))["time"]
        blocks = []
        for height in range(COMMON_HEIGHT + 1, ACTIVATION_HEIGHT):
            block = create_block(
                hashprev=previous_hash,
                coinbase=create_coinbase(height=height),
                ntime=previous_time + 1,
            )
            block.solve()
            blocks.append(block)
            previous_hash = block.sha256
            previous_time = block.nTime
        return blocks

    def run_test(self):
        current_nodes = self.nodes[:len(OLD_RELEASES)]
        old_nodes = self.nodes[len(OLD_RELEASES):]

        self.log.info("Build a post-activation SHA256d fork on every legacy release")
        self.generate(old_nodes[0], OLD_TIP_HEIGHT, sync_fun=self.no_op)
        for old_node in old_nodes[1:]:
            self.connect_nodes(old_nodes[0].index, old_node.index, peer_advertises_v2=False)
            self.sync_blocks([old_nodes[0], old_node])
            self.disconnect_nodes(old_nodes[0].index, old_node.index)
        old_tip = old_nodes[0].getbestblockhash()
        for old_node in old_nodes:
            assert_equal(old_node.getblockcount(), OLD_TIP_HEIGHT)
            assert_equal(old_node.getbestblockhash(), old_tip)

        self.log.info("Give current nodes accepted-fork headers but no blocks")
        accepted_blocks = self.create_accepted_fork(old_nodes[0])
        assert int(old_nodes[0].getblockhash(COMMON_HEIGHT + 1), 16) != accepted_blocks[0].sha256
        for current_node in current_nodes:
            for height in range(1, COMMON_HEIGHT + 1):
                block_hash = old_nodes[0].getblockhash(height)
                current_node.submitheader(old_nodes[0].getblockheader(block_hash, False))
            for block in accepted_blocks:
                current_node.submitheader(CBlockHeader(block).serialize().hex())
            chain_info = current_node.getblockchaininfo()
            assert_equal(chain_info["blocks"], 0)
            assert_equal(chain_info["headers"], ACTIVATION_HEIGHT - 1)

        for (name, _), current_node, old_node in zip(OLD_RELEASES, current_nodes, old_nodes):
            self.log.info(f"Sync the common chain from {name}'s longer divergent fork")
            with current_node.assert_debug_log([f"at height={COMMON_HEIGHT} from peer="]):
                self.connect_nodes(current_node.index, old_node.index, peer_advertises_v2=False)
                self.wait_until(lambda: current_node.getblockcount() == COMMON_HEIGHT)

            peer_info = current_node.getpeerinfo()
            assert_equal(len(peer_info), 1)
            assert not int(peer_info[0]["services"], 16) & NODE_BLAKE2B
            assert_equal(peer_info[0]["startingheight"], OLD_TIP_HEIGHT)
            assert_equal(peer_info[0]["synced_headers"], COMMON_HEIGHT)
            assert peer_info[0]["bytesrecv_per_msg"].get("block", 0) > 0
            assert_equal(current_node.getbestblockhash(), old_node.getblockhash(COMMON_HEIGHT))

            for block in accepted_blocks:
                assert_equal(current_node.submitblock(block.serialize().hex()), None)
            assert_equal(current_node.getblockcount(), ACTIVATION_HEIGHT - 1)

            pong_bytes = peer_info[0]["bytesrecv_per_msg"].get("pong", 0)
            self.log.info(f"Keep {name} connected after BLAKE2b activation")
            self.generate(current_node, 1, sync_fun=self.no_op)
            assert_equal(current_node.getblockcount(), ACTIVATION_HEIGHT)
            current_node.ping()
            self.wait_until(lambda: current_node.getpeerinfo()[0]["bytesrecv_per_msg"].get("pong", 0) > pong_bytes)
            assert_equal(old_node.getblockcount(), OLD_TIP_HEIGHT)
            assert_equal(old_node.getbestblockhash(), old_tip)


if __name__ == "__main__":
    Blake2bLegacyBlockSyncTest(__file__).main()
