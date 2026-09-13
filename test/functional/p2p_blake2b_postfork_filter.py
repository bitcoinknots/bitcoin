#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test refusal of peers lacking NODE_BLAKE2B once shared pre-fork history is complete.

While the next block to connect is below the fork height, peers without
NODE_BLAKE2B are accepted. From then on they are disconnected: new ones at
their version message, connected ones once the tip crosses into fork history.
"""

from test_framework.messages import (
    NODE_BLAKE2B,
    NODE_NETWORK,
    NODE_P2P_V2,
    NODE_WITNESS,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORK_HEIGHT = 20
HANDSHAKE_DROPPED = "node lacks NODE_BLAKE2B, disconnecting"
NO_LONGER_VALID = "existing node lacking NODE_BLAKE2B is no longer useful, disconnecting"


class Blake2bPostforkFilterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-testactivationheight=blake2b@{FORK_HEIGHT}",
            "-blake2b_headline=BLAKE2b functional test headline",
            "-maxconnections=30",
        ]]

    def services(self, *, blake2b):
        services = NODE_NETWORK | NODE_WITNESS
        if blake2b:
            services |= NODE_BLAKE2B
        if self.options.v2transport:
            services |= NODE_P2P_V2
        return services

    def inbound(self, *, blake2b, **kwargs):
        return self.nodes[0].add_p2p_connection(
            P2PInterface(), services=self.services(blake2b=blake2b), **kwargs)

    def outbound(self, p2p_idx, *, blake2b, **kwargs):
        return self.nodes[0].add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=p2p_idx, connection_type="outbound-full-relay",
            services=self.services(blake2b=blake2b),
            supports_v2_p2p=self.options.v2transport,
            advertise_v2_p2p=self.options.v2transport, **kwargs)

    def run_test(self):
        node = self.nodes[0]
        addr = node.get_deterministic_priv_key().address

        self.log.info("Below the fork height, peers lacking NODE_BLAKE2B are accepted")
        self.generatetoaddress(node, FORK_HEIGHT - 2, addr)
        legacy_in = self.inbound(blake2b=False)
        fork_in = self.inbound(blake2b=True)
        legacy_out = self.outbound(0, blake2b=False)
        fork_out = self.outbound(1, blake2b=True)
        for peer in (legacy_in, fork_in, legacy_out, fork_out):
            peer.sync_with_ping()
        assert_equal(len(node.getpeerinfo()), 4)

        self.log.info("Completing shared history disconnects connected peers lacking NODE_BLAKE2B")
        with node.assert_debug_log([NO_LONGER_VALID], unexpected_msgs=[HANDSHAKE_DROPPED]):
            self.generatetoaddress(node, 1, addr)
            legacy_in.wait_for_disconnect()
            legacy_out.wait_for_disconnect()
        fork_in.sync_with_ping()
        fork_out.sync_with_ping()
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)

        self.log.info("New inbound peers lacking NODE_BLAKE2B are refused at their version message")
        with node.assert_debug_log([HANDSHAKE_DROPPED], unexpected_msgs=[NO_LONGER_VALID]):
            refused = self.inbound(blake2b=False, expect_success=False)
            refused.wait_for_disconnect()

        self.log.info("New outbound peers lacking NODE_BLAKE2B are refused at their version message")
        with node.assert_debug_log([HANDSHAKE_DROPPED], unexpected_msgs=[NO_LONGER_VALID]):
            self.outbound(2, blake2b=False, wait_for_disconnect=True)
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)

        self.log.info("Peers advertising NODE_BLAKE2B still connect")
        self.inbound(blake2b=True).sync_with_ping()
        self.outbound(3, blake2b=True).sync_with_ping()
        self.wait_until(lambda: len(node.getpeerinfo()) == 4)

        self.log.info("Fork peers stay connected across the first BLAKE2b block")
        self.generatetoaddress(node, 1, addr)
        assert_equal(node.getblockcount(), FORK_HEIGHT)
        for peer in node.p2ps:
            if peer.is_connected:
                peer.sync_with_ping()
        assert_equal(len(node.getpeerinfo()), 4)


if __name__ == '__main__':
    Blake2bPostforkFilterTest(__file__).main()
