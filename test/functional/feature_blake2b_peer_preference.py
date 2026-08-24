#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that outbound selection prefers NODE_BLAKE2B peers past the BLAKE2b fork.

A node at or past the fork skips a non-NODE_BLAKE2B addrman candidate during
outbound selection; a node with the fork unscheduled applies no preference.
"""
import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.p2p import P2PInterface
from test_framework.messages import CAddress, msg_addr, NODE_NETWORK, NODE_WITNESS, NODE_BLAKE2B

HOLD_OUT_MSG = "holding out for a NODE_BLAKE2B peer"

def _addr(ip, services):
    a = CAddress()
    a.net = CAddress.NET_IPV4
    a.ip = ip
    a.port = 8333
    a.time = int(time.time())
    a.nServices = services
    return a

class Blake2bPeerPreference(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.disable_autoconnect = False  # allow automatic addrman-based outbound
        common = ["-blake2b_headline=", "-dnsseed=0", "-fixedseeds=0", "-debug=net"]
        self.extra_args = [
            ["-testactivationheight=blake2b@2"] + common,  # node0: fork at height 2
            common,                                         # node1: Blake2bHeight unscheduled
        ]

    def run_test(self):
        # Mine one SHA256d block (below the fork) so the tip is height 1: the next
        # block would be the first BLAKE2b block, so node0 is at the fork boundary
        # (m_best_height + 1 == Blake2bHeight) and ShouldPreferBlake2bPeers() is true.
        self.generatetoaddress(self.nodes[0], 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        self.generatetoaddress(self.nodes[1], 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)

        # Inject a genuinely NON-HF address (no NODE_BLAKE2B) via a mock addr
        # message; addpeeraddress can't be used because it hardcodes NODE_BLAKE2B.
        non_hf = _addr("8.8.8.8", NODE_NETWORK | NODE_WITNESS)
        m = msg_addr()
        m.addrs = [non_hf]

        self.log.info("Past-fork node skips the non-NODE_BLAKE2B candidate")
        peer0 = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(expected_msgs=[HOLD_OUT_MSG], timeout=60):
            peer0.send_and_ping(m)

        self.log.info("Node with the fork unscheduled applies no preference")
        peer1 = self.nodes[1].add_p2p_connection(P2PInterface())
        with self.nodes[1].assert_debug_log(expected_msgs=[], unexpected_msgs=[HOLD_OUT_MSG], timeout=20):
            peer1.send_and_ping(m)

if __name__ == '__main__':
    Blake2bPeerPreference(__file__).main()
