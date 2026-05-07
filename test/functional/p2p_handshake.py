#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test P2P behaviour during the handshake phase (VERSION, VERACK messages).
"""
import itertools
import random
import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CBlockHeader,
    CInv,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    NODE_BLAKE2B,
    NODE_REDUCED_DATA,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_NONE,
    NODE_P2P_V2,
    NODE_WITNESS,
    msg_block,
    msg_getblocks,
    msg_getdata,
    msg_getheaders,
    msg_headers,
    msg_sendcmpct,
    msg_sendheaders,
    msg_version,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
    p2p_lock,
)
from test_framework.util import (
    assert_equal,
    p2p_port,
)


# Desirable service flags for outbound non-pruned and pruned peers. Note that
# the desirable service flags for pruned peers are dynamic and only apply if
#  1. the peer's service flag NODE_NETWORK_LIMITED is set *and*
#  2. the local chain is close to the tip (<24h)

# Base service flags (without the preferential-peering bit)
BASE_SERVICE_FLAGS_FULL = NODE_NETWORK | NODE_WITNESS
BASE_SERVICE_FLAGS_PRUNED = NODE_NETWORK_LIMITED | NODE_WITNESS

# Full service flags (with the preferential-peering bit NODE_BLAKE2B)
FULL_SERVICE_FLAGS_FULL = NODE_NETWORK | NODE_WITNESS | NODE_REDUCED_DATA | NODE_BLAKE2B
FULL_SERVICE_FLAGS_PRUNED = NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_REDUCED_DATA | NODE_BLAKE2B


class P2PStartingHeight(P2PInterface):
    def __init__(self, starting_height):
        super().__init__()
        self.starting_height = starting_height

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nStartingHeight = self.starting_height


class P2PHandshakeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            ["-maxstaleoutbound=2",],
        ]

    def add_outbound_connection(self, node, connection_type, services, wait_for_disconnect):
        peer = node.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=0, wait_for_disconnect=wait_for_disconnect,
            connection_type=connection_type, services=services,
            supports_v2_p2p=self.options.v2transport, advertise_v2_p2p=self.options.v2transport)
        if not wait_for_disconnect:
            # check that connection is alive past the version handshake and disconnect manually
            peer.sync_with_ping()
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_desirable_service_flags(self, node, service_flag_tests, desirable_service_flags, expect_disconnect):
        """Check that connecting to a peer either fails or succeeds depending on its offered
           service flags in the VERSION message. The test is exercised for all relevant
           outbound connection types where the desirable service flags check is done."""
        CONNECTION_TYPES = ["outbound-full-relay", "block-relay-only", "addr-fetch"]
        for conn_type, services in itertools.product(CONNECTION_TYPES, service_flag_tests):
            if self.options.v2transport:
                services |= NODE_P2P_V2
            expected_result = "disconnect" if expect_disconnect else "connect"
            self.log.info(f'    - services 0x{services:08x}, type "{conn_type}" [{expected_result}]')
            if expect_disconnect:
                assert (services & desirable_service_flags) != desirable_service_flags
                expected_debug_log = f'does not offer the expected services ' \
                        f'({services:08x} offered, {desirable_service_flags:08x} expected)'
                with node.assert_debug_log([expected_debug_log]):
                    self.add_outbound_connection(node, conn_type, services, wait_for_disconnect=True)
            else:
                assert (services & desirable_service_flags) == desirable_service_flags
                self.add_outbound_connection(node, conn_type, services, wait_for_disconnect=False)

    def test_startingheight(self, node):
        for fake_startheight in [-2**31, -1, 0, 1000000, 2**31-1] + [random.randint(-2**31, 2**31) for _ in range(5)]:
            peer = node.add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False)
            version = msg_version()
            version.nVersion = P2P_VERSION
            version.strSubVer = P2P_SUBVERSION
            version.nServices = P2P_SERVICES
            version.nStartingHeight = fake_startheight
            peer.send_message(version)
            peer.wait_for_verack()
            peer_info = node.getpeerinfo()[-1]
            assert_equal(peer_info['startingheight'], fake_startheight)
            peer.peer_disconnect()

    def generate_at_mocktime(self, time):
        self.nodes[0].setmocktime(time)
        self.generate(self.nodes[0], 1)
        self.nodes[0].setmocktime(0)

    def test_stale_peer_header_probe(self, node):
        block_height = node.getblockcount() + 1
        self.restart_node(0, extra_args=[
            "-maxstaleoutbound=2",
            f"-testactivationheight=blake2b@{block_height + 3}",
            f"-stalepeercommonheight={block_height}",
        ])

        tip_hash = int(node.getbestblockhash(), 16)
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        block = create_block(hashprev=tip_hash, coinbase=create_coinbase(height=block_height), ntime=tip_time + 1)
        block.solve()
        node.submitheader(CBlockHeader(block).serialize().hex())
        assert_equal(node.getblockcount(), block_height - 1)

        legacy_peer = node.add_outbound_p2p_connection(
            P2PInterface(),
            p2p_idx=0,
            connection_type="outbound-full-relay",
            services=BASE_SERVICE_FLAGS_FULL,
            supports_v2_p2p=self.options.v2transport,
            advertise_v2_p2p=self.options.v2transport,
        )
        legacy_peer.wait_until(lambda: "getheaders" in legacy_peer.last_message)
        with p2p_lock:
            request = legacy_peer.last_message["getheaders"]
            assert_equal(request.locator.vHave, [])
            assert_equal(request.hashstop, block.sha256)
            assert_equal(legacy_peer.message_count["getheaders"], 1)

        legacy_peer.send_message(msg_headers([block]))
        legacy_peer.wait_for_getdata([block.sha256])
        legacy_peer.send_message(msg_block(block))
        self.wait_until(lambda: node.getblockcount() == block_height)

        request = msg_getheaders()
        request.locator.vHave = [tip_hash]
        headers_count = legacy_peer.message_count["headers"]
        legacy_peer.send_message(request)
        legacy_peer.wait_until(lambda: legacy_peer.message_count["headers"] > headers_count)
        with p2p_lock:
            headers = legacy_peer.last_message["headers"].headers
            assert_equal(len(headers), 1)
            assert_equal(headers[0].rehash(), block.sha256)

        legacy_peer.send_message(msg_sendheaders())
        legacy_peer.send_message(msg_sendcmpct(announce=True, version=2))
        legacy_peer.sync_with_ping()
        with p2p_lock:
            announcement_counts = {
                msg_type: legacy_peer.message_count[msg_type]
                for msg_type in ["cmpctblock", "headers", "inv"]
            }

        post_common_hashes = [int(block_hash, 16) for block_hash in self.generate(node, 3)]
        legacy_peer.sync_with_ping()
        with p2p_lock:
            for msg_type, count in announcement_counts.items():
                assert_equal(legacy_peer.message_count[msg_type], count)

        headers_count = legacy_peer.message_count["headers"]
        legacy_peer.send_message(request)
        legacy_peer.wait_until(lambda: legacy_peer.message_count["headers"] > headers_count)
        with p2p_lock:
            headers = legacy_peer.last_message["headers"].headers
            assert_equal(len(headers), 1)
            assert_equal(headers[0].rehash(), block.sha256)

        getblocks = msg_getblocks()
        getblocks.locator.vHave = [tip_hash]
        inv_count = legacy_peer.message_count["inv"]
        legacy_peer.send_message(getblocks)
        legacy_peer.wait_until(lambda: legacy_peer.message_count["inv"] > inv_count)
        with p2p_lock:
            inv = legacy_peer.last_message["inv"].inv
            assert_equal(len(inv), 1)
            assert_equal(inv[0].hash, block.sha256)
        legacy_peer.wait_for_block(block.sha256)

        with p2p_lock:
            legacy_peer.last_message.pop("block", None)
            block_count = legacy_peer.message_count["block"]
        legacy_peer.send_message(msg_getdata(inv=[CInv(MSG_BLOCK | MSG_WITNESS_FLAG, block_hash) for block_hash in post_common_hashes]))
        legacy_peer.sync_with_ping()
        with p2p_lock:
            assert_equal(legacy_peer.message_count["block"], block_count)

        legacy_peer.peer_disconnect()
        legacy_peer.wait_for_disconnect()

        stalled_height = block_height - 2
        empty_peer = node.add_outbound_p2p_connection(
            P2PStartingHeight(stalled_height),
            p2p_idx=0,
            connection_type="outbound-full-relay",
            services=BASE_SERVICE_FLAGS_FULL,
            supports_v2_p2p=self.options.v2transport,
            advertise_v2_p2p=self.options.v2transport,
        )
        empty_peer.wait_until(lambda: "getheaders" in empty_peer.last_message)
        with p2p_lock:
            request = empty_peer.last_message["getheaders"]
            assert_equal(request.locator.vHave, [])
            assert_equal(request.hashstop, int(node.getblockhash(stalled_height), 16))
        empty_peer.send_message(msg_headers())
        empty_peer.sync_with_ping()
        with p2p_lock:
            assert_equal(empty_peer.message_count["getheaders"], 1)
        empty_peer.peer_disconnect()
        empty_peer.wait_for_disconnect()

        blake2b_peer = node.add_p2p_connection(P2PInterface(), services=FULL_SERVICE_FLAGS_FULL)
        blake2b_peer.wait_until(lambda: "getheaders" in blake2b_peer.last_message)
        with p2p_lock:
            request = blake2b_peer.last_message["getheaders"]
            assert request.locator.vHave
            assert_equal(request.hashstop, 0)

        node.disconnect_p2ps()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Check that peers lacking base service flags are disconnected")
        # These should always be disconnected regardless of the stale-peer budget
        self.test_desirable_service_flags(node, [NODE_NONE, NODE_NETWORK, NODE_WITNESS],
                                          BASE_SERVICE_FLAGS_FULL, expect_disconnect=True)

        self.log.info("Check that first 2 stale peers connect, 3rd is rejected")
        # Connect first 2 stale peers and keep them connected. A stale peer may
        # well advertise NODE_REDUCED_DATA (eg an unupgraded Knots node); what
        # makes it stale is the missing NODE_BLAKE2B.
        stale_services = NODE_NETWORK | NODE_WITNESS | NODE_REDUCED_DATA
        if self.options.v2transport:
            stale_services |= NODE_P2P_V2
        peer1 = node.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=0, wait_for_disconnect=False,
            connection_type="outbound-full-relay", services=stale_services,
            supports_v2_p2p=self.options.v2transport, advertise_v2_p2p=self.options.v2transport)
        peer1.sync_with_ping()
        peer2 = node.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=1, wait_for_disconnect=False,
            connection_type="outbound-full-relay", services=stale_services,
            supports_v2_p2p=self.options.v2transport, advertise_v2_p2p=self.options.v2transport)
        peer2.sync_with_ping()
        assert len(node.getpeerinfo()) == 2
        # Third stale peer should be rejected
        with node.assert_debug_log(["peer lacks NODE_BLAKE2B and already have 2 stale outbound peers"]):
            node.add_outbound_p2p_connection(
                P2PInterface(), p2p_idx=2, wait_for_disconnect=True,
                connection_type="outbound-full-relay", services=stale_services,
                supports_v2_p2p=self.options.v2transport, advertise_v2_p2p=self.options.v2transport)
        # Clean up - disconnect the 2 stale peers
        peer1.peer_disconnect()
        peer2.peer_disconnect()
        peer1.wait_for_disconnect()
        peer2.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Check that preferred peers always connect")
        self.test_desirable_service_flags(node, [FULL_SERVICE_FLAGS_FULL],
                                          BASE_SERVICE_FLAGS_FULL, expect_disconnect=False)

        self.log.info("Check that limited peers are only desired if the local chain is close to the tip (<24h)")
        self.generate_at_mocktime(int(time.time()) - 25 * 3600)  # tip outside the 24h window, should fail
        self.test_desirable_service_flags(node, [FULL_SERVICE_FLAGS_PRUNED],
                                          BASE_SERVICE_FLAGS_FULL, expect_disconnect=True)
        self.generate_at_mocktime(int(time.time()) - 23 * 3600)  # tip inside the 24h window, should succeed
        self.test_desirable_service_flags(node, [FULL_SERVICE_FLAGS_PRUNED],
                                          BASE_SERVICE_FLAGS_PRUNED, expect_disconnect=False)

        self.log.info("Check that feeler connections get disconnected immediately")
        with node.assert_debug_log(["feeler connection completed"]):
            self.add_outbound_connection(node, "feeler", NODE_NONE, wait_for_disconnect=True)

        self.log.info("Check that connecting to ourself leads to immediate disconnect")
        with node.assert_debug_log(["connected to self", "disconnecting"]):
            node_listen_addr = f"127.0.0.1:{p2p_port(0)}"
            node.addconnection(node_listen_addr, "outbound-full-relay", self.options.v2transport)
            self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Check that peer's announced starting height is remembered")
        self.test_startingheight(node)

        self.log.info("Check that stale peers receive only a bounded common-header probe")
        self.test_stale_peer_header_probe(node)


if __name__ == '__main__':
    P2PHandshakeTest(__file__).main()
