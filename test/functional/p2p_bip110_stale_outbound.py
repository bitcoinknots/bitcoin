#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP-110 tolerance of stale (non-NODE_REDUCED_DATA) outbound peers.

A tolerated stale outbound peer is additional to the automatic outbound target
but still counts within -maxconnections: it gives up its outbound slot (so we
keep looking for a BIP110 peer) and is kept only while we are below our automatic
connection budget. Once we are already full it is disconnected instead, so the
total connection count never exceeds -maxconnections.
"""

import os

from test_framework.messages import (
    CBlockHeader,
    NODE_NETWORK,
    NODE_P2P_V2,
    NODE_REDUCED_DATA,
    NODE_WITNESS,
    from_hex,
    msg_headers,
    msg_version,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SUBVERSION,
    P2P_VERSION,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# A -maxconnections with plenty of room below the automatic connection budget,
# so stale peers are kept.
ROOMY = 30
# A -maxconnections of 1: a single connection already fills the budget, so a
# stale outbound peer has no room and is disconnected.
FULL = 1

# src/net.h outbound targets. A stale peer only ever fills one of these, so
# together they are the natural ceiling on tolerated stale peers.
MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8
MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2
# src/net_processing.h MAX_STALE_OUTBOUND_CONNECTIONS
MAX_STALE_OUTBOUND_CONNECTIONS = (MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
                                  + MAX_BLOCK_RELAY_ONLY_CONNECTIONS)

CHURN_ROUNDS = 25


class BIP110StaleOutboundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"]]
        # anchors.dat is only dumped when outgoing addrman connections are enabled
        self.disable_autoconnect = False

    def services(self, *, reduced_data):
        services = NODE_NETWORK | NODE_WITNESS
        if reduced_data:
            services |= NODE_REDUCED_DATA
        if self.options.v2transport:
            services |= NODE_P2P_V2
        return services

    def connect(self, node, p2p_idx, conn_type, *, reduced_data, **kwargs):
        return node.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=p2p_idx, connection_type=conn_type,
            services=self.services(reduced_data=reduced_data),
            supports_v2_p2p=self.options.v2transport,
            advertise_v2_p2p=self.options.v2transport, **kwargs)

    def outbound_count(self, node):
        return len([p for p in node.getpeerinfo() if not p["inbound"]])

    def disconnect_all(self, node, peers):
        for peer in peers:
            peer.peer_disconnect()
        for peer in peers:
            peer.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_stale_peer_kept_with_room(self):
        node = self.nodes[0]
        self.log.info("A stale outbound peer is kept when we are below the connection budget")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

        with node.assert_debug_log(["connected to non-BIP110 outbound peer (1/2)"]):
            peer = self.connect(node, 0, "outbound-full-relay", reduced_data=False)
            peer.sync_with_ping()
        assert_equal(self.outbound_count(node), 1)
        self.disconnect_all(node, [peer])

    def test_disconnect_when_target_full(self):
        node = self.nodes[0]
        self.log.info("A stale outbound peer is disconnected when its outbound target is already full")
        # Plenty of room within -maxconnections and the stale budget, so the
        # outbound target itself is what refuses the peer.
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=8"])

        # Fill the full-relay target with a mix of BIP110 and stale peers, the
        # scenario where we have fewer BIP110 peers than the target but the total
        # already meets it.
        peers = []
        n_good = MAX_OUTBOUND_FULL_RELAY_CONNECTIONS - 3
        for i in range(n_good):
            peers.append(self.connect(node, i, "outbound-full-relay", reduced_data=True))
            peers[-1].sync_with_ping()
        for i in range(n_good, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS):
            peers.append(self.connect(node, i, "outbound-full-relay", reduced_data=False))
            peers[-1].sync_with_ping()
        assert_equal(self.outbound_count(node), MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)

        # A further stale peer fills no gap, so it is dropped rather than kept as
        # an extra connection.
        target = MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
        with node.assert_debug_log([f"the outbound target is already full ({target}/{target})"]):
            self.connect(node, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, "outbound-full-relay",
                         reduced_data=False, wait_for_disconnect=True)
        self.wait_until(lambda: len(node.getpeerinfo()) == MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)
        self.disconnect_all(node, peers)

    def test_disconnect_when_full(self):
        node = self.nodes[0]
        self.log.info("A stale outbound peer is disconnected when we are already at the connection budget")
        # -maxconnections=1: the peer itself fills the budget, so there is no room
        # to keep it as an additional connection.
        self.restart_node(0, extra_args=[f"-maxconnections={FULL}", "-maxstaleoutbound=2"])

        with node.assert_debug_log(["no room within -maxconnections"]):
            self.connect(node, 0, "outbound-full-relay", reduced_data=False,
                         wait_for_disconnect=True)
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        # A BIP110 peer is unaffected: it takes the ordinary outbound slot.
        peer = self.connect(node, 0, "outbound-full-relay", reduced_data=True)
        peer.sync_with_ping()
        assert_equal(self.outbound_count(node), 1)
        self.disconnect_all(node, [peer])

    def test_stale_peer_displaces_inbound(self):
        node = self.nodes[0]
        self.log.info("A stale outbound peer displaces an inbound slot (no overshoot of -maxconnections)")
        # 11 automatic outbound + 1 inbound = 12, so m_max_inbound == 1. One stale
        # outbound peer then leaves no inbound room, so the next inbound is refused
        # and the total never exceeds -maxconnections.
        self.restart_node(0, extra_args=["-maxconnections=12", "-maxstaleoutbound=2"])

        stale = self.connect(node, 0, "outbound-full-relay", reduced_data=False)
        stale.sync_with_ping()
        assert_equal(self.outbound_count(node), 1)

        rejected = P2PInterface()
        with node.assert_debug_log(["connection dropped (full)"]):
            node.add_p2p_connection(rejected, expect_success=False)
            rejected.wait_for_disconnect()
        assert_equal(len(node.getpeerinfo()), 1)
        self.disconnect_all(node, [stale])

    def test_short_lived_conns_are_not_gated(self):
        node = self.nodes[0]
        self.log.info("addr-fetch/feeler peers are not subject to the stale peer budget")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=0"])

        # With no stale budget, a stale full-relay peer is dropped before marking.
        with node.assert_debug_log(["peer lacks NODE_REDUCED_DATA and already have 0 non-BIP110 outbound peers"]):
            self.connect(node, 0, "outbound-full-relay", reduced_data=False,
                         wait_for_disconnect=True)
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        # A stale addr-fetch peer is not gated: it is short-lived, holds no slot,
        # and -seednode bootstrap depends on it.
        peer = self.connect(node, 0, "addr-fetch", reduced_data=False)
        peer.sync_with_ping()
        assert_equal(len(node.getpeerinfo()), 1)
        self.disconnect_all(node, [peer])

    def test_budget_survives_churn(self):
        node = self.nodes[0]
        self.log.info("The stale peer budget is not leaked by peers dropped mid-handshake")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

        # Tearing the peer down without waiting for verack lands the disconnect
        # while the version handler is still running, racing the demotion against
        # the socket handler's cleanup. The tolerated count is derived from the
        # peers themselves, so churn must not leave it drifting upwards, which
        # would make the node start refusing stale peers.
        for i in range(CHURN_ROUNDS):
            peer = self.connect(node, i % 2, "outbound-full-relay",
                                reduced_data=False, wait_for_verack=False)
            peer.peer_disconnect()
            peer.wait_for_disconnect()
            self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        # The whole budget must still be available.
        peers = []
        for i in range(2):
            peers.append(self.connect(node, i, "outbound-full-relay", reduced_data=False))
            peers[-1].sync_with_ping()
        assert_equal(self.outbound_count(node), 2)
        self.disconnect_all(node, peers)

    def test_redundant_version_does_not_double_count(self):
        node = self.nodes[0]
        self.log.info("A redundant version message does not spend the budget twice")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

        peer = self.connect(node, 0, "outbound-full-relay", reduced_data=False)
        peer.sync_with_ping()

        version = msg_version()
        version.nVersion = P2P_VERSION
        version.strSubVer = P2P_SUBVERSION
        version.nServices = self.services(reduced_data=False)
        version.nStartingHeight = 0
        with node.assert_debug_log(["redundant version message"]):
            peer.send_message(version)
            peer.sync_with_ping()

        # Only one budget slot was spent, so a second stale peer still gets in.
        second = self.connect(node, 1, "outbound-full-relay", reduced_data=False)
        second.sync_with_ping()
        assert_equal(self.outbound_count(node), 2)
        self.disconnect_all(node, [peer, second])

    def test_budget_is_clamped(self):
        node = self.nodes[0]
        self.log.info("-maxstaleoutbound is clamped to MAX_STALE_OUTBOUND_CONNECTIONS")
        # ROOMY is well above the automatic budget, so every stale peer that fits
        # an outbound target is kept.
        self.stop_node(0)
        self.start_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=1000"])

        # Each outbound target is filled entirely by stale peers, so together they
        # reach exactly the clamped budget.
        peers = []
        idx = 0
        for _ in range(MAX_OUTBOUND_FULL_RELAY_CONNECTIONS):
            peers.append(self.connect(node, idx, "outbound-full-relay", reduced_data=False))
            peers[-1].sync_with_ping()
            idx += 1
        # One more full-relay peer has no gap left to fill, so it is disconnected
        # by the target check while the budget still has room.
        target = MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
        with node.assert_debug_log([f"the outbound target is already full ({target}/{target})"]):
            self.connect(node, idx, "outbound-full-relay", reduced_data=False,
                         wait_for_disconnect=True)
        idx += 1

        # The block-relay target takes the rest, so both targets full of stale
        # peers is exactly the clamped budget: the per-target caps and
        # MAX_STALE_OUTBOUND_CONNECTIONS agree.
        for _ in range(MAX_BLOCK_RELAY_ONLY_CONNECTIONS - 1):
            peers.append(self.connect(node, idx, "block-relay-only", reduced_data=False))
            peers[-1].sync_with_ping()
            idx += 1
        # The last one brings us to the clamped budget, so the per-target caps and
        # MAX_STALE_OUTBOUND_CONNECTIONS agree on the ceiling.
        with node.assert_debug_log(
                [f"connected to non-BIP110 outbound peer ({MAX_STALE_OUTBOUND_CONNECTIONS}/"
                 f"{MAX_STALE_OUTBOUND_CONNECTIONS})"]):
            peers.append(self.connect(node, idx, "block-relay-only", reduced_data=False))
            peers[-1].sync_with_ping()
        assert_equal(self.outbound_count(node), MAX_STALE_OUTBOUND_CONNECTIONS)
        self.disconnect_all(node, peers)

        # Over-large values are reported rather than silently reduced.
        self.stop_node(0, expected_stderr=(
            f"Warning: Reducing -maxstaleoutbound from 1000 to "
            f"{MAX_STALE_OUTBOUND_CONNECTIONS}, the maximum supported value."))
        self.start_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

    def test_stale_peers_do_not_take_protect_slots(self):
        node = self.nodes[0]
        self.log.info("Stale peers do not consume the chain-sync protection slots")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=8"])
        self.generateblock(node, output="raw(42)", transactions=[])
        tip_header = from_hex(CBlockHeader(), node.getblockheader(node.getbestblockhash(), False))

        # Only 4 peers can be protected from the lagging-chain eviction. Stale
        # peers connect first-come, so letting them take those slots would leave
        # the BIP110 peers unprotected.
        good = self.connect(node, 0, "outbound-full-relay", reduced_data=True)
        with node.assert_debug_log(["Protecting outbound peer"]):
            good.send_and_ping(msg_headers([tip_header]))

        stale = self.connect(node, 1, "outbound-full-relay", reduced_data=False)
        with node.assert_debug_log(["received: headers"],
                                   unexpected_msgs=["Protecting outbound peer"]):
            stale.send_and_ping(msg_headers([tip_header]))

        self.disconnect_all(node, [good, stale])

    def test_stale_peers_are_not_anchored(self):
        node = self.nodes[0]
        self.log.info("Stale block-relay peers must not be written to anchors.dat")
        self.restart_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

        good = self.connect(node, 0, "block-relay-only", reduced_data=True)
        good.sync_with_ping()
        stale = self.connect(node, 1, "block-relay-only", reduced_data=False)
        stale.sync_with_ping()
        assert_equal(self.outbound_count(node), 2)

        ports = {}
        for info in node.getpeerinfo():
            assert_equal(info["connection_type"], "block-relay-only")
            ports[info["addr"]] = info["services"]
        good_addr = [a for a, s in ports.items() if int(s, 16) & NODE_REDUCED_DATA]
        stale_addr = [a for a, s in ports.items() if not int(s, 16) & NODE_REDUCED_DATA]
        assert_equal(len(good_addr), 1)
        assert_equal(len(stale_addr), 1)

        anchors_path = node.chain_path / "anchors.dat"
        assert not os.path.exists(anchors_path)
        self.stop_node(0)

        with open(anchors_path, "rb") as f:
            anchors_hex = f.read().hex()

        def ip_port(addr):
            return "7f000001" + f"{int(addr.split(':')[1]):04x}"
        assert ip_port(good_addr[0]) in anchors_hex
        assert ip_port(stale_addr[0]) not in anchors_hex

        self.start_node(0, extra_args=[f"-maxconnections={ROOMY}", "-maxstaleoutbound=2"])

    def run_test(self):
        self.test_stale_peer_kept_with_room()
        self.test_disconnect_when_target_full()
        self.test_disconnect_when_full()
        self.test_stale_peer_displaces_inbound()
        self.test_short_lived_conns_are_not_gated()
        self.test_budget_survives_churn()
        self.test_redundant_version_does_not_double_count()
        self.test_budget_is_clamped()
        self.test_stale_peers_do_not_take_protect_slots()
        self.test_stale_peers_are_not_anchored()


if __name__ == '__main__':
    BIP110StaleOutboundTest(__file__).main()
