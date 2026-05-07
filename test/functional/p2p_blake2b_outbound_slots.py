#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test how the automatic outbound slots are filled when peers lack NODE_BLAKE2B.

Only a NODE_BLAKE2B peer can fill a persistent outbound slot: any other is
demoted to stale at the handshake and stops counting towards the target.

A SOCKS5 proxy stands in for the network, so every address the node picks out of
addrman is dialed for real and answered by a python peer with chosen services.

Case A: no fork-capable peer exists. The node fills the outbound target with
        stale peers and then stops dialing, instead of connecting to and
        dropping one peer after another.
Case B: fork-capable peers exist and no stale peer would be tolerated
        (-maxstaleoutbound=0). Every outbound-full-relay and block-relay slot
        goes to a NODE_BLAKE2B peer, and no peer without it takes one.
Case C: addrman claims NODE_BLAKE2B for peers that turn out not to have it,
        which is what a fixed seed is: net.cpp stamps those with
        SeedsServiceFlags() without knowing. The node has to dial one to find
        out, so it works through them and then stops, rather than dialing them
        over and over.
Case D: the same claim, but the peer never completes a handshake. addrman is
        never corrected, since SetServices only runs on a received VERSION, so
        the node has to fall back on the recently-tried backoff instead.
Case E: the extra peers opened past a full target, here the stale-tip one. A
        peer without the bit is refused outright there, so only a fork-capable
        one is dialed for it. Feelers stay ungated so addrman keeps being probed.
"""

import os
import socket
import threading
import time

from test_framework.messages import (
    CBlockHeader,
    NODE_BLAKE2B,
    NODE_NETWORK,
    NODE_WITNESS,
    from_hex,
    msg_headers,
)
from test_framework.p2p import NetworkThread, P2PInterface
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

PRE_FORK = NODE_NETWORK | NODE_WITNESS
FORK_CAPABLE = PRE_FORK | NODE_BLAKE2B

# src/net.h outbound targets and the src/net_processing.h -maxstaleoutbound
# default. The full-relay target and the default are equal, so case A reaches
# both limits at once.
MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8
MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2
DEFAULT_MAXSTALEOUTBOUND = 8

# Enough peers to answer both outbound targets at once, with room to spare for
# a slot being re-armed after the node drops its peer. Case B keeps some of them
# pre-fork, so that dialing one is observable rather than silently refused by the
# proxy, which is what makes its "no peer without the bit took a slot" real.
NUM_FORK_CAPABLE_LISTENERS = 14
NUM_PRE_FORK_LISTENERS = 6
NUM_LISTENERS = NUM_FORK_CAPABLE_LISTENERS + NUM_PRE_FORK_LISTENERS
# Enough pre-fork addresses that the node never runs out of ones to pick, so
# picking a fork-capable one has to be a preference rather than an accident,
# and enough fork-capable ones that it can still find the last few it needs by
# drawing from addrman. They stay a small minority of it either way.
NUM_PRE_FORK = 1000
NUM_FORK_CAPABLE = 64
# Case C works through these one at a time, so keep it to what fits the window.
NUM_LYING = 40
# Case D only needs enough to tell one dial each from dialing in a loop.
NUM_DEAD = 5
# Case E ages the tip past the 30 minutes that make it stale, in steps short
# enough that no peer trips the 20 minute inactivity timeout.
STALE_TIP_STEP = 8 * 60
STALE_TIP_STEPS = 4
# Long enough for the two connections per second the dial loop used to make.
QUIET_SECONDS = 15
# The last slot can fill while a connection is already on its way, so let that
# one land before taking the counts the quiet window is measured against.
SETTLE_SECONDS = 5

REFUSED = "peer lacks NODE_BLAKE2B and"


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Blake2bOutboundSlots(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Let the node run ThreadOpenConnections and pick its own peers.
        self.disable_autoconnect = False

    def setup_network(self):
        self.lock = threading.Lock()
        # Case C makes every listener answer without NODE_BLAKE2B, whatever the
        # address it was reached at claims in addrman.
        self.lying = False
        # Case D has the proxy close every dial instead of serving it.
        self.dead = False
        self.exhausted = []
        self.dialed = []
        self.last_dial = 0.0
        self.free = {PRE_FORK: [], FORK_CAPABLE: []}
        self.ports = {}

        conf = Socks5Configuration()
        conf.addr = ('127.0.0.1', p2p_port(self.num_nodes))
        conf.unauth = True
        conf.auth = True
        conf.keep_alive = True
        conf.destinations_factory = self.pick_destination
        self.proxy = Socks5Server(conf)
        self.proxy.start()

        self.extra_args = [[f"-proxy={conf.addr[0]}:{conf.addr[1]}", "-proxyrandomize=0",
                            "-dnsseed=0", "-fixedseeds=0", "-debug=net"]]
        self.add_nodes(self.num_nodes, self.extra_args)

    def serving(self, port, peer):
        """Wait until `peer` is the protocol the listener on `port` will hand the
        next connection. NetworkThread.listeners persists once bound, so checking
        that would be vacuous on a re-arm and would also race the window before
        the proto is installed, in which the node's dial is dropped."""
        deadline = time.time() + 10 * self.options.timeout_factor
        while time.time() < deadline:
            if NetworkThread.protos.get(('127.0.0.1', port)) is peer:
                return True
            time.sleep(0.05)
        return False

    def arm(self, idx, services):
        """Have listener `idx` answer its next connection with `services`."""
        for _ in range(10):
            # A port free when we look can be taken before the listener binds it,
            # which under a parallel test run happens often enough to matter, so
            # check the listener came up and pick another port if it did not.
            port = self.ports.setdefault(idx, free_port())
            peer = P2PInterface()
            # connect_id and connect_cb go unused: the node finds these peers
            # through the proxy, not through the addconnection RPC.
            peer.peer_accept_connection(
                connect_id=1, connect_cb=lambda a, p: None, net=self.chain,
                timeout_factor=self.options.timeout_factor,
                supports_v2_p2p=False, reconnect=False, services=services)
            NetworkThread.listen(peer, lambda a, p: None, port=port)
            if self.serving(port, peer):
                self.peers[idx] = (peer, services)
                self.free[services].append(idx)
                return
            del self.ports[idx]
        raise AssertionError(f"could not bind a listener for slot {idx}")

    def arm_listeners(self, counts):
        """Have the listeners answer their next connection, `counts` of each
        service flavor."""
        self.free = {PRE_FORK: [], FORK_CAPABLE: []}
        self.peers = {}
        idx = 0
        for services, count in counts.items():
            for _ in range(count):
                self.arm(idx, services)
                idx += 1
        assert idx <= len(self.ports)

    def wait_serving(self, predicate, timeout):
        """Wait for the node, re-arming dropped listeners as we go."""
        def check():
            self.reap()
            return predicate()
        self.wait_until(check, timeout=timeout)

    def reap(self):
        """Re-arm the listeners whose peer the node has dropped, so a slot is
        never spent for good on a connection that did not become a peer."""
        with self.lock:
            for idx, (peer, services) in list(self.peers.items()):
                if not peer.is_connected and peer.message_count.get("version"):
                    self.arm(idx, services)

    def pick_destination(self, addr, port):
        """Answer a dial with a listener advertising that address's services."""
        services = PRE_FORK if self.lying else (
            FORK_CAPABLE if addr.startswith("250.") else PRE_FORK)
        with self.lock:
            self.dialed.append(addr)
            self.last_dial = time.time()
            if self.dead:
                return None
            if not self.free[services]:
                # The proxy has already accepted, so returning None here would
                # leave the node holding a connection that never handshakes and
                # would surface as an unexplained "kept dialing" failure.
                self.exhausted.append(addr)
                return None
            idx = self.free[services].pop(0)
        return {"actual_to_addr": "127.0.0.1", "actual_to_port": self.ports[idx]}

    def seed_addrman(self, node, fork_capable):
        """Fill addrman, every address in its own /16 so it is the service flags
        and not the netgroup rule that decides which ones the node picks."""
        for n in range(fork_capable):
            node.addpeeraddress(f"250.{n}.0.1", 8333, False, FORK_CAPABLE)
        for n in range(NUM_PRE_FORK):
            node.addpeeraddress(f"{251 + n // 256}.{n % 256}.0.1", 8333, False, PRE_FORK)

    def dialing_stopped(self):
        """Nothing dialed for a while. The count of addresses worked through is
        not a reliable wait: addrman drops the occasional one to a bucket
        collision, so an exact total may never arrive."""
        with self.lock:
            return bool(self.dialed) and time.time() - self.last_dial > SETTLE_SECONDS

    def log_since(self, node, offset):
        with open(node.debug_log_path, encoding="utf8") as f:
            f.seek(offset)
            return f.read()

    def log_count(self, node, needle):
        with open(node.debug_log_path, encoding="utf8") as f:
            return f.read().count(needle)

    def outbound(self, node, conn_type, fork_capable=False):
        peers = [p for p in node.getpeerinfo() if p["connection_type"] == conn_type]
        if fork_capable:
            peers = [p for p in peers if int(p["services"], 16) & NODE_BLAKE2B]
        return peers

    def run_test(self):
        try:
            self.check_outbound_slots()
        finally:
            self.proxy.stop()

    def check_outbound_slots(self):
        node = self.nodes[0]
        target = MAX_OUTBOUND_FULL_RELAY_CONNECTIONS

        self.log.info("Case A: with no fork-capable peer, fill the target and stop dialing")
        self.arm_listeners({PRE_FORK: NUM_LISTENERS})
        self.start_node(0)
        self.seed_addrman(node, fork_capable=0)
        self.wait_serving(lambda: self.log_count(
            node, f"connected to stale outbound peer ({DEFAULT_MAXSTALEOUTBOUND}/") >= 1, timeout=60)
        assert_equal(len(self.outbound(node, "outbound-full-relay")), target)

        time.sleep(SETTLE_SECONDS)
        with self.lock:
            dialed = len(self.dialed)
        refused = self.log_count(node, REFUSED)
        time.sleep(QUIET_SECONDS)
        with self.lock:
            assert_equal(len(self.dialed), dialed)
        assert_equal(self.log_count(node, REFUSED), refused)
        assert_equal(self.exhausted, [])
        self.log.info(f"stopped after {dialed} dials, nothing further in {QUIET_SECONDS}s")

        self.log.info("Case B: with -maxstaleoutbound=0, every slot goes to a fork-capable peer")
        self.stop_node(0)
        self.dialed.clear()
        self.arm_listeners({FORK_CAPABLE: NUM_FORK_CAPABLE_LISTENERS,
                            PRE_FORK: NUM_PRE_FORK_LISTENERS})
        self.start_node(0, extra_args=self.extra_args[0] + ["-maxstaleoutbound=0"])
        # debug.log spans both cases, and case A can leave a refusal in it from a
        # connection that was already on its way when the last slot filled, so
        # count from here rather than from the start of the file.
        refused = self.log_count(node, REFUSED)
        self.seed_addrman(node, fork_capable=NUM_FORK_CAPABLE)
        self.wait_serving(lambda: len(
            self.outbound(node, "outbound-full-relay", fork_capable=True)) == target, timeout=120)
        # The block-relay slots are filled through the same preference, once the
        # full-relay target no longer claims every connection attempt.
        self.wait_serving(lambda: len(self.outbound(node, "block-relay-only", fork_capable=True))
                          == MAX_BLOCK_RELAY_ONLY_CONNECTIONS, timeout=120)
        # Some of the listeners answer without NODE_BLAKE2B, so had the node
        # dialed one it would have been dropped at the handshake and logged.
        assert_equal(self.log_count(node, REFUSED), refused)
        assert_equal(self.exhausted, [])
        self.log.info(f"all {target} outbound-full-relay and "
                      f"{MAX_BLOCK_RELAY_ONLY_CONNECTIONS} block-relay slots are NODE_BLAKE2B peers")

        self.log.info("Case C: addresses that claim NODE_BLAKE2B without having it")
        self.stop_node(0)
        # Start from an empty addrman so these are the only addresses to pick.
        for stale in ("peers.dat", "anchors.dat"):
            (node.chain_path / stale).unlink(missing_ok=True)
        self.lying = True
        self.dialed.clear()
        self.arm_listeners({PRE_FORK: NUM_LISTENERS})
        self.start_node(0)
        for n in range(NUM_LYING):
            node.addpeeraddress(f"250.{n}.0.1", 8333, False, FORK_CAPABLE)
        # Each one costs a connection to disprove, after which the handshake has
        # corrected addrman and it is not picked again.
        self.wait_serving(lambda: self.dialing_stopped(), timeout=240)
        with self.lock:
            dialed = len(self.dialed)
        assert dialed <= NUM_LYING + 2, f"{dialed} dials for {NUM_LYING} addresses looks like a loop"
        time.sleep(QUIET_SECONDS)
        with self.lock:
            assert_equal(len(self.dialed), dialed)
        assert_equal(self.exhausted, [])
        self.log.info(f"worked through {dialed} of them and stopped, "
                      f"nothing further in {QUIET_SECONDS}s")

        self.log.info("Case D: the claim is never disproven because the peer never answers")
        self.stop_node(0)
        for stale in ("peers.dat", "anchors.dat"):
            (node.chain_path / stale).unlink(missing_ok=True)
        self.dialed.clear()
        # Every dial now goes to a port nothing listens on, so no VERSION ever
        # arrives and addrman keeps the claim. -maxstaleoutbound=0 means no peer
        # without NODE_BLAKE2B would be kept, so these are the only candidates.
        # The proxy has to close too: a half-open connection would keep the
        # address's netgroup occupied and hide the re-dialing this checks for.
        self.proxy.keep_alive = False
        self.dead = True
        self.start_node(0, extra_args=self.extra_args[0] + ["-maxstaleoutbound=0"])
        for n in range(NUM_DEAD):
            node.addpeeraddress(f"250.{n}.0.1", 8333, False, FORK_CAPABLE)
        self.wait_serving(lambda: self.dialing_stopped(), timeout=240)
        with self.lock:
            dialed = len(self.dialed)
        assert dialed <= NUM_DEAD + 2, f"{dialed} dials for {NUM_DEAD} addresses looks like a loop"
        time.sleep(QUIET_SECONDS)
        with self.lock:
            assert_equal(len(self.dialed), dialed)
        self.log.info(f"tried each of {NUM_DEAD} once ({dialed} dials) and backed off, "
                      f"nothing further in {QUIET_SECONDS}s")

        self.log.info("Case E: the extra peer opened once the target is already full")
        self.stop_node(0)
        for stale in ("peers.dat", "anchors.dat"):
            (node.chain_path / stale).unlink(missing_ok=True)
        # Cases C and D left every listener answering without the bit; case E
        # needs the fork-capable ones to answer with it again.
        self.lying = False
        self.dead = False
        self.proxy.keep_alive = True
        self.dialed.clear()
        self.arm_listeners({FORK_CAPABLE: NUM_FORK_CAPABLE_LISTENERS,
                            PRE_FORK: NUM_PRE_FORK_LISTENERS})
        self.start_node(0, extra_args=self.extra_args[0] + ["-maxstaleoutbound=0"])
        self.seed_addrman(node, fork_capable=NUM_FORK_CAPABLE)
        self.wait_serving(lambda: len(
            self.outbound(node, "outbound-full-relay", fork_capable=True)) == target, timeout=120)
        self.wait_serving(lambda: len(self.outbound(node, "block-relay-only", fork_capable=True))
                          == MAX_BLOCK_RELAY_ONLY_CONNECTIONS, timeout=120)

        now = int(time.time())
        node.setmocktime(now)
        self.generate(node, 1, sync_fun=self.no_op)
        self.wait_until(lambda: not node.getblockchaininfo()["initialblockdownload"], timeout=30)
        # Each peer announces the tip, or ConsiderEviction drops them all once it
        # is 22 minutes old for never having sent a header.
        tip = from_hex(CBlockHeader(), node.getblockheader(node.getbestblockhash(), False))
        with self.lock:
            for peer, _ in self.peers.values():
                if peer.is_connected:
                    peer.send_message(msg_headers(headers=[tip]))

        def all_fresh(t):
            peers = [p for p in node.getpeerinfo() if not p["inbound"]]
            return len(peers) >= target and all(p["lastrecv"] >= t - 60 for p in peers)

        for step in range(STALE_TIP_STEPS):
            if step == STALE_TIP_STEPS - 1:
                # offset first: a feeler logged between here and the clear would
                # otherwise reach the proxy unaccounted for and read as wasted
                mark = node.debug_log_path.stat().st_size
                with self.lock:
                    self.dialed.clear()
            now += STALE_TIP_STEP
            node.setmocktime(now)
            # the ping this triggers refreshes lastrecv, so the next step cannot
            # trip the inactivity timeout
            self.wait_until(lambda: all_fresh(now), timeout=60)
            self.reap()

        self.wait_until(lambda: "Potential stale tip detected" in self.log_since(node, mark),
                        timeout=120)
        # Wait for the extra peer to actually land rather than sampling a fixed
        # window: without the preference the node works through pre-fork peers
        # to get here, so the refusals below are then certain rather than likely.
        self.wait_serving(lambda: len(self.outbound(node, "outbound-full-relay")) > target,
                          timeout=180)

        window = self.log_since(node, mark)
        feelers = {line.split("Making feeler connection to ")[1].split(":")[0]
                   for line in window.splitlines() if "Making feeler connection to " in line}
        with self.lock:
            wasted = [a for a in self.dialed if not a.startswith("250.") and a not in feelers]
        assert_equal(window.count(REFUSED), 0)
        assert_equal(wasted, [])
        self.log.info(f"stale-tip peer dialed only fork-capable addresses, "
                      f"{len(feelers)} feeler(s) unaffected")


if __name__ == '__main__':
    Blake2bOutboundSlots(__file__).main()
