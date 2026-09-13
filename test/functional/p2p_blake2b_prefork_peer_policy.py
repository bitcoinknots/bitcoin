#!/usr/bin/env python3
"""Local peer-management policy for peers that do not advertise NODE_BLAKE2B.

Pre-fork ("Spamcoin") peers are not refused outright -- pre-fork blocks are
immutable history and such a peer is a legitimate source of that data -- but
while at least one NODE_BLAKE2B peer is connected, we send them no
`getheaders`, in or out of our own IBD. This exclusion is not exempted for
manually-configured (-addnode/-connect) peers. It is a sync-slot efficiency
policy, not a safety one -- headers are validated against the consensus rules
for their height whoever sends them -- so it has a bootstrap fallback: with no
NODE_BLAKE2B peer connected at all we do sync headers from whoever we have,
rather than not syncing.

Disconnecting such a peer once it is no longer useful is deliberately out of
scope here; see bitcoinknots/bitcoin#412, which covers that separately and with
an earlier trigger.

Case A: a pre-fork peer's block is still accepted while we are in IBD.
Case B: no `getheaders` ever goes to the pre-fork peer, while an otherwise
        identical NODE_BLAKE2B control peer does receive one.
Case D: a manually-added pre-fork peer is excluded from header sync just the
        same -- the exclusion has no manual-peer exemption -- in or out of our
        own IBD. A NODE_BLAKE2B control peer is connected first so that the
        exclusion is in force at all -- otherwise the bootstrap fallback would
        (correctly) send the manual peer a `getheaders` and the case would be
        testing the fallback rather than the exclusion.

Cases E and F cover the `getheaders` paths a peer can trigger unilaterally,
which the header-sync trigger alone does not gate:

Case E: a `headers` message whose first header does not connect draws no
        `getheaders` for a pre-fork peer, while it does for a control peer.
Case F: an unconnecting `cmpctblock` draws no `getheaders` either. That path
        only fires out of IBD, so it reuses case D's peer on case D's node,
        which case D has already taken out of IBD -- and, as in case D, the
        exclusion is only in force there because that node also has a
        NODE_BLAKE2B peer.

Cases G and H cover the bootstrap fallback itself, on a third node kept free of
any other peer so the "no fork-aware peer connected" premise is exact:

Case G: with a single pre-fork peer and no NODE_BLAKE2B peer at all, the node
        does send `getheaders` to that pre-fork peer. This is the regression
        the fallback exists to prevent: without it such a node -- the common
        case while most of the network is still pre-fork -- would get no
        headers at all until a fork-aware peer happened to connect.
Case H: as soon as a NODE_BLAKE2B peer connects, the fallback turns off again
        and the pre-fork peer stops drawing `getheaders`, while the same
        stimulus still draws one for the NODE_BLAKE2B peer.
Case I: the reverse of case H. A NODE_BLAKE2B peer that is our active header
        sync source goes away, and the fallback comes back on by itself: the
        pre-fork peer we had been withholding `getheaders` from starts getting
        them, with no external stimulus. Nothing kicks this -- FinalizeNode()
        both uncounts the peer and hands back its `nSyncStarted` slot, and the
        next SendMessages tick re-runs the header-sync trigger -- but that is
        precisely what the case pins down, since a missed decrement would strand
        the node with no header source at all.
Case J: the fork-aware peer count survives a mix of connection orders and
        disconnect mechanisms. The count is not exposed over RPC, so each step
        is checked through the behavior it drives: whether a pre-fork peer that
        has never been sent a `getheaders` (so nothing but policy can be
        suppressing one) draws one or not.
Case K: the low-work headers-sync entry point (TryLowWorkHeadersSync) honors
        the same predicate. Reaching it needs a full 2000-header message whose
        claimed work is under the anti-DoS threshold, so these two nodes run
        with `-minimumchainwork` set, the way p2p_headers_sync_with_minchainwork
        does, instead of regtest's default threshold of zero.
"""
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    HeaderAndShortIDs,
    NODE_BLAKE2B,
    NODE_NETWORK,
    NODE_WITNESS,
    msg_block,
    msg_cmpctblock,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

HF = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B
# NODE_NETWORK is required, otherwise CanServeBlocks() is false and the
# header-sync gate under test is never reached at all.
NON_HF = NODE_NETWORK | NODE_WITNESS

# Number of full message-handler round trips to let any pending policy action
# fire (one is enough in practice; several make the negative `getheaders`
# assertions meaningful rather than merely early).
SETTLE_ROUNDS = 5

# MAX_HEADERS_RESULTS. TryLowWorkHeadersSync() only starts a low-work sync for a
# headers message of exactly this size, and PeerManager::Options::max_headers_result
# is not settable from the command line, so case K has to send a real full batch.
MAX_HEADERS_RESULTS = 2000

# Enough required chain work that 2000 regtest headers (worth 2 units each) stay
# far below it, so GetAntiDoSWorkThreshold() is nonzero and case K's headers take
# the low-work branch. Regtest's default is 0, which makes that branch unreachable.
MIN_CHAIN_WORK = "0x1000000"


class Blake2bPreforkPeerPolicy(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Nodes 2..6 each host one case group and must have no peer other than
        # the ones that case adds, so the "no fork-aware peer connected" premise
        # the bootstrap fallback keys off is exactly what the test asserts:
        #   2 -> cases G and H, 3 -> case I, 4 -> case J, 5 and 6 -> case K.
        self.num_nodes = 7
        low_work_args = ["-debug=net", f"-minimumchainwork={MIN_CHAIN_WORK}", "-checkblockindex=0"]
        self.extra_args = [["-debug=net"]] * 5 + [low_work_args] * 2

    def setup_network(self):
        # Leave the nodes unconnected; every peer in this test is explicit.
        self.setup_nodes()

    def in_ibd(self, node):
        return node.getblockchaininfo()["initialblockdownload"]

    def getheaders_count(self, p2p_conn):
        # wait_for_getheaders() pops the message, so for "never sent" assertions
        # use the monotonic counter instead.
        return p2p_conn.message_count["getheaders"]

    def add_manual_p2p_connection(self, node, p2p_conn, *, p2p_idx, services):
        """Bring up a real MANUAL connection.

        The `addconnection` RPC used by add_outbound_p2p_connection() cannot
        create MANUAL connections, so drive `addnode ... onetry` instead, using
        the same accept-connection plumbing.
        """
        def connect_cb(address, port):
            self.log.debug(f"Manually connecting to {address}:{port}")
            node.addnode(f"{address}:{port}", "onetry")

        p2p_conn.peer_accept_connection(
            connect_cb=connect_cb,
            connect_id=p2p_idx + 1,
            net=node.chain,
            timeout_factor=node.timeout_factor,
            services=services,
            # The node is the one dialling out here, so the mock peer has to
            # speak whatever transport the node was started with; hardcoding v1
            # makes the BIP324 handshake fail on magic bytes under
            # --v2transport. reconnect is False because we advertise exactly
            # what we support, so there is no v1 fallback to wait for.
            supports_v2_p2p=node.use_v2transport,
            reconnect=False,
        )()
        p2p_conn.wait_for_connect()
        node.p2ps.append(p2p_conn)
        if node.use_v2transport:
            p2p_conn.wait_until(lambda: p2p_conn.v2_state.tried_v2_handshake)
        p2p_conn.wait_until(lambda: not p2p_conn.on_connection_send_msg)
        p2p_conn.wait_for_verack()
        p2p_conn.sync_with_ping()
        return p2p_conn

    def newest_peer_id(self, node):
        """The node's id for the peer that connected most recently."""
        return max(p["id"] for p in node.getpeerinfo())

    def disconnect_and_finalize(self, node, p2p_conn, peer_id):
        """Disconnect a peer and wait until the node has finished accounting for it.

        Waiting for the connection to drop, or even for getpeerinfo() to stop
        listing the peer, is not enough: the node removes it from m_nodes in
        DisconnectNodes() but only calls FinalizeNode() -- where the fork-aware
        count is decremented -- once the last reference is released, on a later
        socket handler pass. A negative assertion made in that window can pass
        whether the count is right or wrong, which makes it worthless. The log
        line below is the last statement in FinalizeNode(), so waiting for it
        pins the assertions that follow to the post-decrement state.
        """
        with node.assert_debug_log([f"Cleared nodestate for peer={peer_id}"], timeout=60):
            p2p_conn.peer_disconnect()
            p2p_conn.wait_for_disconnect()
        self.wait_until(lambda: all(p["id"] != peer_id for p in node.getpeerinfo()), timeout=60)

    def settle(self, p2p_conn):
        for _ in range(SETTLE_ROUNDS):
            p2p_conn.sync_with_ping()

    def unconnecting_block(self, node):
        """A solved block whose parent the node has never seen.

        Announcing it is what drives both the unconnecting-headers path and the
        unconnecting-compact-block path.
        """
        tip = node.getbestblockhash()
        tip_time = node.getblockheader(tip)["time"]
        height = node.getblockcount() + 1
        # Built on the real tip, but never delivered, so the child below does not
        # connect to anything in the node's block index.
        orphan_parent = create_block(hashprev=int(tip, 16), coinbase=create_coinbase(height=height),
                                     ntime=tip_time + 1)
        orphan_parent.solve()
        child = create_block(hashprev=orphan_parent.sha256, coinbase=create_coinbase(height=height + 1),
                             ntime=tip_time + 2)
        child.solve()
        return child

    def low_work_headers(self, node, count):
        """A full, valid-PoW header chain off `node`'s tip with negligible work.

        Regtest headers are worth 2 units of chain work each, so a batch of this
        size lands far under a -minimumchainwork of MIN_CHAIN_WORK and takes
        TryLowWorkHeadersSync()'s low-work branch. The headers are never meant to
        be accepted into the block index; only the anti-DoS path is under test.
        """
        tip = node.getbestblockhash()
        prev_hash = int(tip, 16)
        prev_time = node.getblockheader(tip)["time"]
        height = node.getblockcount() + 1
        headers = []
        for _ in range(count):
            block = create_block(hashprev=prev_hash, coinbase=create_coinbase(height=height),
                                 ntime=prev_time + 1)
            block.solve()
            headers.append(CBlockHeader(block))
            prev_hash = block.sha256
            prev_time = block.nTime
            height += 1
        return headers

    def non_continuous_headers(self, node):
        """Two headers that do not connect to each other.

        CheckHeadersPoW() rejects the sequence and calls Misbehaving(), which is
        how case J gets a fork-aware peer disconnected by the punishment path
        rather than by a clean close. Both headers build on the node's tip, so
        the first one connects to our block index and only the second one breaks
        the chain -- otherwise the message would be routed to the unconnecting
        headers path instead and draw no punishment.
        """
        tip = node.getbestblockhash()
        tip_hash = int(tip, 16)
        tip_time = node.getblockheader(tip)["time"]
        height = node.getblockcount() + 1
        first = create_block(hashprev=tip_hash, coinbase=create_coinbase(height=height), ntime=tip_time + 1)
        first.solve()
        second = create_block(hashprev=tip_hash, coinbase=create_coinbase(height=height), ntime=tip_time + 2)
        second.solve()
        return [CBlockHeader(first), CBlockHeader(second)]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Case A: block data from a pre-fork peer is accepted during our IBD")
        assert self.in_ibd(node), "node should start out in IBD"
        # Connect the fork-aware control peer first, so that the exclusion is
        # in force from the moment the pre-fork peer joins. With no fork-aware
        # peer present the bootstrap fallback would (correctly) send the pre-fork
        # peer a getheaders, and cases B and E would be testing the fallback
        # instead of the exclusion. Cases G and H cover the fallback deliberately,
        # on a node kept free of fork-aware peers for the purpose.
        control = node.add_p2p_connection(P2PInterface(), services=HF)
        control.wait_for_getheaders(timeout=60)
        prefork = node.add_p2p_connection(P2PInterface(), services=NON_HF)

        tip_hash = int(node.getbestblockhash(), 16)
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        # Back-date the block so accepting it does not end our IBD (cases B and
        # E assert we are still in it); it only has to beat median-time-past.
        block = create_block(hashprev=tip_hash, coinbase=create_coinbase(height=1), ntime=tip_time + 1)
        block.solve()
        prefork.send_and_ping(msg_block(block))

        assert_equal(node.getbestblockhash(), block.hash)
        assert_equal(node.getblockcount(), 1)
        assert self.in_ibd(node), "node left IBD unexpectedly; later cases would be invalid"
        self.log.info("PASS A: tip advanced to the pre-fork peer's block, still in IBD")

        self.log.info("Case B: no getheaders to the pre-fork peer, but a control peer gets one")
        self.settle(prefork)

        assert_equal(self.getheaders_count(prefork), 0)
        assert self.getheaders_count(control) > 0, "control peer got no getheaders; test would be vacuous"
        # The pre-fork peer is excluded from header sync but still connected: the
        # policy withholds `getheaders`, it does not drop the peer.
        assert self.in_ibd(node)
        assert prefork.is_connected
        assert_equal(len(node.getpeerinfo()), 2)
        self.log.info("PASS B: pre-fork peer got 0 getheaders, control peer got "
                      f"{self.getheaders_count(control)}, both still connected")

        self.log.info("Case E: an unconnecting headers message from a pre-fork peer draws no getheaders")
        # A second control peer. nSyncStarted is already 1 and m_best_header is
        # old, so the header-sync trigger passes it over and it starts from a
        # count of 0 -- which makes it a clean positive control for the
        # unconnecting-headers path specifically, rather than for header sync.
        # The first control peer cannot serve here: it was sent a getheaders on
        # connect and is inside the HEADERS_RESPONSE_TIME window.
        control2 = node.add_p2p_connection(P2PInterface(), services=HF)
        self.settle(control2)
        assert_equal(self.getheaders_count(control2), 0)

        orphan = self.unconnecting_block(node)
        prefork.send_and_ping(msg_headers([CBlockHeader(orphan)]))
        control2.send_and_ping(msg_headers([CBlockHeader(orphan)]))
        self.settle(prefork)
        self.settle(control2)

        assert_equal(self.getheaders_count(prefork), 0)
        assert self.getheaders_count(control2) > 0, \
            "control peer got no getheaders for unconnecting headers; the case would be vacuous"
        assert self.in_ibd(node)
        assert prefork.is_connected
        self.log.info("PASS E: unconnecting headers drew 0 getheaders for the pre-fork peer, "
                      f"{self.getheaders_count(control2)} for the control peer")

        self.log.info("Case D: a manual pre-fork peer is excluded from header sync too")
        manual_node = self.nodes[1]
        assert self.in_ibd(manual_node)
        # Give this node a fork-aware peer FIRST. The exclusion only applies
        # while some NODE_BLAKE2B peer is connected; with the manual pre-fork peer
        # alone the bootstrap fallback would fire and it would rightly be sent a
        # getheaders, so the assertions below would be testing the fallback rather
        # than the manual peer's lack of exemption from the exclusion.
        manual_control = manual_node.add_p2p_connection(P2PInterface(), services=HF)
        manual_control.wait_for_getheaders(timeout=60)

        manual = self.add_manual_p2p_connection(manual_node, P2PInterface(), p2p_idx=0, services=NON_HF)

        peer_info = manual_node.getpeerinfo()
        assert_equal(len(peer_info), 2)
        manual_info = [p for p in peer_info if p["connection_type"] == "manual"]
        assert_equal(len(manual_info), 1)
        assert not int(manual_info[0]["services"], 16) & NODE_BLAKE2B
        # The premise: a fork-aware alternative exists, so the exclusion is live.
        assert any(int(p["services"], 16) & NODE_BLAKE2B for p in peer_info), \
            "no fork-aware peer on this node; case D would be testing the bootstrap fallback"

        self.settle(manual)
        assert_equal(self.getheaders_count(manual), 0)

        # Leave IBD and check again, both because the exclusion is meant to hold
        # in or out of IBD and because case F's compact-block path only fires out
        # of IBD.
        self.generate(manual_node, 1, sync_fun=self.no_op)
        self.wait_until(lambda: not self.in_ibd(manual_node), timeout=60)
        self.settle(manual)

        assert manual.is_connected, "manual pre-fork peer is gone; case F needs it"
        assert manual_control.is_connected, "fork-aware control peer was disconnected"
        assert_equal(len(manual_node.getpeerinfo()), 2)
        assert_equal(self.getheaders_count(manual), 0)
        self.log.info("PASS D: manual pre-fork peer never asked for headers, in or out of IBD, "
                      "while a fork-aware peer was available")

        self.log.info("Case F: an unconnecting compact block from a pre-fork peer draws no getheaders")
        # The compact block handler only requests deeper headers when we are out
        # of IBD, so this reuses case D's peer on case D's node, which case D has
        # already taken out of IBD. Case D's fork-aware control peer is still
        # connected, so the exclusion (rather than the fallback) is what is under
        # test here too.
        assert not self.in_ibd(manual_node)
        assert manual_control.is_connected, \
            "fork-aware peer gone; case F would be testing the bootstrap fallback"
        cmpct = HeaderAndShortIDs()
        cmpct.initialize_from_block(self.unconnecting_block(manual_node))
        manual.send_and_ping(msg_cmpctblock(cmpct.to_p2p()))
        self.settle(manual)

        assert manual.is_connected
        assert_equal(self.getheaders_count(manual), 0)
        self.log.info("PASS F: unconnecting compact block drew 0 getheaders for the pre-fork peer")

        self.log.info("Case G: with no fork-aware peer at all, a pre-fork peer does get getheaders")
        # A node of its own, still on the clean chain and with no peers yet, so
        # "we have zero NODE_BLAKE2B peers" is exactly true rather than incidental.
        boot_node = self.nodes[2]
        assert self.in_ibd(boot_node)
        assert_equal(len(boot_node.getpeerinfo()), 0)

        boot_prefork = boot_node.add_p2p_connection(P2PInterface(), services=NON_HF)
        boot_info = boot_node.getpeerinfo()
        assert_equal(len(boot_info), 1)
        assert not int(boot_info[0]["services"], 16) & NODE_BLAKE2B, \
            "the only peer must lack NODE_BLAKE2B for the fallback premise to hold"

        # The whole point of the fallback: without it this node would sit at zero
        # headers indefinitely, which is what the unconditional exclusion caused.
        boot_prefork.wait_for_getheaders(timeout=60)
        assert self.in_ibd(boot_node)
        assert boot_prefork.is_connected
        self.log.info("PASS G: pre-fork peer received "
                      f"{self.getheaders_count(boot_prefork)} getheaders with no fork-aware peer present")

        self.log.info("Case H: the fallback turns off once a fork-aware peer connects")
        prefork_baseline = self.getheaders_count(boot_prefork)
        boot_control = boot_node.add_p2p_connection(P2PInterface(), services=HF)
        # It must actually become the sync source, not merely be connected. This
        # only happens because the pre-fork peer hands back the header-sync slot
        # once the fallback stops applying to it; otherwise nSyncStarted stays 1
        # and this would block until the headers-sync timeout.
        boot_control.wait_for_getheaders(timeout=60)

        # As in case E, the positive control has to be a peer that is not already
        # inside its HEADERS_RESPONSE_TIME window -- boot_control just received a
        # getheaders, so a fresh fork-aware peer serves instead. nSyncStarted is
        # 1 and m_best_header is old, so it is passed over by the header-sync
        # trigger and starts from a count of 0.
        boot_control2 = boot_node.add_p2p_connection(P2PInterface(), services=HF)
        self.settle(boot_control2)
        assert_equal(self.getheaders_count(boot_control2), 0)

        # Actively try to draw a fresh getheaders from each. Without a stimulus
        # the negative assertion would be vacuous: normal timing alone suppresses
        # a repeat request regardless of policy.
        boot_orphan = self.unconnecting_block(boot_node)
        boot_prefork.send_and_ping(msg_headers([CBlockHeader(boot_orphan)]))
        boot_control2.send_and_ping(msg_headers([CBlockHeader(boot_orphan)]))
        self.settle(boot_prefork)
        self.settle(boot_control2)

        assert_equal(self.getheaders_count(boot_prefork), prefork_baseline)
        assert self.getheaders_count(boot_control2) > 0, \
            "the fork-aware peer drew no getheaders either; the negative assertion would be vacuous"
        assert boot_prefork.is_connected, "pre-fork peer disconnected; the policy only withholds getheaders"
        assert self.in_ibd(boot_node)
        self.log.info("PASS H: pre-fork peer stayed at "
                      f"{prefork_baseline} getheaders once a fork-aware peer connected, while the "
                      f"fork-aware control got {self.getheaders_count(boot_control2)}")

        self.run_case_i()
        self.run_case_j()
        self.run_case_k()

    def run_case_i(self):
        self.log.info("Case I: the fallback comes back on when the last fork-aware peer goes away")
        # The mirror image of case H, on a node of its own so that "the last
        # fork-aware peer" is exact. Nothing in the test pokes the node after the
        # disconnect: FinalizeNode() has to both uncount the peer and give back
        # the nSyncStarted slot it was holding, and the next SendMessages tick
        # has to re-run the header-sync trigger on its own. If the count did not
        # come back down to zero, this node would be left with a peer it refuses
        # to sync from and no other header source at all -- a permanently stuck
        # node, which is the failure this case exists to catch.
        node = self.nodes[3]
        assert self.in_ibd(node)
        assert_equal(len(node.getpeerinfo()), 0)

        fork_aware = node.add_p2p_connection(P2PInterface(), services=HF)
        fork_aware_id = self.newest_peer_id(node)
        # It must actually be the header sync source, not merely connected, or
        # its departure would not be releasing anything.
        fork_aware.wait_for_getheaders(timeout=60)

        prefork = node.add_p2p_connection(P2PInterface(), services=NON_HF)
        self.settle(prefork)
        assert_equal(self.getheaders_count(prefork), 0)
        assert_equal(len(node.getpeerinfo()), 2)

        self.disconnect_and_finalize(node, fork_aware, fork_aware_id)
        assert_equal(len(node.getpeerinfo()), 1)
        assert not int(node.getpeerinfo()[0]["services"], 16) & NODE_BLAKE2B

        # No stimulus, no reconnect, no second peer: the node has to resume
        # header sync from the pre-fork peer by itself. The peer has never been
        # sent a getheaders, so its HEADERS_RESPONSE_TIME window is not a factor
        # and policy is the only thing that could still be suppressing one.
        prefork.wait_for_getheaders(timeout=60)
        assert prefork.is_connected
        assert self.in_ibd(node)
        self.log.info("PASS I: pre-fork peer went from 0 to "
                      f"{self.getheaders_count(prefork)} getheaders after the fork-aware peer left, "
                      "with no external stimulus")

    def run_case_j(self):
        self.log.info("Case J: the fork-aware peer count survives mixed orders and disconnect paths")
        # m_fork_aware_header_sync_peers is not exposed over RPC, so every step
        # below is checked through the one thing it drives: whether a pre-fork
        # peer draws a getheaders. The pre-fork peer used for that (`prefork_b`)
        # is never sent one until the final step, so its HEADERS_RESPONSE_TIME
        # window is never in play -- policy is the only possible suppressor, and
        # a single SendMessages tick is enough for a permitted request to go out.
        #
        # The negative steps are not vacuous: the first and last steps show this
        # same node sending a getheaders to a pre-fork peer whenever the count is
        # genuinely zero.
        node = self.nodes[4]
        assert self.in_ibd(node)
        assert_equal(len(node.getpeerinfo()), 0)

        # Step 1: pre-fork peer first, no fork-aware peer at all -> count 0, the
        # fallback applies. Deliberately the reverse of the order cases G and H
        # use, so the increment is exercised on a node that already had a
        # pre-fork peer holding the sync slot.
        prefork_a = node.add_p2p_connection(P2PInterface(), services=NON_HF)
        prefork_a_id = self.newest_peer_id(node)
        prefork_a.wait_for_getheaders(timeout=60)
        self.log.info("  J1: count 0, pre-fork peer got getheaders")

        # Step 2: first fork-aware peer -> count 1. It takes over the sync slot,
        # which is only possible because prefork_a hands it back.
        fork_aware_a = node.add_p2p_connection(P2PInterface(), services=HF)
        fork_aware_a_id = self.newest_peer_id(node)
        fork_aware_a.wait_for_getheaders(timeout=60)

        # Step 3: a second pre-fork peer, connected while the count is 1, is
        # excluded and stays at zero getheaders.
        prefork_b = node.add_p2p_connection(P2PInterface(), services=NON_HF)
        self.settle(prefork_b)
        assert_equal(self.getheaders_count(prefork_b), 0)
        self.log.info("  J2: count 1, second pre-fork peer got 0 getheaders")

        # Step 4: disconnect a peer that was never counted. A decrement here
        # would take the count to 0 and wrongly re-open the fallback.
        #
        # Note what this step does and does not settle on its own: fork_aware_a
        # still holds the single nSyncStarted slot, so even a wrongly re-opened
        # fallback cannot produce a getheaders for prefork_b yet. The spurious
        # decrement is therefore caught one step later, the first moment the slot
        # is free -- which is exactly what step 5 provides. Steps 4 and 5 are one
        # check in two parts, not two independent ones. (Verified by mutation:
        # making the decrement unconditional fails this case at step 5.)
        self.disconnect_and_finalize(node, prefork_a, prefork_a_id)
        self.settle(prefork_b)
        assert_equal(self.getheaders_count(prefork_b), 0)
        self.log.info("  J3: pre-fork peer disconnected; still no getheaders for the other pre-fork peer")

        # Step 5: a second fork-aware peer -> count 2, then take one away with a
        # clean disconnect -> count 1, freeing the sync slot. The count must now
        # be 1 both because fork_aware_b is still connected and because step 4's
        # peer was never counted; either error shows up here as prefork_b
        # suddenly being allowed.
        fork_aware_b = node.add_p2p_connection(P2PInterface(), services=HF)
        self.settle(fork_aware_b)
        self.disconnect_and_finalize(node, fork_aware_a, fork_aware_a_id)
        self.settle(prefork_b)
        assert_equal(self.getheaders_count(prefork_b), 0)
        assert fork_aware_b.is_connected
        self.log.info("  J4: with the sync slot free and one fork-aware peer left, "
                      "the pre-fork peer is still excluded")

        # Step 6: remove the last fork-aware peer through the punishment path
        # instead of a clean close -- Misbehaving() sets m_should_discourage and
        # MaybeDiscourageAndDisconnect() drops the connection. It is a different
        # route into DisconnectNodes(), but it still ends at FinalizeNode(), and
        # the count must reach 0 all the same. (127.0.0.1 is treated as local, so
        # the peer is disconnected but not discouraged; nothing here depends on
        # which of the two happens.)
        fork_aware_b.send_message(msg_headers(self.non_continuous_headers(node)))
        fork_aware_b.wait_for_disconnect(timeout=60)
        self.wait_until(lambda: len(node.getpeerinfo()) == 1, timeout=60)
        assert_equal(len(node.getpeerinfo()), 1)
        assert not int(node.getpeerinfo()[0]["services"], 16) & NODE_BLAKE2B

        prefork_b.wait_for_getheaders(timeout=60)
        assert prefork_b.is_connected
        assert self.in_ibd(node)
        self.log.info("  J5: misbehavior disconnect took count 1 -> 0, pre-fork peer got "
                      f"{self.getheaders_count(prefork_b)} getheaders")
        self.log.info("PASS J: the count tracked every connect and every disconnect path exercised")

    def run_case_k(self):
        self.log.info("Case K: TryLowWorkHeadersSync honors the same predicate")
        # The low-work headers-sync entry point is a fifth place the policy has
        # to hold, and the only one not reachable with a handful of headers: it
        # needs a headers message of exactly MAX_HEADERS_RESULTS whose claimed
        # work is below GetAntiDoSWorkThreshold(). On regtest that threshold is
        # zero unless -minimumchainwork is set, which is how
        # p2p_headers_sync_with_minchainwork reaches the same branch; nodes 5 and
        # 6 are started that way. Both are clean-chain nodes at the same genesis
        # block, so one batch of headers serves for both.
        allowed_node = self.nodes[5]
        excluded_node = self.nodes[6]
        assert_equal(len(allowed_node.getpeerinfo()), 0)
        assert_equal(len(excluded_node.getpeerinfo()), 0)
        assert_equal(allowed_node.getbestblockhash(), excluded_node.getbestblockhash())

        headers = self.low_work_headers(allowed_node, MAX_HEADERS_RESULTS)
        assert_equal(len(headers), MAX_HEADERS_RESULTS)

        self.log.info("  K1: under the bootstrap fallback, a pre-fork peer may start a low-work sync")
        boot_prefork = allowed_node.add_p2p_connection(P2PInterface(), services=NON_HF)
        boot_prefork.wait_for_getheaders(timeout=60)
        with allowed_node.assert_debug_log(expected_msgs=["Initial headers sync started with peer="],
                                           timeout=60):
            boot_prefork.send_message(msg_headers(headers))
            boot_prefork.sync_with_ping(timeout=60)
        self.log.info("  K1: low-work sync started from the pre-fork peer, as the fallback requires")

        self.log.info("  K2: with a fork-aware peer connected, the same batch is refused")
        control = excluded_node.add_p2p_connection(P2PInterface(), services=HF)
        control.wait_for_getheaders(timeout=60)
        prefork = excluded_node.add_p2p_connection(P2PInterface(), services=NON_HF)
        self.settle(prefork)
        assert_equal(self.getheaders_count(prefork), 0)

        with excluded_node.assert_debug_log(
                expected_msgs=[f"Ignoring low-work chain (height={MAX_HEADERS_RESULTS})"],
                unexpected_msgs=["Initial headers sync started with peer="],
                timeout=60):
            prefork.send_message(msg_headers(headers))
            prefork.sync_with_ping(timeout=60)

        # Positive control on the same node with the same headers: the batch is
        # otherwise perfectly capable of starting a low-work sync, so the refusal
        # above is the policy and nothing else.
        with excluded_node.assert_debug_log(expected_msgs=["Initial headers sync started with peer="],
                                            timeout=60):
            control.send_message(msg_headers(headers))
            control.sync_with_ping(timeout=60)

        assert prefork.is_connected, "pre-fork peer disconnected; the policy only withholds getheaders"
        self.log.info("PASS K: the low-work sync entry point allowed the pre-fork peer only under the "
                      "fallback, and refused it while a fork-aware peer was connected")


if __name__ == '__main__':
    Blake2bPreforkPeerPolicy(__file__).main()
