#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The closing-block floor over the network and across a restart.

feature_timewarp.py submits blocks by RPC, which exercises the rule but never carries
it over the wire. The floor is enforced in ContextualCheckBlockHeaderVolatile, reached
both from ContextualCheckBlockHeader when a header is accepted and from ConnectBlock
when a block is connected. Headers sync is therefore its hot path: a node learns about a
violating block from a peer long before it has the block itself. What is checked here is
that

  - a fresh node reaches the same tip by syncing a floor-constrained chain from a peer,
  - it reaches that tip again after -reindex, so the rule holds on revalidation,
  - a node below the activation height accepts a chain the forked nodes reject,
  - a forked node does not follow that chain even when it carries strictly more work, and
  - a node that already followed such a chain corrects itself when the rule turns on.

The last two are the ones that matter. A rule that rejects a block on submitblock but
lets the same block in behind a longer chain is not a consensus rule; and one that a
late upgrader silently keeps violating is a chain split waiting to happen, because
neither check is re-derived for a chain that is already connected.
"""

from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

INTERVAL = 144
CLOSING = 2 * INTERVAL - 1         # 287: (h + 1) % 144 == 0, so h closes a period
WINDOW_START = CLOSING - INTERVAL  # 143: where the window the next retarget measures began

MOCKTIME = 1700000000
SPIKE = MAX_FUTURE_BLOCK_TIME


class TimewarpSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        forked = [f"-testactivationheight=timewarpfix@{CLOSING}"]
        never = [f"-testactivationheight=timewarpfix@{CLOSING + 100000}"]
        self.extra_args = [
            forked,   # node0: miner, forked
            forked,   # node1: syncs from node0
            never,    # node2: never activates; becomes the late upgrader
            never,    # node3: never activates; late upgrader via -reindex-chainstate
        ]

    def build(self, node, ntime):
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        block = create_block(int(tmpl["previousblockhash"], 16),
                             create_coinbase(height=tmpl["height"]),
                             ntime, tmpl=tmpl)
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        miner, syncer, legacy, legacy2 = self.nodes
        addr = miner.get_deterministic_priv_key().address

        self.log.info("Build the shared prefix, with the window start stamped ahead")
        for node in self.nodes:
            node.setmocktime(MOCKTIME)
        self.generatetoaddress(miner, WINDOW_START - 1, addr)
        for node in self.nodes:
            node.setmocktime(MOCKTIME + SPIKE)
        self.generatetoaddress(miner, 1, addr)
        for node in self.nodes:
            node.setmocktime(MOCKTIME + 1)
        self.generatetoaddress(miner, CLOSING - 1 - WINDOW_START, addr)
        self.sync_blocks()

        floor = miner.getblockheader(miner.getblockhash(WINDOW_START))["time"]
        assert_equal(floor, MOCKTIME + SPIKE)
        for node in self.nodes:
            assert_equal(node.getblockcount(), CLOSING - 1)
        prefix_tip = miner.getbestblockhash()

        # Split the network completely: each side now builds its own closing block, and
        # the two late-upgrader nodes must not learn of anything over the wire.
        for a in range(self.num_nodes):
            for b in range(a + 1, self.num_nodes):
                self.disconnect_nodes(a, b)

        self.log.info("Below the activation height the violating block is accepted")
        for node in self.nodes:
            node.setmocktime(MOCKTIME)
        bad = self.build(legacy, floor - 1)
        for node in (legacy, legacy2):
            assert_equal(node.submitblock(bad.serialize().hex()), None)
            assert_equal(node.getblockcount(), CLOSING)

        self.log.info("The forked miner builds a valid closing block at the floor")
        good = self.build(miner, floor)
        assert_equal(miner.submitblock(good.serialize().hex()), None)
        assert_equal(miner.getblockcount(), CLOSING)
        assert good.hash != bad.hash

        self.log.info("A fresh node reaches the same tip by syncing over P2P")
        assert_equal(syncer.getblockcount(), CLOSING - 1)
        self.connect_nodes(0, 1)
        self.sync_blocks([miner, syncer])
        assert_equal(syncer.getbestblockhash(), miner.getbestblockhash())
        assert_equal(syncer.getblockcount(), CLOSING)
        assert_equal(syncer.getblockheader(syncer.getbestblockhash())["time"], floor)
        self.disconnect_nodes(0, 1)

        self.log.info("It reaches the same tip again after -reindex")
        tip_before = syncer.getbestblockhash()
        for flag in ("-reindex", "-reindex-chainstate"):
            # -reindex rebuilds the block index and revalidates headers;
            # -reindex-chainstate keeps the index and replays blocks only, which does not
            # re-run ContextualCheckBlockHeader. Both must land on the same tip.
            self.restart_node(1, extra_args=self.extra_args[1] + [flag])
            syncer = self.nodes[1]
            syncer.setmocktime(MOCKTIME)
            assert_equal(syncer.getbestblockhash(), tip_before)
            assert_equal(syncer.getblockcount(), CLOSING)
            self.log.info(f"  {flag}: back at {CLOSING}")

        self.log.info("The legacy chain is extended until it carries strictly more work")
        legacy.setmocktime(MOCKTIME + 1)
        blocks = self.generatetoaddress(legacy, 3, addr, sync_fun=self.no_op)
        for h in blocks:
            assert_equal(legacy2.submitblock(legacy.getblock(h, 0)), None)
        assert_equal(legacy.getblockcount(), CLOSING + 3)
        assert_equal(legacy2.getbestblockhash(), legacy.getbestblockhash())
        assert_greater_than(int(legacy.getblockheader(legacy.getbestblockhash())["chainwork"], 16),
                            int(miner.getblockheader(miner.getbestblockhash())["chainwork"], 16))

        self.log.info("A forked node does not follow it, however much work it carries")
        # The rule is a header rule, so this is settled in AcceptBlockHeader during
        # headers sync, before any block of that chain is ever requested. The header is
        # refused outright, so no block index is created for it at all.
        for n, node in ((0, miner), (1, syncer)):
            with node.assert_debug_log(expected_msgs=["time-timewarp-closing"], timeout=30):
                self.connect_nodes(n, 2)
            assert_equal(node.getblockcount(), CLOSING)
            assert_equal(node.getbestblockhash(), good.hash)
            assert_raises_rpc_error(-5, "Block not found", lambda: node.getblock(bad.hash))
            assert bad.hash not in [t["hash"] for t in node.getchaintips()]
            self.disconnect_nodes(n, 2)

        self.log.info("The legacy node meanwhile sits on the chain the fork rejected")
        assert_equal(legacy.getblockcount(), CLOSING + 3)
        assert_equal(legacy.getblockhash(CLOSING), bad.hash)
        assert_equal(miner.getblockhash(CLOSING), good.hash)
        assert_equal(miner.getblockhash(WINDOW_START), legacy.getblockhash(WINDOW_START))
        self.log.info(f"split confirmed at height {CLOSING}, shared up to {CLOSING - 1}")

        self.log.info("A late upgrader corrects itself instead of keeping the bad chain")
        # node2 followed the violating chain while the rule was not in force, which is
        # what an operator upgrading after the flag day looks like. Restarting it with
        # the rule active must rewind it, not leave it silently diverged: the header is
        # already in its block index, so AcceptBlockHeader will never look at it again.
        bad_tip = legacy.getbestblockhash()   # captured before the restart: same node
        self.restart_node(2, extra_args=self.extra_args[0])
        upgraded = self.nodes[2]
        upgraded.setmocktime(MOCKTIME)
        assert_equal(upgraded.getblockcount(), CLOSING - 1)
        assert_equal(upgraded.getbestblockhash(), prefix_tip)
        # The block data is still on disk, so this is about the verdict, not the bytes:
        # the header is marked invalid and is no longer on the active chain.
        assert_equal(upgraded.getblockheader(bad.hash)["confirmations"], -1)
        tips = {t["hash"]: t["status"] for t in upgraded.getchaintips()}
        assert_equal(tips[bad_tip], "invalid")
        self.log.info(f"  rewound from {CLOSING + 3} to {CLOSING - 1}, the last block "
                      f"both sides agree on")

        self.log.info("...and also when it upgrades via -reindex-chainstate")
        # -reindex-chainstate keeps the block index and replays blocks through
        # ConnectBlock, which re-runs ContextualCheckBlockHeaderVolatile but not
        # ContextualCheckBlockHeader. bad-version-blake2b lives in the volatile function,
        # which is how the BLAKE2b fork survives this path; the closing-block floor is
        # placed there for the same reason. A node taking this path must not be left on
        # the bad chain.
        self.restart_node(3, extra_args=self.extra_args[0] + ["-reindex-chainstate"])
        rebuilt = self.nodes[3]
        rebuilt.setmocktime(MOCKTIME)
        assert_equal(rebuilt.getblockcount(), CLOSING - 1)
        assert_equal(rebuilt.getbestblockhash(), prefix_tip)


if __name__ == "__main__":
    TimewarpSyncTest(__file__).main()
