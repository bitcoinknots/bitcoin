#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Crossing the contiguous-window activation height on live nodes.

This is the only end-to-end coverage of rule A, the change to what the retarget
measures, so it runs in the default suite rather than the extended one.
feature_timewarp_retarget.py demonstrates the attack itself and is slow enough to stay
opt-in; everything here fits in well under a minute.

Regtest cannot substitute: fPowNoRetargeting makes CalculateNextWorkRequired return the
previous nBits unchanged, so both rules produce identical nBits there no matter what.
Hence a custom signet, with the retarget interval shortened by -signetblocktime.

Blocks are spaced at the target interval rather than one second apart, so the measured
spans land between the 0.25x and 4x clamps. That matters: a schedule that drives every
span past a clamp has the one-block difference between the two windows absorbed, and the
rules agree on nBits. A transition is only observable where the spans are unclamped.

Three nodes, deliberately unconnected:
  node0  legacy, no activation height
  node1  activation partway along the chain
  node2  a legacy twin of node0, so the two upgrade paths can be tested independently
"""

import subprocess

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlockHeader, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

INTERVAL = 8                             # blocks per retarget period
SIGNET_BLOCK_TIME = 1209600 // INTERVAL  # keeps nPowTargetTimespan at 14 days
GENESIS_TIME = 1598918400                # signet genesis nTime

# Activate at the closing block of the second period. The retarget at height INTERVAL
# agrees under both rules here simply because the fork is not active yet at that point,
# so the one at 2*INTERVAL is the first that can diverge. (The genesis edge case, where a
# contiguous window has no predecessor to measure from, would also force agreement at the
# first retarget, but it is not what is doing the work here.)
TRANSITION = 2 * INTERVAL - 1            # 15


class TimewarpActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 3
        base = ["-signetchallenge=51", f"-signetblocktime={SIGNET_BLOCK_TIME}"]
        self.extra_args = [
            base,                                              # node0: legacy
            base + [f"-signettimewarpfixheight={TRANSITION}"],  # node1: forked
            base,                                              # node2: legacy twin
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()

    def setup_network(self):
        self.setup_nodes()  # deliberately unconnected: independent chains

    def build(self, node, ntime):
        tmpl = node.getblocktemplate({"rules": ["segwit", "signet"]})
        block = create_block(int(tmpl["previousblockhash"], 16),
                             create_coinbase(height=tmpl["height"]),
                             ntime, tmpl=tmpl)
        add_witness_commitment(block)
        head = CBlockHeader.serialize(block).hex()
        out = subprocess.run([self.options.bitcoinutil, "grind", head],
                             stdout=subprocess.PIPE, input=b"", check=True).stdout.strip()
        block.nNonce = from_hex(CBlockHeader(), out.decode()).nNonce
        block.rehash()
        return block

    def run_test(self):
        legacy, trans, twin = self.nodes

        self.log.info(f"interval={INTERVAL} blocks, activation at height {TRANSITION}")
        for height in range(1, TRANSITION + 1):
            block = self.build(legacy, GENESIS_TIME + height * SIGNET_BLOCK_TIME)
            for node in (legacy, trans, twin):
                assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(legacy.getblockcount(), TRANSITION)
        assert_equal(legacy.getbestblockhash(), trans.getbestblockhash())
        self.log.info(f"identical up to the activation height {TRANSITION}, including the "
                      f"retarget at {INTERVAL} where the fork is not yet active")

        # The retarget after the activation closing block is the first measured
        # contiguously, so the two nodes now disagree about nBits for the same height.
        nxt = GENESIS_TIME + (TRANSITION + 1) * SIGNET_BLOCK_TIME
        legacy_block = self.build(legacy, nxt)
        fork_block = self.build(trans, nxt)
        assert legacy_block.nBits != fork_block.nBits, "windows agreed; the run proves nothing"

        assert_equal(legacy.submitblock(legacy_block.serialize().hex()), None)
        assert_equal(twin.submitblock(legacy_block.serialize().hex()), None)
        assert_equal(trans.submitblock(legacy_block.serialize().hex()), "bad-diffbits")
        assert_equal(trans.getblockcount(), TRANSITION)

        assert_equal(trans.submitblock(fork_block.serialize().hex()), None)
        assert_equal(legacy.submitblock(fork_block.serialize().hex()), "bad-diffbits")
        assert_equal(legacy.getblockhash(TRANSITION + 1), legacy_block.hash)
        assert_equal(trans.getblockhash(TRANSITION + 1), fork_block.hash)
        self.log.info(f"split at height {TRANSITION + 1}: legacy nBits {legacy_block.nBits:#x}, "
                      f"contiguous {fork_block.nBits:#x}; each rejects the other as bad-diffbits")

        # Carry the legacy chain past a SECOND retarget, so the late upgraders below have
        # more than one violator. A node that ran months past the fork would have one per
        # retarget, and the correction sorts by height and relies on invalidating the
        # lowest to fail its descendants; one violator never exercises that.
        for height in range(TRANSITION + 2, 3 * INTERVAL + 2):
            blk = self.build(legacy, GENESIS_TIME + height * SIGNET_BLOCK_TIME)
            for node in (legacy, twin):
                assert_equal(node.submitblock(blk.serialize().hex()), None)
        assert_equal(legacy.getblockcount(), 3 * INTERVAL + 1)
        second = 3 * INTERVAL   # 24, the next retarget after the split at 16
        # Captured before any upgrade restart: these heights stop existing once rewound.
        second_hash = legacy.getblockhash(second)
        self.log.info(f"legacy chain extended to {legacy.getblockcount()}, crossing retargets "
                      f"{TRANSITION + 1} and {second}")

        # -reindex-chainstate keeps the block index and never re-accepts a header, so its
        # only enforcement is what ConnectBlock re-runs. That covers the closing-block
        # floor but not bad-diffbits, so rule A needs the startup scan to mark violators
        # before the rebuild picks a chain.
        self.log.info("a late upgrader using -reindex-chainstate is rewound past every violator")
        self.restart_node(0, extra_args=self.extra_args[1] + ["-reindex-chainstate"])
        assert_equal(self.nodes[0].getblockcount(), TRANSITION)

        # The plain-restart path, on the twin: node0 is already corrected and the marks
        # persist to the block index, so restarting it again would assert nothing.
        self.log.info("a late upgrader carrying legacy nBits is rewound on a plain restart")
        assert_equal(twin.getblockcount(), 3 * INTERVAL + 1)
        self.restart_node(2, extra_args=self.extra_args[1])
        upgraded = self.nodes[2]
        assert_equal(upgraded.getblockcount(), TRANSITION)
        assert_equal(upgraded.getblockheader(second_hash)["confirmations"], -1)
        self.log.info(f"  rewound to {TRANSITION}; both inherited retarget blocks "
                      f"({TRANSITION + 1}, {second}) are marked invalid")

        # An honest node must NOT be rewound. Every other exercise of the startup scan
        # runs against a node that should be corrected, so a false positive in the gate
        # would otherwise go unnoticed.
        self.log.info("a node already on the correct chain is left alone")
        fork_tip = trans.getbestblockhash()
        fork_height = trans.getblockcount()
        self.restart_node(1, extra_args=self.extra_args[1])
        assert_equal(self.nodes[1].getbestblockhash(), fork_tip)
        assert_equal(self.nodes[1].getblockcount(), fork_height)


if __name__ == "__main__":
    TimewarpActivationTest(__file__).main()
