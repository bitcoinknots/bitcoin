#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The timewarp attack against live nodes, on a custom signet that actually retargets.

feature_timewarp.py covers the closing-block floor on regtest, where fPowNoRetargeting
leaves the difficulty arithmetic untouched, and feature_timewarp_activation.py covers
crossing the activation height. This runs the attack itself, which is slow enough to
belong in the extended set.

Three nodes, deliberately unconnected:
  node0  no activation height, today's rules
  node1  rules active from the start of the chain
  node2  an activation height the chain never reaches

node0 and node2 are fed byte-identical blocks and must agree at every step, which shows
that an unreached activation height changes nothing. node1 mines its own chain, because
under the new rule the attack produces different difficulty and so different blocks.

The retarget interval is shortened to 8 blocks with -signetblocktime, which leaves
nPowTargetTimespan at 14 days. The seam being exercised does not depend on the interval:
the window for the retarget at height R is [R-N, R-1], which spans N blocks but only N-1
inter-block intervals, so the gap between R-1 and R is measured by nothing.
"""

import subprocess

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlockHeader, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

INTERVAL = 8                             # blocks per retarget period
SIGNET_BLOCK_TIME = 1209600 // INTERVAL  # keeps nPowTargetTimespan at 14 days
GENESIS_TIME = 1598918400                # signet genesis nTime

# Two warmup epochs lift difficulty 16x off the powLimit floor, which is the headroom
# the attack needs to drop 4x twice without the floor clamping and hiding the result.
WARMUP_EPOCHS = 2
ATTACK_EPOCHS = 2
SPIKE_OFFSET = 60 * 24 * 60 * 60         # 60 days, past the 4x clamp at 56 days

NEVER = 1000000                          # an activation height the chain never reaches



class TimewarpRetargetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 3
        base = ["-signetchallenge=51", f"-signetblocktime={SIGNET_BLOCK_TIME}"]
        self.extra_args = [
            base,
            base + ["-signettimewarpfixheight=0"],
            base + [f"-signettimewarpfixheight={NEVER}"],
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

    def schedule(self, height, kind, index):
        """The attacker's timestamp for a block at this height."""
        if kind == "attack" and height % INTERVAL == INTERVAL - 1:
            return GENESIS_TIME + SPIKE_OFFSET + index
        return GENESIS_TIME + height

    def run_epoch(self, nodes, kind, index):
        for _ in range(INTERVAL):
            height = nodes[0].getblockcount() + 1
            block = self.build(nodes[0], self.schedule(height, kind, index))
            for node in nodes:
                assert_equal(node.submitblock(block.serialize().hex()), None)
            assert_equal(len({node.getbestblockhash() for node in nodes}), 1)

    def tip(self, node):
        return node.getblockheader(node.getbestblockhash())

    def run_chain(self, nodes, label):
        for e in range(WARMUP_EPOCHS):
            self.run_epoch(nodes, "warmup", e)
        start = self.tip(nodes[0])

        for e in range(ATTACK_EPOCHS):
            self.run_epoch(nodes, "attack", e)
            self.log.info(f"{label} attack epoch {e}: difficulty {self.tip(nodes[0])['difficulty']}")
        end = self.tip(nodes[0])

        self.log.info(f"RESULT {label}: difficulty {start['difficulty']} -> {end['difficulty']} "
                      f"while the chain's own clock advanced {end['time'] - start['time']}s over "
                      f"{ATTACK_EPOCHS * INTERVAL} blocks")
        return start["difficulty"], end["difficulty"]

    def run_test(self):
        current, fork, gated = self.nodes[0], self.nodes[1], self.nodes[2]
        self.log.info(f"interval={INTERVAL} blocks, target timespan=1209600s, "
                      f"spacing={SIGNET_BLOCK_TIME}s")

        before, after = self.run_chain([current, gated], "current rule")
        assert_greater_than(before, after * 8)
        assert_equal(current.getbestblockhash(), gated.getbestblockhash())
        assert_equal(self.tip(current), self.tip(gated))
        self.log.info("an unreached activation height changed nothing at any block")

        f_before, f_after = self.run_chain([fork], "contiguous windows")
        assert_greater_than(f_after * 2, f_before)
        assert_greater_than(f_after, after * 8)
        self.log.info("the same attack does not lower difficulty under contiguous windows")



if __name__ == "__main__":
    TimewarpRetargetTest(__file__).main()
