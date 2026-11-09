#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Live-node coverage for the closing-block timestamp floor.

Once retarget windows are contiguous the block closing a period is also the block the
next window is measured from, so it may not be stamped before the block this window
started from. The arithmetic is covered by timewarp_tests; what is checked here is that
a real node rejects such a block, mines at the floor rather than below it, and applies
none of this before the activation height.

Regtest's retarget interval is 144 blocks, so height 287 closes the second period and
its floor is the timestamp of height 143.
"""

from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import CBlockHeader
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

INTERVAL = 144
CLOSING = 2 * INTERVAL - 1      # 287: (h + 1) % 144 == 0, so h closes a period
WINDOW_START = CLOSING - INTERVAL  # 143: where the window the next retarget measures began

MOCKTIME = 1700000000
SPIKE = MAX_FUTURE_BLOCK_TIME   # how far ahead the window start is stamped: the most
                                # consensus ever allows, so the floor it produces lands
                                # exactly on the future-time limit


class TimewarpFloorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [f"-testactivationheight=timewarpfix@{CLOSING}"],
            [f"-testactivationheight=timewarpfix@{CLOSING + 100000}"],
        ]

    def template(self, node):
        return node.getblocktemplate({"rules": ["segwit"]})

    def build(self, node, ntime):
        tmpl = self.template(node)
        block = create_block(int(tmpl["previousblockhash"], 16),
                             create_coinbase(height=tmpl["height"]),
                             ntime, tmpl=tmpl)
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        forked, unforked = self.nodes
        addr = forked.get_deterministic_priv_key().address

        self.log.info("Build a chain whose window start is stamped ahead of everything after it")
        self.nodes[0].setmocktime(MOCKTIME)
        self.nodes[1].setmocktime(MOCKTIME)
        self.generatetoaddress(forked, WINDOW_START - 1, addr)
        for node in self.nodes:
            node.setmocktime(MOCKTIME + SPIKE)
        self.generatetoaddress(forked, 1, addr)
        for node in self.nodes:
            node.setmocktime(MOCKTIME + 1)
        self.generatetoaddress(forked, CLOSING - 1 - WINDOW_START, addr)

        assert_equal(forked.getblockcount(), CLOSING - 1)
        assert_equal(unforked.getblockcount(), CLOSING - 1)
        floor = forked.getblockheader(forked.getblockhash(WINDOW_START))["time"]
        assert_equal(floor, MOCKTIME + SPIKE)
        tip_mtp = forked.getblockheader(forked.getbestblockhash())["mediantime"]
        assert_greater_than(floor, tip_mtp + 1)
        self.log.info(f"window start at height {WINDOW_START} is {floor - tip_mtp}s above the tip's "
                      f"median time past, so only the floor keeps the closing block legal")

        self.disconnect_nodes(0, 1)

        self.log.info("The activation height is reported, so an operator can see the schedule")
        # "active" is asked of the block after the tip, which here is the closing block
        # the rule first applies to.
        assert_equal(forked.getdeploymentinfo()["timewarpfix"], {"height": CLOSING, "active": True})
        assert_equal(unforked.getdeploymentinfo()["timewarpfix"],
                     {"height": CLOSING + 100000, "active": False})

        self.log.info("The floor is what the template offers, not median time past plus one")
        tmpl = self.template(forked)
        assert_equal(tmpl["mintime"], floor)
        assert_greater_than_or_equal(tmpl["curtime"], tmpl["mintime"])
        assert_equal(self.template(unforked)["mintime"], tip_mtp + 1)

        self.log.info("A closing block below the floor is rejected")
        too_early = self.build(forked, floor - 1)
        assert_raises_rpc_error(
            -25, "time-timewarp-closing",
            lambda: forked.submitheader(hexdata=CBlockHeader(too_early).serialize().hex()),
        )
        assert_equal(forked.submitblock(too_early.serialize().hex()), "time-timewarp-closing")
        assert_equal(forked.getblockcount(), CLOSING - 1)

        self.log.info("The same block is accepted below the activation height")
        assert_equal(unforked.submitblock(self.build(unforked, floor - 1).serialize().hex()), None)
        assert_equal(unforked.getblockcount(), CLOSING)

        self.log.info("The floor can never demand a time the future-time limit forbids")
        # A lower bound on a timestamp could in principle ask for a time that the
        # future-time limit rejects, leaving a period impossible to close. Here the
        # window started a full MAX_FUTURE_BLOCK_TIME ahead of the node's clock, which
        # puts the floor exactly on that limit: the tightest case there is.
        for node in self.nodes:
            node.setmocktime(MOCKTIME)
        assert_equal(floor, MOCKTIME + MAX_FUTURE_BLOCK_TIME)
        assert_equal(self.template(forked)["mintime"], floor)
        too_new = self.build(forked, floor + 1)
        assert_raises_rpc_error(
            -25, "time-too-new",
            lambda: forked.submitheader(hexdata=CBlockHeader(too_new).serialize().hex()),
        )

        self.log.info("A closing block at the floor is accepted")
        assert_equal(forked.submitblock(self.build(forked, floor).serialize().hex()), None)
        assert_equal(forked.getblockcount(), CLOSING)
        assert_equal(forked.getblockheader(forked.getbestblockhash())["time"], floor)

        self.log.info("The floor applies to closing blocks only")
        # The block after it opens a period, where the pre-existing BIP94 template clamp
        # of 600s below the parent applies instead.
        assert_equal(self.template(forked)["mintime"], floor - 600)
        assert_equal(forked.submitblock(self.build(forked, floor - 600).serialize().hex()), None)

        mtp = forked.getblockheader(forked.getbestblockhash())["mediantime"]
        assert_greater_than(floor, mtp + 1)
        assert_equal(self.template(forked)["mintime"], mtp + 1)
        assert_equal(forked.submitblock(self.build(forked, mtp + 1).serialize().hex()), None)
        assert_equal(forked.getblockcount(), CLOSING + 2)
        assert_equal(forked.getblockheader(forked.getbestblockhash())["time"], mtp + 1)

        self.log.info("The floor is read along the branch being validated, not the active chain")
        # A branch that forks below the window start and never stamps a block ahead has a
        # floor of its own. Headers alone settle this, since the rule is a header rule.
        prev = int(forked.getblockhash(WINDOW_START - 1), 16)
        ntime = forked.getblockheader(forked.getblockhash(WINDOW_START - 1))["time"]
        for height in range(WINDOW_START, CLOSING + 1):
            ntime += 1
            branch = create_block(prev, create_coinbase(height), ntime, height=height)
            branch.solve()
            forked.submitheader(hexdata=CBlockHeader(branch).serialize().hex())
            prev = branch.sha256
        assert_greater_than(floor, ntime)
        assert_equal(forked.getblockheader(branch.hash)["height"], CLOSING)
        assert_equal(forked.getblockcount(), CLOSING + 2)

        self.log.info("A period's first block has no floor of its own, even more than 2h back")
        # This is the deliberate departure from BIP-54, whose first-block rule forbids a
        # period opening more than 7200s before the block that closed the last one. Under
        # contiguous windows that block is no longer a measurement endpoint, so there is
        # nothing to protect and the rule, and its grace period, go away. Pin it with a gap
        # BIP-54 would reject: close the next period 12200s ahead of the chain's median
        # time, then open the one after at median time plus one.
        closing2 = CLOSING + INTERVAL
        self.generatetoaddress(forked, closing2 - 1 - forked.getblockcount(), addr,
                               sync_fun=self.no_op)
        assert_equal(forked.getblockcount(), closing2 - 1)
        floor2 = forked.getblockheader(forked.getblockhash(closing2 - INTERVAL))["time"]
        assert_equal(floor2, floor)
        forked.setmocktime(MOCKTIME + 5000)
        high = MOCKTIME + 5000 + MAX_FUTURE_BLOCK_TIME
        assert_greater_than_or_equal(high, floor2)
        assert_equal(forked.submitblock(self.build(forked, high).serialize().hex()), None)
        assert_equal(forked.getblockcount(), closing2)
        mtp2 = forked.getblockheader(forked.getbestblockhash())["mediantime"]
        assert_greater_than(high - (mtp2 + 1), 7200)
        assert_equal(forked.submitblock(self.build(forked, mtp2 + 1).serialize().hex()), None)
        assert_equal(forked.getblockheader(forked.getbestblockhash())["time"], mtp2 + 1)
        self.log.info(f"  period opened {high - (mtp2 + 1)}s below the closing block, accepted")


if __name__ == "__main__":
    TimewarpFloorTest(__file__).main()
