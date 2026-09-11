#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the extra-work temporary soft fork.

While the deployment is active, a block must meet its header target divided by
the extra-work factor, which rises when the hashrate over the last 72 blocks
exceeds the hashrate over the last 4320 blocks by more than 5/4 (both measured
as effective work over elapsed median-time-past) and is 1 otherwise. It
activates for the first block whose parent's median-time-past reaches
-extrawork and expires with RDTS (-rdtsexpiry).

The chain's timing is driven with mocktime. Where the factor is above 1, block
intervals are scaled by it, as they would be on a real network where the
required work grew: a 5x burst at 120 s spacing becomes 120 s * factor.

Covered:
- option validation (requires -rdtsexpiry, must precede it)
- inactive before the start time: factor 1, no rule advertised, target as bits encode
- steady hashrate after activation keeps factor 1 and the header target
- a 5x hashrate burst raises the factor to ~4 (5 / band 5/4); getblocktemplate
  lists "!extra_work", requires client support, lowers "target" and reports the factor
- a block meeting the header target but not the effective target is rejected
  with bad-extra-work, both as a submitted block and as a header
- when the burst leaves, the factor returns to 1 within about a fast window
- -reindex reproduces the chain and the factor
- expiry: once the parent's median-time-past reaches the RDTS expiry, the
  rule and the rule advertisement are gone
"""
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    CBlockHeader,
    uint256_from_compact,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

BLAKE2B_HEIGHT = 120
FAST_WINDOW = 72
SLOW_WINDOW = 4320
SPACING = 600
# Mock clock: blocks are stamped from T0 at the target spacing; the rule starts
# once the median-time-past reaches START (after the slow window is full) and
# RDTS (with it, this rule) expires at EXPIRY.
T0 = 1_600_000_000
START = T0 + (SLOW_WINDOW + 300) * SPACING
EXPIRY = START + 2_000 * SPACING
REJECT = 'bad-extra-work'
CLIENT_RULES = ['segwit', 'blake2b', 'extra_work']


class ExtraWorkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}',
            f'-rdtsexpiry={EXPIRY}',
            f'-extrawork={START}',
        ]
        self.extra_args = [self.base_args]

    # -- helpers ---------------------------------------------------------

    def deployment(self):
        return self.nodes[0].getdeploymentinfo()['deployments'].get('extra_work')

    def factor(self):
        return self.deployment()['factor']

    def mine_one(self, spacing):
        """Mine one block `spacing` seconds after the previous one."""
        self.mocktime += spacing
        self.nodes[0].setmocktime(self.mocktime)
        self.generate(self.wallet, 1, sync_fun=self.no_op)

    def mine(self, count, spacing=SPACING):
        for _ in range(count):
            self.mine_one(spacing)

    def mine_physical(self, count, hash_multiple):
        """Mine `count` blocks as a network with `hash_multiple` times the base
        hashrate would: the interval is the base spacing divided by the hash
        multiple, times the extra work the rule currently requires."""
        for _ in range(count):
            self.mine_one(int(SPACING * self.factor() / hash_multiple))

    def tmpl(self, rules=CLIENT_RULES):
        return self.nodes[0].getblocktemplate({'rules': rules})

    @staticmethod
    def header_target(tmpl):
        return uint256_from_compact(int(tmpl['bits'], 16))

    def assert_inactive(self, tmpl):
        assert_equal(self.deployment()['active'], False)
        assert_equal(self.factor(), 1)
        assert '!extra_work' not in tmpl['rules']
        assert 'extra_work_factor' not in tmpl
        assert_equal(int(tmpl['target'], 16), self.header_target(tmpl))

    # -- test ------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Option validation")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=[f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}', f'-extrawork={START}'],
            expected_msg='Error: -extrawork requires -rdtsexpiry=<time> (the rule expires with RDTS).')
        node.assert_start_raises_init_error(
            extra_args=[f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}', f'-rdtsexpiry={EXPIRY}', f'-extrawork={EXPIRY}'],
            expected_msg=f'Error: Invalid start ({EXPIRY}) for -extrawork=<time>: must precede the RDTS expiry ({EXPIRY}).')
        self.start_node(0)
        node.add_p2p_connection(P2PInterface())  # getblocktemplate needs a peer
        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        self.log.info("Before activation: steady blocks at the target spacing, factor 1, nothing advertised")
        self.mine(SLOW_WINDOW + 200)  # crosses the BLAKE2b fork and fills the slow window
        assert_greater_than(START, node.getblockheader(node.getbestblockhash())['mediantime'])
        info = self.deployment()
        assert_equal(info['type'], 'flagday')
        assert_equal(info['start_time'], START)
        assert_equal(info['expiry_time'], EXPIRY)
        self.assert_inactive(self.tmpl(rules=['segwit', 'blake2b']))

        self.log.info("Activation: the first block whose parent's median-time-past reaches the start time")
        while node.getblockheader(node.getbestblockhash())['mediantime'] < START:
            assert_equal(self.deployment()['active'], False)
            self.mine(1)
        assert_equal(self.deployment()['active'], True)
        activation = node.getblockcount() + 1
        self.log.info(f"  activation height {activation}")

        self.log.info("Active with steady hashrate: factor stays 1 and the target is the header target")
        self.mine(FAST_WINDOW + 10)
        assert_equal(self.factor(), 1)
        tmpl = self.tmpl()
        assert '!extra_work' in tmpl['rules']
        assert_equal(tmpl['extra_work_factor'], 1)
        assert_equal(int(tmpl['target'], 16), self.header_target(tmpl))
        assert_raises_rpc_error(-8, "Support for 'extra_work' rule requires explicit client support",
                                node.getblocktemplate, {'rules': ['segwit', 'blake2b']})

        self.log.info("A 5x hashrate burst: the factor rises toward 5 / (5/4) = 4 within a fast window")
        self.mine_physical(FAST_WINDOW, hash_multiple=5)
        burst_factor = self.factor()
        self.log.info(f"  factor after one fast window: {burst_factor:.2f}")
        assert_greater_than(burst_factor, 2.5)
        self.mine_physical(FAST_WINDOW, hash_multiple=5)
        burst_factor = self.factor()
        self.log.info(f"  factor after two fast windows: {burst_factor:.2f}")
        assert_greater_than(burst_factor, 3.0)
        assert_greater_than(4.6, burst_factor)
        tmpl = self.tmpl()
        assert_equal(tmpl['extra_work_factor'], burst_factor)
        header_target = self.header_target(tmpl)
        effective_target = int(tmpl['target'], 16)
        assert_greater_than(header_target, effective_target)
        # target = header_target / factor, up to the 16 fractional bits of the factor
        assert abs(effective_target * burst_factor / header_target - 1) < 1e-4

        self.log.info("A block meeting the header target but not the effective target is rejected")
        block = create_block(tmpl=tmpl)
        add_witness_commitment(block)
        block.solve()
        while not (effective_target < block.sha256 <= header_target):
            block.nNonce += 1
            block.rehash()
            if block.sha256 > header_target:
                block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), REJECT)
        assert_raises_rpc_error(-25, REJECT, node.submitheader, CBlockHeader(block).serialize().hex())
        assert_equal(node.getblockcount(), activation - 1 + FAST_WINDOW + 10 + 2 * FAST_WINDOW)
        # The same block with enough work is accepted
        while block.sha256 > effective_target:
            block.nNonce += 1
            block.rehash()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), block.hash)

        self.log.info("-reindex reproduces the chain and the factor")
        tip = node.getbestblockhash()
        self.restart_node(0, extra_args=self.base_args + ['-reindex'])
        node.setmocktime(self.mocktime)
        node.add_p2p_connection(P2PInterface())
        self.wait_until(lambda: node.getbestblockhash() == tip)
        assert_equal(self.deployment()['active'], True)
        assert_equal(int(self.tmpl()['target'], 16) < header_target, True)
        reindexed_factor = self.factor()
        assert_greater_than(reindexed_factor, 3.0)

        self.log.info("The burst leaves: blocks slow down by the factor and it decays back to 1")
        self.mine_physical(FAST_WINDOW + 20, hash_multiple=1)
        decayed = self.factor()
        self.log.info(f"  factor after the burst: {decayed:.2f}")
        assert_greater_than(1.2, decayed)
        self.mine_physical(FAST_WINDOW, hash_multiple=1)
        assert_equal(self.factor(), 1)
        tmpl = self.tmpl()
        assert_equal(int(tmpl['target'], 16), self.header_target(tmpl))

        self.log.info("Expiry: the rule ends once the parent's median-time-past reaches the RDTS expiry")
        while node.getblockheader(node.getbestblockhash())['mediantime'] < EXPIRY:
            assert_equal(self.deployment()['active'], True)
            self.mine(1)
        self.assert_inactive(self.tmpl(rules=['segwit', 'blake2b']))
        self.mine(3)


if __name__ == '__main__':
    ExtraWorkTest(__file__).main()
