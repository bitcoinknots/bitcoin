#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Legacy RDTS signaling window.

v1 blocks from RdtsLegacySignalingHeight up to the BLAKE2b fork height must
carry the legacy RDTS version bit (bit 4 under the versionbits top bits), as
the versionbits deployment in Knots 29.3/29.4 required on mainnet. This pins
the hardfork onto the chain those releases followed: the signaling and
non-signaling branches have equal work per block, so without the rule the
fork's parent would be whichever branch a node happened to see first.

Cases:
  INHERITED  a datadir advanced past the window start by a client without
             the rule is truncated at the first non-signaling block at
             startup, and the correction persists across a restart.
  LIVE       inside the window a non-signaling v1 block is rejected with
             bad-version-reduced_data, header-only and full; a signaling one
             is accepted; bit 4 without the versionbits top bits is not a
             signal; the rule does not apply below the window and ends at the
             fork height (the v2 fork block needs no bit).
  P2P        the same header from an inbound peer is rejected; the peer is
             kept (Knots does not punish peers for invalid blocks unless it
             relies on them for blocks).
  END        with -rdtslegacysignalingend below the fork height the rule
             stops there (the mainnet bound, 963648, for a fork scheduled
             above it).
  ARGS       -rdtslegacysignalingheight needs a blake2b activation height,
             must be at least 1 and below it; -rdtslegacysignalingend needs
             the start and must be above it.
"""

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CBlockHeader, msg_headers
from test_framework.p2p import P2PInterface
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error

WINDOW_START = 120
WINDOW_END = 180
FORK_HEIGHT = 200
INHERITED_TIP = 150
SIGNAL_VERSION = 0x20000010     # versionbits top bits + bit 4
NO_SIGNAL_VERSION = 0x20000000  # top bits, bit 4 clear
BIT_ONLY_VERSION = 0x00000010   # bit 4 without the top bits: not a signal
REJECT = 'bad-version-reduced_data'
# Must match the test framework's default -blake2b_headline argument.
HEADLINE = b'BLAKE2b functional test headline'


def rule_args(window=WINDOW_START, fork=FORK_HEIGHT):
    return [f'-rdtslegacysignalingheight={window}', f'-testactivationheight=blake2b@{fork}']


class RdtsLegacySignalingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The node starts without the rule, standing in for a client that
        # did not require the signal.
        self.extra_args = [[]]

    def make_block(self, node, parent_hash, height, *, version=NO_SIGNAL_VERSION, v2=False, time_offset=1):
        parent_time = node.getblockheader(parent_hash)['time']
        coinbase = create_coinbase(height)
        if v2:
            # The first BLAKE2b block must carry the headline.
            coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + HEADLINE)
            coinbase.rehash()
        block = create_block(int(parent_hash, 16), coinbase, ntime=parent_time + time_offset,
                             version=version, height=height, header_v2=v2)
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_tip(self, node, **kwargs):
        blk = self.make_block(node, node.getbestblockhash(), node.getblockcount() + 1, **kwargs)
        return blk, node.submitblock(blk.serialize().hex())

    def mine_to(self, node, target, **kwargs):
        while node.getblockcount() < target:
            _, res = self.submit_tip(node, **kwargs)
            assert_equal(res, None)

    def tip_status(self, node, block_hash):
        for t in node.getchaintips():
            if t['hash'] == block_hash:
                return t['status']
        return None

    def run_test(self):
        node = self.nodes[0]

        self.log.info("INHERITED: a non-signaling chain built without the rule is truncated at startup")
        self.mine_to(node, INHERITED_TIP)
        inherited_tip = node.getbestblockhash()
        first_bad = node.getblockhash(WINDOW_START)
        self.stop_node(0)
        rewind = INHERITED_TIP - WINDOW_START + 1
        with node.assert_debug_log([f'block {first_bad} at height {WINDOW_START} does not carry the RDTS signal required in the legacy signaling window',
                                    f'rewinding the active chain by {rewind} block(s)']):
            self.start_node(0, extra_args=rule_args())
        assert_equal(node.getblockcount(), WINDOW_START - 1)
        assert_equal(self.tip_status(node, inherited_tip), 'invalid')
        # The marks persist: a restart neither repeats the rewind nor undoes it.
        self.restart_node(0, extra_args=rule_args())
        assert_equal(node.getblockcount(), WINDOW_START - 1)
        assert_equal(self.tip_status(node, inherited_tip), 'invalid')

        self.log.info("LIVE: inside the window a non-signaling block is rejected, header-only and full")
        # A different timestamp from the inherited block 120, which is already
        # in the index as invalid (a byte-identical block is 'duplicate-invalid').
        blk, res = self.submit_tip(node, time_offset=2)
        assert_equal(res, REJECT)
        assert_equal(node.getblockcount(), WINDOW_START - 1)
        assert_raises_rpc_error(-25, REJECT, node.submitheader, CBlockHeader(blk).serialize().hex())

        self.log.info("P2P: the same header from an inbound peer is rejected and the peer kept")
        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log([REJECT, 'got DoS score 100 on invalid block header; tolerating']):
            peer.send_and_ping(msg_headers([CBlockHeader(blk)]))
        assert_equal(node.getblockcount(), WINDOW_START - 1)
        assert peer.is_connected
        node.disconnect_p2ps()
        _, res = self.submit_tip(node, version=BIT_ONLY_VERSION)
        assert_equal(res, REJECT)

        self.log.info("LIVE: a signaling block is accepted through the end of the window")
        self.mine_to(node, FORK_HEIGHT - 2, version=SIGNAL_VERSION)
        _, res = self.submit_tip(node)  # last window height, no signal
        assert_equal(res, REJECT)
        _, res = self.submit_tip(node, version=SIGNAL_VERSION)
        assert_equal(res, None)
        assert_equal(node.getblockcount(), FORK_HEIGHT - 1)

        self.log.info("LIVE: the rule does not apply below the window")
        below = self.make_block(node, node.getblockhash(WINDOW_START - 2), WINDOW_START - 1, time_offset=2)
        assert node.submitblock(below.serialize().hex()) in (None, 'inconclusive')
        assert self.tip_status(node, below.hash) != 'invalid'

        self.log.info("LIVE: the window ends at the fork height; the v2 fork block needs no bit")
        _, res = self.submit_tip(node, v2=True)
        assert_equal(res, None)
        assert_equal(node.getblockcount(), FORK_HEIGHT)
        self.restart_node(0, extra_args=rule_args())
        assert_equal(node.getblockcount(), FORK_HEIGHT)

        self.log.info("END: with an explicit end below the fork height the rule stops there")
        self.restart_node(0, extra_args=rule_args() + [f'-rdtslegacysignalingend={WINDOW_END}'])
        assert_equal(node.getblockcount(), FORK_HEIGHT)  # the signaling chain is valid either way
        inside = self.make_block(node, node.getblockhash(WINDOW_END - 2), WINDOW_END - 1, time_offset=2)
        assert_equal(node.submitblock(inside.serialize().hex()), REJECT)
        past = self.make_block(node, node.getblockhash(WINDOW_END - 1), WINDOW_END, time_offset=2)
        assert node.submitblock(past.serialize().hex()) in (None, 'inconclusive')
        assert self.tip_status(node, past.hash) != 'invalid'

        self.log.info("ARGS: the options need a blake2b height and a sane window")
        self.stop_node(0)
        node.assert_start_raises_init_error([f'-rdtslegacysignalingheight={WINDOW_START}'],
                                            'rdtslegacysignalingheight requires -testactivationheight=blake2b',
                                            match=ErrorMatch.PARTIAL_REGEX)
        node.assert_start_raises_init_error(rule_args(window=FORK_HEIGHT),
                                            'must be at least 1 and below the blake2b activation height',
                                            match=ErrorMatch.PARTIAL_REGEX)
        node.assert_start_raises_init_error(rule_args(window=0),
                                            'must be at least 1 and below the blake2b activation height',
                                            match=ErrorMatch.PARTIAL_REGEX)
        node.assert_start_raises_init_error([f'-testactivationheight=blake2b@{FORK_HEIGHT}', f'-rdtslegacysignalingend={WINDOW_END}'],
                                            'rdtslegacysignalingend requires -rdtslegacysignalingheight',
                                            match=ErrorMatch.PARTIAL_REGEX)
        node.assert_start_raises_init_error(rule_args() + [f'-rdtslegacysignalingend={WINDOW_START}'],
                                            'must be above -rdtslegacysignalingheight',
                                            match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=rule_args())


if __name__ == '__main__':
    RdtsLegacySignalingTest(__file__).main()
