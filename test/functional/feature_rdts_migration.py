#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""BIP110/RDTS: at startup, an enforcing node corrects chain state inherited
from a client that was not enforcing the BLAKE2b hardfork.

A data directory advanced by a non-enforcing client can contain SHA256d blocks
at or above the fork height. Normal startup does not re-validate inherited
history, so the enforcing node corrects it: every offending block in the index
(active chain or side branch) is marked invalid and the node reorganizes to
the best valid chain, mirroring BIP148. Truncating the inherited branch at the
fork height leaves it at the last shared pre-fork block, which the BLAKE2b
chain extends past, so the reorg needs no work advantage below the fork.

Each node builds a plain SHA256d chain with the fork unscheduled (as a
non-enforcing client would), then restarts with
-testactivationheight=blake2b@FORK_HEIGHT to become enforcing.

Cases:
  A_CLEAN      inherited chain ends below the fork height -> untouched.
  A_ACTIVE     inherited SHA256d blocks past the fork on the ACTIVE chain ->
               auto-truncated to the fork height at startup (no operator
               command), and the correction persists across a restart.
  A_NONACTIVE  offending blocks on a NON-active side branch -> marked invalid
               at startup while a compliant active chain is left untouched.
  A_BOUNDARY   a chain ending at exactly FORK_HEIGHT - 1 -> untouched (the
               last legal SHA256d block).
  A_MULTI      two independent offending branches on one node -> BOTH
               invalidated.
  A_PRUNED     the offending block's data is pruned -> the node offers a
               reindex and fails closed if declined.
  A_REINDEX_CHAINSTATE  a chainstate rebuild re-runs the contextual header
               check through ConnectBlock, so it recovers on its own.
  A_EMPTY_CHAINSTATE  the block index holds offenders but the coins database
               has no best block (chainstate directory removed by hand), so
               there is no active chain when the correction would run: it must
               stand aside (not crash) and let the rebuild reject the offenders.
  A_CRASH      a flush writes the block index before the coins database; a
               crash in between, right after the correction, leaves the coins
               tip on a block already marked invalid. The next start must
               rewind to the last valid block on its own, not assert.
  A_WARNING    the invalidated SHA256d branch outweighs the BLAKE2b chain by
               construction; it must not raise the "do not appear to fully
               agree with our peers" warning (which is re-derived from the
               index at every start), while a genuinely invalid heavier
               BLAKE2b-era branch still does.
"""
import os
import shutil

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.script import CScript, OP_RETURN, OP_NOP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal

FORK_HEIGHT = 288
CHAIN_TIP = 440
FORK_WARNING = "do not appear to fully agree with our peers"
# Large enough that a regtest tip is never "old", taking the node out of IBD
# (the fork warning is suppressed during IBD).
NOT_IBD = '-maxtipage=100000000000'

# The pruned case needs the violator >= MIN_BLOCKS_TO_KEEP (288) below the tip.
PRUNE_FORK_HEIGHT = 144
PRUNE_TIP = 432        # violator + MIN_BLOCKS_TO_KEEP
# A ~64kiB coinbase so each block fills a -fastprune block file (64kiB), making
# the violator's file independently prunable.
BIG_SCRIPT = CScript([OP_RETURN] + [OP_NOP] * 70000)
# The first BLAKE2b block's coinbase must contain the headline; this value must
# match the test framework's default -blake2b_headline argument.
HEADLINE = b'BLAKE2b functional test headline'


def fork_arg(height=FORK_HEIGHT):
    return f'-testactivationheight=blake2b@{height}'


class RdtsMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 10
        self.setup_clean_chain = True
        # Every node first builds a SHA256d chain with the fork unscheduled,
        # exactly as a non-enforcing client would; enforcement arrives via a
        # restart with -testactivationheight=blake2b@FORK_HEIGHT.
        self.extra_args = [[], [], [], [], [], ['-prune=1', '-fastprune'], [], [], [], []]

    def setup_network(self):
        self.setup_nodes()  # driven directly, no connections

    # ---- block helpers -------------------------------------------------

    def make_block(self, node, parent_hash, parent_time, height, *, v2=False, txs=None, coinbase=None):
        if coinbase is None:
            coinbase = create_coinbase(height)
            if v2:
                # The first BLAKE2b block must carry the headline.
                coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + HEADLINE)
                coinbase.rehash()
        block = create_block(int(parent_hash, 16), coinbase, ntime=parent_time + 1,
                             txlist=txs, height=height, header_v2=v2)
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_tip(self, node, *, v2=False, time_offset=1):
        """Extend the node's active tip by one block."""
        tip = node.getbestblockhash()
        blk = self.make_block(node, tip, node.getblockheader(tip)['time'] + time_offset - 1,
                              node.getblockcount() + 1, v2=v2)
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        return blk

    def mine_to(self, node, target):
        while node.getblockcount() < target:
            self.submit_tip(node)

    def make_side_block(self, node, fork_height, time_offset=100):
        """A sibling of the active chain's block at fork_height + 1: same
        parent, offset timestamp so the hash differs."""
        parent = node.getblockhash(fork_height)
        parent_time = node.getblockheader(parent)['time']
        blk = self.make_block(node, parent, parent_time + time_offset, fork_height + 1)
        # "inconclusive" == accepted as a valid lower-work fork, not the tip.
        assert node.submitblock(blk.serialize().hex()) in (None, "inconclusive")
        return blk

    def extend_side_block(self, node, parent_blk, height):
        blk = self.make_block(node, parent_blk.hash, parent_blk.nTime, height)
        assert node.submitblock(blk.serialize().hex()) in (None, "inconclusive")
        return blk

    def submit_big_tip(self, node):
        """Extend the tip with a ~64kiB block (fills one -fastprune file)."""
        tip = node.getbestblockhash()
        cb = create_coinbase(node.getblockcount() + 1, script_pubkey=BIG_SCRIPT)
        block = self.make_block(node, tip, node.getblockheader(tip)['time'],
                                node.getblockcount() + 1, coinbase=cb)
        assert_equal(node.submitblock(block.serialize().hex()), None)

    def restart(self, i, extra):
        self.stop_node(i)
        self.start_node(i, extra_args=extra)
        return self.nodes[i]

    def chaintip_status(self, node, block_hash):
        for t in node.getchaintips():
            if t['hash'] == block_hash:
                return t['status']
        return None

    def has_fork_warning(self, node):
        return any(FORK_WARNING in w for w in node.getblockchaininfo()['warnings'])

    # ---- test ----------------------------------------------------------

    def run_test(self):
        n_clean, n_active, n_nonactive, n_bound, n_multi, n_prune, n_rc, n_empty, n_warn, n_crash = self.nodes

        # A_CLEAN: an inherited chain that never reached the fork height has
        # no offending blocks and must be left alone.
        self.log.info("A_CLEAN: inherited chain below the fork height is untouched")
        self.mine_to(n_clean, FORK_HEIGHT - 50)
        tip_before = n_clean.getbestblockhash()
        n_clean = self.restart(0, [fork_arg()])
        assert_equal(n_clean.getbestblockhash(), tip_before)
        assert_equal(n_clean.getblockcount(), FORK_HEIGHT - 50)
        self.log.info("  A_CLEAN CONFIRMED: pre-fork chain not disturbed")

        # A_ACTIVE: the real migration shape. The inherited ACTIVE chain runs
        # SHA256d well past the fork height; the enforcing node truncates it to
        # the last legal pre-fork block. A second offending branch is planted
        # so one correction pass handles an active-chain reorg and a
        # side-branch mark together.
        self.log.info("A_ACTIVE: inherited SHA256d chain past the fork is truncated")
        self.mine_to(n_active, CHAIN_TIP)
        old_tip = n_active.getbestblockhash()
        first_bad = n_active.getblockhash(FORK_HEIGHT)
        side_parent = self.make_side_block(n_active, FORK_HEIGHT - 2, time_offset=200)
        side_bad = self.extend_side_block(n_active, side_parent, FORK_HEIGHT)
        assert_equal(n_active.getbestblockhash(), old_tip)
        n_active = self.restart(1, [fork_arg()])
        assert_equal(n_active.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_active, old_tip), 'invalid')
        assert n_active.getblock(first_bad)['confirmations'] < 0
        assert_equal(self.chaintip_status(n_active, side_bad.hash), 'invalid')
        self.log.info(f"  truncated to height {n_active.getblockcount()}; active and "
                      f"non-active offenders both invalidated in one pass")
        n_active = self.restart(1, [fork_arg()])
        assert_equal(n_active.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_active, old_tip), 'invalid')
        self.log.info("  A_ACTIVE CONFIRMED: correction persists across restart (idempotent)")

        # A_NONACTIVE: an offending branch that is NOT the active chain must
        # also be invalidated. Note an offending branch always reaches at least
        # FORK_HEIGHT, so it necessarily outruns any compliant SHA256d chain
        # (which stops at FORK_HEIGHT - 1): the only compliant chain that can
        # be longer is a real BLAKE2b chain past the fork, which is also the
        # true post-fork topology. Build it in three phases.
        self.log.info("A_NONACTIVE: offending side branch invalidated, BLAKE2b chain kept")
        # Phase 1, still non-enforcing: main SHA256d chain plus an offending
        # side branch that (being longer) takes over as the active chain.
        self.mine_to(n_nonactive, FORK_HEIGHT - 1)
        shared_tip = n_nonactive.getbestblockhash()
        side_parent = self.make_side_block(n_nonactive, FORK_HEIGHT - 3)
        side_mid = self.extend_side_block(n_nonactive, side_parent, FORK_HEIGHT - 1)
        side_bad = self.extend_side_block(n_nonactive, side_mid, FORK_HEIGHT)
        assert_equal(n_nonactive.getbestblockhash(), side_bad.hash)
        # Phase 2: enforcing. The correction invalidates the offending block
        # and the node falls back to a legal pre-fork tip. Truncating the
        # branch at FORK_HEIGHT leaves it exactly as long as the main chain
        # (any branch reaching FORK_HEIGHT also has a block at FORK_HEIGHT-1),
        # so which of the two equal-work tips wins is an arbitrary tie: assert
        # the height and the invalidation, not the winner.
        n_nonactive = self.restart(2, [fork_arg()])
        assert_equal(n_nonactive.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_nonactive, side_bad.hash), 'invalid')
        # Phase 3: extend across the fork with BLAKE2b, so the valid chain is
        # genuinely the active one, then restart: the correction must leave it
        # alone while the offending branch stays invalid.
        for _ in range(3):
            self.submit_tip(n_nonactive, v2=True)
        blake_tip = n_nonactive.getbestblockhash()
        assert_equal(n_nonactive.getblockcount(), FORK_HEIGHT + 2)
        n_nonactive = self.restart(2, [fork_arg()])
        assert_equal(n_nonactive.getbestblockhash(), blake_tip)
        assert_equal(self.chaintip_status(n_nonactive, side_bad.hash), 'invalid')
        self.log.info("  A_NONACTIVE CONFIRMED: non-active offender invalidated, BLAKE2b chain kept")

        # A_BOUNDARY: a chain ending at exactly FORK_HEIGHT - 1 is entirely
        # legal SHA256d history and must not be touched.
        self.log.info("A_BOUNDARY: chain ending at FORK_HEIGHT - 1 is untouched")
        self.mine_to(n_bound, FORK_HEIGHT - 1)
        bound_tip = n_bound.getbestblockhash()
        n_bound = self.restart(3, [fork_arg()])
        assert_equal(n_bound.getbestblockhash(), bound_tip)
        assert_equal(n_bound.getblockcount(), FORK_HEIGHT - 1)
        self.log.info("  A_BOUNDARY CONFIRMED: last legal SHA256d block kept")

        # A_MULTI: two independent offending branches must BOTH be invalidated
        # in one pass, leaving only legal pre-fork history. (One of the
        # offending branches is the active chain here, since any branch
        # reaching FORK_HEIGHT outruns a chain that stops below it.)
        self.log.info("A_MULTI: two offending branches -> both invalidated (multi-pass)")
        self.mine_to(n_multi, FORK_HEIGHT - 1)
        a_parent = self.make_side_block(n_multi, FORK_HEIGHT - 2, time_offset=100)
        a_bad = self.extend_side_block(n_multi, a_parent, FORK_HEIGHT)
        b_parent = self.make_side_block(n_multi, FORK_HEIGHT - 3, time_offset=200)
        b_mid = self.extend_side_block(n_multi, b_parent, FORK_HEIGHT - 1)
        b_bad = self.extend_side_block(n_multi, b_mid, FORK_HEIGHT)
        n_multi = self.restart(4, [fork_arg()])
        # Both branches truncate to FORK_HEIGHT - 1, tying with the main chain
        # on work, so assert the height and the invalidations rather than which
        # of the equal-work tips wins (see A_NONACTIVE).
        assert_equal(n_multi.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_multi, a_bad.hash), 'invalid')
        assert_equal(self.chaintip_status(n_multi, b_bad.hash), 'invalid')
        self.log.info("  A_MULTI CONFIRMED: both offending branches invalidated")

        # A_PRUNED: the offending block sits below the prune horizon, so the
        # data needed to rewind to it is gone. The node must FAIL CLOSED rather
        # than partially rewind and strand good blocks.
        self.log.info("A_PRUNED: offender's data pruned -> offers reindex, fails closed if declined")
        for _ in range(PRUNE_TIP):
            self.submit_big_tip(n_prune)
        assert_equal(n_prune.getblockcount(), PRUNE_TIP)
        prune_tip = n_prune.getbestblockhash()
        pruned_to = n_prune.pruneblockchain(PRUNE_FORK_HEIGHT)
        assert pruned_to >= PRUNE_FORK_HEIGHT, f"pruneblockchain only reached {pruned_to}"
        self.stop_node(5)
        self.nodes[5].assert_start_raises_init_error(
            extra_args=['-prune=1', '-fastprune', fork_arg(PRUNE_FORK_HEIGHT)],
            expected_msg="is invalid under it, and correcting it needs block data that has been pruned",
            match=ErrorMatch.PARTIAL_REGEX)
        # When the prompt is approved (here via the test option), the node takes
        # the reindex path instead of aborting. On a pruned node the rebuild
        # cannot restore the pruned pre-fork history (that is why the prompt
        # says it will re-download the chain), so the offending blocks left in
        # the remaining files have no parent to connect to: the node ends up
        # far below the fork with the inherited tip no longer active, rather
        # than running on it.
        with self.nodes[5].busy_wait_for_debug_log([b"Reindexing finished"]):
            self.start_node(5, extra_args=['-prune=1', '-fastprune', fork_arg(PRUNE_FORK_HEIGHT),
                                           '-test=reindex_after_failure_noninteractive_yes'])
        assert self.nodes[5].getblockcount() < PRUNE_FORK_HEIGHT
        assert self.nodes[5].getbestblockhash() != prune_tip
        self.stop_node(5)
        self.log.info("  A_PRUNED CONFIRMED: prompts to rebuild; declined -> fail closed, approved -> reindex")

        # A_REINDEX_CHAINSTATE: a chainstate rebuild reconnects blocks through
        # ConnectBlock, which re-runs the contextual bad-version-blake2b check,
        # so it recovers on its own without the startup correction pass.
        self.log.info("A_REINDEX_CHAINSTATE: chainstate rebuild re-enforces the fork rule")
        self.mine_to(n_rc, CHAIN_TIP)
        rc_bad_tip = n_rc.getbestblockhash()
        n_rc = self.restart(6, [fork_arg(), '-reindex-chainstate'])
        # The rebuild runs in the background. Wait for the verdict itself (the
        # tip is marked invalid only when the rebuild rejects it), not for a
        # height the count would also pass through if the rule were broken.
        self.wait_until(lambda: self.chaintip_status(n_rc, rc_bad_tip) == 'invalid')
        assert_equal(n_rc.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(n_rc.getbestblockhash(), n_rc.getblockhash(FORK_HEIGHT - 1))
        self.stop_node(6)
        self.log.info("  A_REINDEX_CHAINSTATE CONFIRMED: recovered during the rebuild")

        # A_EMPTY_CHAINSTATE: the coins database has no best block, so the
        # active chain is empty when the correction would run (LoadChainTip is
        # skipped), exactly as under a reindex but without the flag. The pass
        # must stand aside rather than invalidate against a missing tip, and the
        # rebuild rejects the offenders through ConnectBlock, as it does for
        # -reindex-chainstate.
        self.log.info("A_EMPTY_CHAINSTATE: offenders in the index, no active chain -> rebuild recovers")
        self.mine_to(n_empty, FORK_HEIGHT + 5)
        empty_bad_tip = n_empty.getbestblockhash()
        self.stop_node(7)
        shutil.rmtree(os.path.join(n_empty.chain_path, 'chainstate'))
        self.start_node(7, extra_args=[fork_arg()])
        self.wait_until(lambda: self.chaintip_status(n_empty, empty_bad_tip) == 'invalid')
        assert_equal(n_empty.getblockcount(), FORK_HEIGHT - 1)
        # A plain restart afterwards is the normal shape and must stay put.
        n_empty = self.restart(7, [fork_arg()])
        assert_equal(n_empty.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_empty, empty_bad_tip), 'invalid')
        self.log.info("  A_EMPTY_CHAINSTATE CONFIRMED: no crash, rebuild rejected the offenders")

        # A_CRASH: FlushStateToDisk writes the block index (synchronously) and
        # then the coins database. If the node dies in between right after the
        # correction, the index keeps the invalid marks while the coins
        # database still names the old tip. Reproduced by restoring the
        # pre-correction chainstate under the post-correction block index.
        self.log.info("A_CRASH: coins tip marked invalid after an interrupted flush -> rewound at startup")
        self.mine_to(n_crash, CHAIN_TIP)
        old_tip = n_crash.getbestblockhash()
        self.stop_node(9)
        chainstate = os.path.join(n_crash.chain_path, 'chainstate')
        stale = os.path.join(n_crash.chain_path, 'chainstate.stale')
        shutil.copytree(chainstate, stale)
        self.start_node(9, extra_args=[fork_arg()])
        assert_equal(n_crash.getblockcount(), FORK_HEIGHT - 1)
        self.stop_node(9)
        shutil.rmtree(chainstate)
        shutil.move(stale, chainstate)
        with n_crash.assert_debug_log(["is marked invalid; the chain will be rewound"]):
            self.start_node(9, extra_args=[fork_arg()])
        assert_equal(n_crash.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.chaintip_status(n_crash, old_tip), 'invalid')
        n_crash = self.restart(9, [fork_arg()])
        assert_equal(n_crash.getblockcount(), FORK_HEIGHT - 1)
        self.log.info("  A_CRASH CONFIRMED: recovered without operator action")

        # A_WARNING: the invalidated SHA256d branch keeps far more work than the
        # BLAKE2b chain (on mainnet, ~2^20 BLAKE2b blocks per inherited SHA256d
        # block). It must not drive the "do not appear to fully agree with our
        # peers" warning, which is re-derived from the highest-work failed index
        # entry at every start (so it would first show on the SECOND start), nor
        # -alertnotify. A genuinely invalid heavier BLAKE2b-era branch must still
        # raise it: the exclusion is keyed on the fork block's PoW, nothing wider.
        self.log.info("A_WARNING: invalidated SHA256d branch does not raise the fork warning")
        self.mine_to(n_warn, FORK_HEIGHT + 20)
        warn_bad_tip = n_warn.getbestblockhash()
        n_warn = self.restart(8, [fork_arg()])
        assert_equal(n_warn.getblockcount(), FORK_HEIGHT - 1)
        # Second start, out of IBD (the warning is suppressed during IBD), then a
        # tip update to evaluate it.
        n_warn = self.restart(8, [fork_arg(), NOT_IBD])
        assert_equal(self.chaintip_status(n_warn, warn_bad_tip), 'invalid')
        self.submit_tip(n_warn, v2=True)
        assert_equal(n_warn.getblockchaininfo()['initialblockdownload'], False)
        assert not self.has_fork_warning(n_warn), n_warn.getblockchaininfo()['warnings']
        # Negative control: a BLAKE2b-era branch invalidated by hand, heavier
        # than the new tip by more than 6 blocks after a restart, still warns.
        for _ in range(9):
            self.submit_tip(n_warn, v2=True)
        assert_equal(n_warn.getblockcount(), FORK_HEIGHT + 9)
        n_warn.invalidateblock(n_warn.getblockhash(FORK_HEIGHT + 1))
        assert_equal(n_warn.getblockcount(), FORK_HEIGHT)
        n_warn = self.restart(8, [fork_arg(), NOT_IBD])
        self.submit_tip(n_warn, v2=True, time_offset=2)  # a sibling of the invalidated block, not a duplicate
        assert self.has_fork_warning(n_warn), n_warn.getblockchaininfo()['warnings']
        self.log.info("  A_WARNING CONFIRMED: SHA256d branch excluded, BLAKE2b-era invalid branch still warns")

        self.log.info("")
        self.log.info("RESULT: an enforcing node auto-corrects inherited pre-hardfork history on "
                      "both the active chain (truncate + reorg) and non-active branches (mark "
                      "invalid), persists the correction, and never disturbs legal history.")


if __name__ == '__main__':
    RdtsMigrationTest(__file__).main()
