#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the release of the long coinbase maturity rule by median time past.

node0 has the release time from the start, and a wallet.
node1 does not enforce the rule (as software that stopped enforcing it
earlier would), accepts a block that the release time makes invalid, and is
then restarted with it.
node2 has an earlier release time, and follows node0's chain given more work.
"""

import time

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_node import ErrorMatch
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

LONG_START_HEIGHT = 2
LONG_ENFORCE_HEIGHT = LONG_START_HEIGHT + COINBASE_MATURITY + 2
COINBASE_MATURITY_POLICY_TIME = 365 * 24 * 60 * 60
DEPLOYMENT = "long_coinbase_maturity"
REJECT_REASON = "bad-txns-premature-spend-of-coinbase"


class LongCoinbaseMaturityReleaseTimeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.enable_wallet_if_possible()
        self.start_time = int(time.time())
        self.early_release_time = self.start_time + 10000
        self.release_time = self.start_time + COINBASE_MATURITY_POLICY_TIME
        self.timed_args = [
            f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:{self.release_time}",
            "-checkmempool=1",
        ]
        self.early_args = [
            f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:{self.early_release_time}",
            "-checkmempool=1",
        ]
        self.extra_args = [self.timed_args, ["-checkmempool=1"], self.early_args]

    def set_time(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def reconnect(self):
        # Peers that have been silent for a jump of mock time are dropped as
        # inactive; wait that out and connect them again
        for a, b in [(0, 1), (1, 2)]:
            self.disconnect_nodes(a, b)
        for a, b in [(0, 1), (1, 2)]:
            self.connect_nodes(a, b)

    def create_next_block(self, node, txs=None):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(height),
            node.getblockheader(tip)["time"] + 1,
            height=height,
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def assert_deployment(self, node, *, active, release_time):
        deployment = node.getdeploymentinfo()["deployments"][DEPLOYMENT]
        assert_equal(deployment["type"], "flagday")
        assert_equal(deployment["height"], LONG_ENFORCE_HEIGHT)
        assert_equal(deployment["coinbase_start_height"], LONG_START_HEIGHT)
        assert_equal(deployment["expiry_time"], release_time)
        assert_equal(deployment["active"], active)
        assert "height_end" not in deployment
        assert "maturity" not in deployment
        assert_equal(DEPLOYMENT in node.getblocktemplate({"rules": ["segwit"]})["rules"], active)

    def get_chaintip_status(self, node, block_hash):
        for tip in node.getchaintips():
            if tip["hash"] == block_hash:
                return tip["status"]
        raise AssertionError(f"missing chaintip {block_hash}")

    def coinbase_of(self, node, block_hash):
        return node.getblock(block_hash)["tx"][0]

    def check_rejected_schedules(self):
        node = self.nodes[0]
        self.stop_node(0)
        for args, msg in [
            ([f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}"], "Invalid format"),
            ([f"-testcoinbasematuritylong=-1:{LONG_ENFORCE_HEIGHT}:{self.release_time}"], "Invalid start height"),
            ([f"-testcoinbasematuritylong={LONG_START_HEIGHT}:1:{self.release_time}"], "Invalid enforce height"),
            ([f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:soon"], "Invalid release time"),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=msg, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=self.timed_args)
        self.connect_nodes(0, 1)

    def run_test(self):
        self.check_rejected_schedules()
        node_timed, node_lax, node_early = self.nodes
        wallet = MiniWallet(node_timed)
        self.set_time(self.start_time)

        self.log.info("Build a common chain on which the rule is enforced")
        self.generate(wallet, LONG_ENFORCE_HEIGHT + 1)
        self.assert_deployment(node_timed, active=True, release_time=self.release_time)
        assert DEPLOYMENT not in node_lax.getdeploymentinfo()["deployments"]
        self.assert_deployment(node_early, active=True, release_time=self.early_release_time)

        self.log.info("Only the earlier release time is reached by the first jump of time")
        self.set_time(self.early_release_time + 100)
        self.reconnect()
        late_blocks = self.generate(wallet, 7)
        assert node_timed.getblockheader(late_blocks[-1])["mediantime"] >= self.early_release_time
        self.assert_deployment(node_timed, active=True, release_time=self.release_time)
        self.assert_deployment(node_early, active=False, release_time=self.early_release_time)
        # Coinbases minted at a median time past past the earlier release
        # time: their year of policy hold outlasts the later release time
        late_coinbase_a = self.coinbase_of(node_timed, late_blocks[-2])
        late_coinbase_b = self.coinbase_of(node_timed, late_blocks[-1])
        if self.is_wallet_compiled():
            wallet_block = self.generatetoaddress(node_timed, 1, node_timed.getnewaddress())[0]
            wallet_coinbase = self.coinbase_of(node_timed, wallet_block)
            wallet_coinbase_value = node_timed.getblock(wallet_block, 2)["tx"][0]["vout"][0]["value"]
        common_tip = node_timed.getbestblockhash()

        self.log.info("A block spending a held coinbase before the release time is invalid only with it")
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)
        held_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=self.coinbase_of(node_timed, node_timed.getblockhash(LONG_START_HEIGHT))))
        assert_raises_rpc_error(-26, REJECT_REASON, node_timed.sendrawtransaction, held_spend["hex"])
        bad_block = self.create_next_block(node_timed, [held_spend["tx"]])
        assert_equal(node_timed.submitblock(bad_block.serialize().hex()), REJECT_REASON)
        assert_equal(node_timed.getbestblockhash(), common_tip)
        for node in (node_lax, node_early):
            assert_equal(node.submitblock(bad_block.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), bad_block.hash)
        self.generate(node_lax, 2, sync_fun=self.no_op)
        bad_branch_tip = node_lax.getbestblockhash()

        self.log.info("Learning of the release time revalidates the blocks connected from the enforce height on")
        # Blocks are timestamped in mock time, which a restart forgets
        restart_args = self.timed_args + [f"-mocktime={self.early_release_time + 100}"]
        with node_lax.assert_debug_log(expected_msgs=["Chainstate revalidation: rewinding"]):
            self.restart_node(1, extra_args=restart_args)
        assert_equal(node_lax.getbestblockhash(), common_tip)
        assert_equal(self.get_chaintip_status(node_lax, bad_branch_tip), "invalid")
        assert_equal(node_lax.getrawmempool(), [])
        self.assert_deployment(node_lax, active=True, release_time=self.release_time)

        self.log.info("...and only once")
        with node_lax.assert_debug_log(expected_msgs=[], unexpected_msgs=["Chainstate revalidation: rewinding"]):
            self.restart_node(1, extra_args=restart_args)
        assert_equal(node_lax.getbestblockhash(), common_tip)

        self.log.info("A node past its own release time follows the chain that respects the later one, given more work")
        self.generate(wallet, 2, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_blocks()
        assert_equal(node_early.getbestblockhash(), node_timed.getbestblockhash())
        assert_equal(self.get_chaintip_status(node_early, bad_block.hash), "valid-fork")

        self.log.info("Bury the later coinbases under ordinary maturity")
        self.generate(wallet, COINBASE_MATURITY)

        self.log.info("The rule holds until the parent's median time past reaches the release time, however deep the coinbase is")
        self.set_time(self.release_time + 100)
        self.reconnect()
        self.generate(wallet, 5)
        self.assert_deployment(node_timed, active=True, release_time=self.release_time)
        assert_raises_rpc_error(-26, REJECT_REASON, node_timed.sendrawtransaction, held_spend["hex"])
        # Compact block relay announces a block before validating it, so keep
        # this one from reaching a node that would accept it
        self.disconnect_nodes(0, 1)
        bad_block = self.create_next_block(node_timed, [held_spend["tx"]])
        assert_equal(node_timed.submitblock(bad_block.serialize().hex()), REJECT_REASON)

        release_block = self.generate(wallet, 1, sync_fun=self.no_op)[0]
        assert node_timed.getblockheader(release_block)["mediantime"] >= self.release_time
        self.assert_deployment(node_timed, active=False, release_time=self.release_time)

        self.log.info("Once released, a covered coinbase a year old is relayed again")
        node_timed.sendrawtransaction(held_spend["hex"])
        assert_equal(node_timed.getrawmempool(), [held_spend["txid"]])

        self.log.info("A reorg back below the release time holds it again")
        node_timed.invalidateblock(release_block)
        assert_equal(node_timed.getrawmempool(), [])
        self.assert_deployment(node_timed, active=True, release_time=self.release_time)
        node_timed.reconsiderblock(release_block)
        assert_equal(node_timed.getbestblockhash(), release_block)
        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("Policy holds a released coinbase until its year is up, while consensus accepts its spend")
        late_spend_a = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=late_coinbase_a))
        assert_raises_rpc_error(-26, REJECT_REASON, node_timed.sendrawtransaction, late_spend_a["hex"])
        node_timed.sendrawtransaction(held_spend["hex"])
        block = self.create_next_block(node_timed, [held_spend["tx"], late_spend_a["tx"]])
        assert_equal(node_timed.submitblock(block.serialize().hex()), None)
        self.sync_blocks()
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), block.hash)
        if self.is_wallet_compiled():
            self.log.info("The wallet treats a coinbase as immature until its year is up")
            assert_equal(node_timed.gettransaction(wallet_coinbase)["details"][0]["category"], "immature")
            balances = node_timed.getbalances()["mine"]
            assert_equal(balances["immature"], wallet_coinbase_value)
            assert_equal(balances["trusted"], 0)

        self.log.info("A year of median time past releases each coinbase on its own")
        late_spend_b = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=late_coinbase_b))
        self.set_time(self.early_release_time + COINBASE_MATURITY_POLICY_TIME + 1000)
        self.reconnect()
        self.generate(wallet, 5)
        assert_raises_rpc_error(-26, REJECT_REASON, node_timed.sendrawtransaction, late_spend_b["hex"])
        if self.is_wallet_compiled():
            assert_equal(node_timed.gettransaction(wallet_coinbase)["details"][0]["category"], "immature")
        self.generate(wallet, 1)
        node_timed.sendrawtransaction(late_spend_b["hex"])
        assert_equal(node_timed.getrawmempool(), [late_spend_b["txid"]])
        if self.is_wallet_compiled():
            assert_equal(node_timed.gettransaction(wallet_coinbase)["details"][0]["category"], "generate")
            balances = node_timed.getbalances()["mine"]
            assert_equal(balances["immature"], 0)
            assert_equal(balances["trusted"], wallet_coinbase_value)
        self.generate(wallet, 1)
        assert_equal(node_timed.getrawmempool(), [])
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), node_timed.getbestblockhash())


if __name__ == "__main__":
    LongCoinbaseMaturityReleaseTimeTest(__file__).main()
