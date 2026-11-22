#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test rolling coinbase maturity policy and consensus.

From ACTIVATION, every reward mined from START up to (not including) END needs
ROLLING confirmations, counted from its own block, so one reward unlocks per
block. Rewards before START and from END on keep ordinary maturity. Relay holds
covered rewards to the rolling depth as soon as the rule is scheduled.

The same checks run on three nodes, without RDTS, with RDTS active, and with
RDTS already expired, since the rule must not depend on RDTS.
"""

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

START = 110
ACTIVATION = 230
END = 240
ROLLING = COINBASE_MATURITY + 50
DEPLOYMENT = "rolling_coinbase_maturity"
FORK_HEIGHT = 2
PREMATURE = "bad-txns-premature-spend-of-coinbase"

BASE_ARGS = [
    f"-testcoinbasematurityrolling={ACTIVATION}:{START}:{END}:{ROLLING}",
    "-checkmempool=1",
]
# name, extra args, whether RDTS is enforced once blocks are being mined
MODES = [
    ("without RDTS", [], None),
    ("with RDTS active", [f"-testactivationheight=blake2b@{FORK_HEIGHT}", "-rdtsexpiry=4102444800"], True),
    ("with RDTS expired", [f"-testactivationheight=blake2b@{FORK_HEIGHT}", "-rdtsexpiry=1296688603"], False),
]


class RollingCoinbaseMaturityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = len(MODES)
        self.setup_clean_chain = True
        self.extra_args = [BASE_ARGS + extra for _, extra, _ in MODES]

    def setup_network(self):
        # Each node is its own chain.
        self.setup_nodes()

    def create_next_block(self, node, txs=None):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(height, script_pubkey=self.wallet.get_output_script()),
            node.getblockheader(tip)["time"] + 1,
            height=height,
            txlist=txs,
            header_v2=self.rdts is not None and height >= FORK_HEIGHT,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def submit(self, node, txs=None):
        return node.submitblock(self.create_next_block(node, txs).serialize().hex())

    def coinbase_spend(self, node, height):
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        if not any(u["txid"] == txid for u in self.wallet._utxos):
            self.wallet.rescan_utxos(include_mempool=False)
        return self.wallet.create_self_transfer(utxo_to_spend=self.wallet.get_utxo(txid=txid, mark_as_spent=False))

    def mine_to(self, node, height):
        while node.getblockcount() < height:
            assert_equal(self.submit(node), None)

    def assert_refused(self, node, spend):
        """Neither relay nor consensus accepts the spend in the next block."""
        assert_raises_rpc_error(-26, PREMATURE, node.sendrawtransaction, spend["hex"])
        assert_equal(self.submit(node, [spend["tx"]]), PREMATURE)

    def assert_accepted(self, node, spend):
        """Relay accepts the spend, and the next block may include it."""
        node.sendrawtransaction(spend["hex"])
        assert spend["txid"] in node.getrawmempool()
        assert_equal(self.submit(node, [spend["tx"]]), None)

    def assert_deployment(self, node, active):
        deployment = node.getdeploymentinfo()["deployments"][DEPLOYMENT]
        assert_equal(deployment["type"], "flagday")
        assert_equal(deployment["height"], ACTIVATION)
        assert_equal(deployment["coinbase_start_height"], START)
        assert_equal(deployment["coinbase_end_height"], END)
        assert_equal(deployment["maturity"], ROLLING)
        assert "height_end" not in deployment
        assert "expiry_time" not in deployment
        assert_equal(deployment["active"], active)
        rules = ["segwit"] + (["blake2b"] if self.rdts is not None else [])
        assert_equal(DEPLOYMENT in node.getblocktemplate({"rules": rules})["rules"], active)

    def assert_rdts(self, node):
        if self.rdts is None:
            return
        assert_equal(node.getdeploymentinfo()["deployments"]["reduced_data"]["active"], self.rdts)

    def check_rejected_schedules(self):
        node = self.nodes[0]
        self.stop_node(0)
        for args, msg in [
            ([f"-testcoinbasematurityrolling={ACTIVATION}:{START}:{END}"], "Invalid format"),
            (["-testcoinbasematurityrolling=1:2:3:4:5"], "Invalid format"),
            ([f"-testcoinbasematurityrolling=1:{START}:{END}:{ROLLING}"], "Invalid activation height"),
            ([f"-testcoinbasematurityrolling=x:{START}:{END}:{ROLLING}"], "Invalid activation height"),
            ([f"-testcoinbasematurityrolling={ACTIVATION}:-1:{END}:{ROLLING}"], "Invalid start height"),
            ([f"-testcoinbasematurityrolling={ACTIVATION}:99999999999999999999:{END}:{ROLLING}"], "Invalid start height"),
            ([f"-testcoinbasematurityrolling={ACTIVATION}:{START}:{START}:{ROLLING}"], "Invalid end height"),
            ([f"-testcoinbasematurityrolling={ACTIVATION}:{START}:{END}:{COINBASE_MATURITY}"], "Invalid maturity"),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=msg, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=self.extra_args[0].copy())

    def run_mode(self, n):
        name, _, self.rdts = MODES[n]
        node = self.nodes[n]
        self.log.info(f"Node {n}, {name}")
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 10, sync_fun=self.no_op)
        self.mine_to(node, START - 1 + COINBASE_MATURITY - 1)
        self.assert_rdts(node)

        self.log.info("  A reward from before the start height keeps ordinary maturity")
        self.assert_accepted(node, self.coinbase_spend(node, START - 1))

        self.log.info("  Before activation, relay already holds covered rewards; consensus does not yet")
        self.mine_to(node, START + COINBASE_MATURITY + 1)
        early = self.coinbase_spend(node, START)
        assert_raises_rpc_error(-26, PREMATURE, node.sendrawtransaction, early["hex"])
        assert_equal(self.submit(node, [early["tx"]]), None)

        self.mine_to(node, ACTIVATION - 2)
        self.assert_deployment(node, active=False)
        self.mine_to(node, ACTIVATION - 1)
        self.assert_deployment(node, active=True)

        self.log.info("  Each covered reward unlocks at its own height + ROLLING, one per block")
        self.mine_to(node, START + 1 + ROLLING - 2)
        self.assert_refused(node, self.coinbase_spend(node, START + 1))
        for coin_height in range(START + 1, START + 4):
            self.mine_to(node, coin_height + ROLLING - 1)
            # The next block is exactly ROLLING above this reward and one short for the next.
            self.assert_refused(node, self.coinbase_spend(node, coin_height + 1))
            spend = self.coinbase_spend(node, coin_height)
            if coin_height == START + 1:
                self.log.info("  A reorg that makes the spend premature again evicts it from the mempool")
                node.sendrawtransaction(spend["hex"])
                tip_hash = node.getbestblockhash()
                node.invalidateblock(tip_hash)
                assert spend["txid"] not in node.getrawmempool()
                node.reconsiderblock(tip_hash)
            self.assert_accepted(node, spend)
            assert_equal(node.getblockcount(), coin_height + ROLLING)

        self.log.info("  The rule still holds after a restart")
        self.restart_node(n)
        self.assert_deployment(node, active=True)
        self.assert_refused(node, self.coinbase_spend(node, START + 10))

        self.log.info("  Coverage ends at the end height: the last covered reward needs ROLLING, the next one does not")
        self.mine_to(node, END + COINBASE_MATURITY - 2)
        self.assert_refused(node, self.coinbase_spend(node, END))
        self.mine_to(node, END + COINBASE_MATURITY - 1)
        self.assert_refused(node, self.coinbase_spend(node, END - 1))
        self.assert_accepted(node, self.coinbase_spend(node, END))
        self.mine_to(node, END - 1 + ROLLING - 2)
        self.assert_refused(node, self.coinbase_spend(node, END - 1))
        self.mine_to(node, END - 1 + ROLLING - 1)
        self.assert_accepted(node, self.coinbase_spend(node, END - 1))

        self.assert_rdts(node)
        self.assert_deployment(node, active=True)

    def run_test(self):
        self.check_rejected_schedules()
        for n in range(len(MODES)):
            self.run_mode(n)


if __name__ == "__main__":
    RollingCoinbaseMaturityTest(__file__).main()
