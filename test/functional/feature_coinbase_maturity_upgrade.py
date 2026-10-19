#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test an actual #419-compatible binary and rolling-maturity upgrade.

Pass --old-bitcoind=/path/to/bitcoind built from #419 or its target branch
before this patch. All shared new-rule blocks must be accepted by the old
node. On upgrade, its height-limited marker must trigger a rewind to the old
release minus one, revalidate stale side branches, and reject premature spends.
"""
from pathlib import Path

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

START = 2
RELEASE = START + 6480
T0 = 1_800_000_000
EXPIRY = T0 + 20000
REJECT = "bad-txns-premature-spend-of-coinbase"


class RollingCoinbaseMaturityUpgradeTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--after-expiry", action="store_true", help="Upgrade with an expired active tip containing a pre-expiry violation")
        parser.add_argument("--old-bitcoind", help="Unmodified #419-compatible bitcoind (never downloaded by this test)")

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = ["-checkmempool=1", f"-mocktime={T0 + 10000}"]
        self.old_args = common + [f"-testcoinbasematuritylong={START}:{START}:{RELEASE}"]
        self.new_args = self.old_args + [f"-testcoinbasematuritylongexpiry={EXPIRY}"]
        self.extra_args = [self.old_args, self.new_args]

    def skip_test_if_missing_module(self):
        if not self.options.old_bitcoind:
            raise SkipTest("--old-bitcoind is required for old/new binary compatibility")
        assert Path(self.options.old_bitcoind).is_file()

    def setup_nodes(self):
        self.add_nodes(2, self.extra_args, binary=[self.options.old_bitcoind, self.options.bitcoind])
        self.start_nodes()

    def block(self, node, txs=(), timestamp=None):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        result = create_block(int(tip, 16), create_coinbase(height), timestamp or node.getblockheader(tip)["time"] + 1, height=height, txlist=list(txs))
        add_witness_commitment(result)
        result.solve()
        return result

    def submit(self, node, block, expected=None):
        assert_equal(node.submitblock(block.serialize().hex()), expected)

    def status(self, node, block_hash):
        return next(tip["status"] for tip in node.getchaintips() if tip["hash"] == block_hash)

    def run_test(self):
        old, new = self.nodes
        wallet = MiniWallet(new)
        for node in self.nodes:
            node.setmocktime(T0 + 10000)
        self.generate(wallet, RELEASE - 1)
        assert_equal(old.getbestblockhash(), new.getbestblockhash())
        assert_equal(old.getdeploymentinfo()["deployments"]["long_coinbase_maturity"]["active"], False)
        assert_equal(new.getdeploymentinfo()["deployments"]["long_coinbase_maturity"]["active"], True)
        self.disconnect_nodes(1, 0)
        common_tip = new.getbestblockhash()
        coinbase = new.getblock(new.getblockhash(3))["tx"][0]
        spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase))
        assert_equal(new.testmempoolaccept([spend["hex"]])[0]["reject-reason"], REJECT)
        bad = self.block(new, [spend["tx"]])
        self.log.info("At the old release, #419 accepts the premature spend that the new node rejects")
        self.submit(new, bad, REJECT)
        self.submit(old, bad)
        bad_tip = self.block(old)
        self.submit(old, bad_tip)

        self.log.info("The old node accepts every block of the stricter node's longer valid branch")
        for _ in range(3):
            good = self.block(new)
            self.submit(new, good)
            assert old.submitblock(good.serialize().hex()) in (None, "inconclusive")
        assert_equal(old.getbestblockhash(), new.getbestblockhash())
        assert_equal(self.status(old, bad_tip.hash), "valid-fork")

        # Keep another invalid active branch and an equal-work valid fork in
        # the old database so startup must actually revalidate cached blocks.
        wallet.rescan_utxos()
        # Keep this reward below policy maturity even after the expiry blocks.
        # Height 100 also predates regtest's subsidy halvings to zero.
        later_coin_height = 100
        coinbase = new.getblock(new.getblockhash(later_coin_height))["tx"][0]
        later_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase))
        result = old.testmempoolaccept([later_spend["hex"]])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], REJECT)
        self.log.info("#419 rejects spend %s from height %s at depth %s in policy: %s; accepts it in a block", later_spend["txid"], later_coin_height, old.getblockcount() + 1 - later_coin_height, REJECT)
        later_bad = self.block(old, [later_spend["tx"]])
        self.submit(new, later_bad, REJECT)
        self.submit(old, later_bad)
        later_bad_tip = self.block(old)
        self.submit(old, later_bad_tip)
        for _ in range(2):
            good = self.block(new)
            self.submit(new, good)
            assert old.submitblock(good.serialize().hex()) in (None, "inconclusive")
        assert_equal(old.getbestblockhash(), later_bad_tip.hash)
        if self.options.after_expiry:
            self.log.info("Both branches cross expiry, but the old active branch contains a pre-expiry violation")
            self.new_args = [arg for arg in self.new_args if not arg.startswith("-mocktime=")] + [f"-mocktime={EXPIRY + 10000}"]
            for node in self.nodes:
                node.setmocktime(EXPIRY + 10000)
            for offset in range(11):
                self.submit(old, self.block(old, timestamp=EXPIRY + offset))
                good = self.block(new, timestamp=EXPIRY + offset)
                self.submit(new, good)
                assert old.submitblock(good.serialize().hex()) in (None, "inconclusive")
            assert old.getblockheader(old.getbestblockhash())["mediantime"] >= EXPIRY
            assert new.getblockheader(new.getbestblockhash())["mediantime"] >= EXPIRY
        good_tip = new.getbestblockhash()

        self.log.info("Upgrade the old binary: rewind exactly to release-1 and select the revalidated fork")
        self.stop_node(0)
        old.binary = self.options.bitcoind
        old.args[0] = self.options.bitcoind
        rewind_height = RELEASE - 1
        with old.assert_debug_log(expected_msgs=["Chainstate revalidation: rewinding", f"(height {rewind_height})"]):
            self.start_node(0, extra_args=self.new_args)
        assert_equal(old.getbestblockhash(), good_tip)
        # Shorter stale forks are demoted; they need not be connected until
        # they acquire enough work to compete with the active chain.
        assert_equal(self.status(old, bad_tip.hash), "valid-headers")
        # In the after-expiry variant this is an internal block, not a tip.
        if not self.options.after_expiry:
            assert_equal(self.status(old, later_bad_tip.hash), "invalid")
        else:
            assert old.getblockheader(later_bad_tip.hash)["confirmations"] == -1
        # The first rejected spend has reached 6480 depth by this tip.
        assert_equal(set(old.getrawmempool()), {spend["txid"]})
        if self.options.after_expiry:
            depth = old.getblockcount() + 1 - later_coin_height
            assert 100 <= depth < 6480
            for node in self.nodes:
                result = node.testmempoolaccept([later_spend["hex"]])[0]
                assert_equal(result["allowed"], False)
                assert_equal(result["reject-reason"], REJECT)
                assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, later_spend["hex"])
            self.log.info("After expiry, spend %s from height %s at depth %s is rejected by policy: %s", later_spend["txid"], later_coin_height, depth, REJECT)
        assert_equal(new.getblockheader(common_tip)["height"], rewind_height)
        self.log.info("The persisted marker prevents a second rewind")
        with old.assert_debug_log(expected_msgs=[], unexpected_msgs=["Chainstate revalidation: rewinding"]):
            self.restart_node(0, extra_args=self.new_args)
        assert_equal(old.getbestblockhash(), good_tip)
        assert_equal(set(old.getrawmempool()), {spend["txid"]})
        # Reconnecting peers does not automatically announce an old mempool.
        assert_equal(new.sendrawtransaction(spend["hex"]), spend["txid"])
        if self.options.after_expiry:
            self.log.info("Mine the policy-rejected spend after expiry to prove consensus validity")
            released = self.block(new, [later_spend["tx"]])
            self.submit(new, released)
            assert_equal(new.gettxout(coinbase, 0), None)
        self.connect_nodes(1, 0)
        self.sync_all()
        if self.options.after_expiry:
            assert_equal(old.getbestblockhash(), released.hash)
            assert_equal(old.gettxout(coinbase, 0), None)
        assert_equal(set(old.getrawmempool()), {spend["txid"]})
        self.log.info("Idempotent restart and peer block/mempool resynchronization passed")


if __name__ == "__main__":
    RollingCoinbaseMaturityUpgradeTest(__file__).main()
