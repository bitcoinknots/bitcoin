#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Rolling coinbase maturity, policy, wallet, GBT and reorg boundaries.

The default synthetic schedule is small enough for routine CI. --full-depth
uses mainnet's 6480-block depth. --before-boundary moves the old release later
to exercise successful spends before that boundary, which cannot occur for
covered mainnet rewards before 979920.
"""
from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import COIN
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

START = 2
SMALL_MATURITY = 120
T0 = 1_800_000_000
EXPIRY = 1_819_756_800
REJECT = "bad-txns-premature-spend-of-coinbase"
DEPLOYMENT = "long_coinbase_maturity"


class RollingCoinbaseMaturityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--before-boundary", action="store_true")
        parser.add_argument("--full-depth", action="store_true", help="Exercise the mainnet 6480-block depth (extended suite)")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Reindexing roughly 20,000 blocks can hold the chain lock for longer
        # than the default RPC timeout.
        self.rpc_timeout = 600
        self.enable_wallet_if_possible()
        self.maturity = 6480 if self.options.full_depth else SMALL_MATURITY
        self.release = (7000 if self.options.full_depth else 160) if self.options.before_boundary else START + self.maturity
        self.args = [
            f"-testcoinbasematuritylong={START}:{START}:{self.release}:{self.maturity}",
            f"-testcoinbasematuritylongexpiry={EXPIRY}",
            f"-mocktime={T0}",
            "-checkmempool=1",
        ]
        self.extra_args = [self.args]

    def mine(self, count):
        node = self.nodes[0]
        blocks = []
        while count:
            chunk = min(count, 256)
            now = node.getblockheader(node.getbestblockhash())["time"] + chunk + 1
            node.setmocktime(now)
            blocks.extend(self.generatetodescriptor(node, chunk, self.wallet.get_descriptor(), sync_fun=self.no_op))
            count -= chunk
        return blocks

    def mine_to(self, height):
        self.mine(height - self.nodes[0].getblockcount())

    def block(self, txs=(), *, timestamp=None, fees=0, script=None):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        self.block_counter = getattr(self, "block_counter", 0) + 1
        coinbase = create_coinbase(height, fees=fees, script_pubkey=script)
        coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + bytes(CScript([self.block_counter])))
        block = create_block(
            int(tip, 16),
            coinbase,
            timestamp or node.getblockheader(tip)["time"] + 1,
            height=height,
            txlist=list(txs),
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def submit(self, block, expected=None):
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), expected)

    def spend(self, height, **kwargs):
        node = self.nodes[0]
        self.wallet.rescan_utxos()
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        return self.wallet.create_self_transfer(utxo_to_spend=next(utxo for utxo in self.wallet.get_utxos(include_immature_coinbase=True) if utxo["txid"] == txid), **kwargs)

    def check_spend(self, tx, *, allowed, policy_allowed=None):
        node = self.nodes[0]
        if policy_allowed is None:
            policy_allowed = allowed
        result = node.testmempoolaccept([tx["hex"]], 0)[0]
        assert result["allowed"] == policy_allowed, result
        if not policy_allowed:
            assert_equal(result["reject-reason"], REJECT)
            assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, tx["hex"])
        proposal = self.block([tx["tx"]])
        assert_equal(node.getblocktemplate({"mode": "proposal", "data": proposal.serialize().hex(), "rules": ["segwit"]}), None if allowed else REJECT)
        if not allowed:
            self.submit(proposal, REJECT)

    def deployment(self, *, active, maturity):
        node = self.nodes[0]
        deployment = node.getdeploymentinfo()["deployments"][DEPLOYMENT]
        assert_equal(deployment["height"], START)
        assert_equal(deployment["coinbase_start_height"], START)
        assert_equal(deployment["expiry_time"], EXPIRY)
        assert_equal(deployment["maturity"], maturity)
        assert_equal(deployment["active"], active)
        assert "height_end" not in deployment
        assert_equal(DEPLOYMENT in node.getblocktemplate({"rules": ["segwit"]})["rules"], active)

    def wallet_balance(self, *, trusted, immature):
        if self.is_wallet_compiled():
            balance = self.nodes[0].getbalances()["mine"]
            assert_equal(balance["trusted"], trusted)
            assert_equal(balance["immature"], immature)

    def check_options(self):
        node = self.nodes[0]
        self.stop_node(0)
        for args, message in [
            (["-testcoinbasematuritylongexpiry=bad"], "Invalid expiry"),
            (["-testcoinbasematuritylongexpiry=1296688602"], "Invalid expiry"),
            (["-testcoinbasematuritylong=2:2:6482", "-testcoinbasematuritylongexpiry=1800000000", "-testactivationheight=blake2b@200000", "-rdtsexpiry=1800000001"], "must match"),
            (["-testcoinbasematuritylong=2:2:6482:bad"], "Invalid maturity"),
            (["-testcoinbasematuritylong=2:2:6482:99"], "Invalid maturity"),
            (["-testcoinbasematuritylong=2:2:6482:2147483647"], "Invalid maturity"),
            (["-testcoinbasematuritylong=2:2:6482:6480:extra"], "Invalid format"),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=message, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=self.args.copy())

    def run_test(self):
        self.check_options()
        if self.is_wallet_compiled():
            for rpc in ("listtransactions", "listsinceblock", "gettransaction"):
                help_text = self.nodes[0].help(rpc)
                assert "applicable coinbase maturity" in help_text
                assert "100 confirmations" not in help_text
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.mine(2)
        self.deployment(active=True, maturity=self.maturity)
        if self.is_wallet_compiled():
            self.generatetoaddress(node, 1, node.getnewaddress())
        else:
            self.mine(1)
        self.mine_to(99)
        self.log.info("Pre-start consensus maturity is 100; unchanged policy requires the long depth")
        pre_start = self.spend(1)
        self.check_spend(pre_start, allowed=False)
        self.mine(1)
        self.check_spend(pre_start, allowed=True, policy_allowed=False)

        self.mine_to(START + self.maturity - 2)
        self.log.info("Depth maturity-1 fails; maturity succeeds, including before the synthetic old boundary")
        first = self.spend(START, fee=Decimal("1"))
        self.check_spend(first, allowed=False)
        self.mine(1)
        self.check_spend(first, allowed=True)
        assert_equal(node.sendrawtransaction(first["hex"], 0), first["txid"])
        child = self.wallet.create_self_transfer(utxo_to_spend=first["new_utxo"])
        node.sendrawtransaction(child["hex"])
        maturity_parent = node.getbestblockhash()
        boundary_block = self.block([first["tx"]], fees=COIN, script=self.wallet.get_output_script())
        self.submit(boundary_block)
        self.wallet_balance(trusted=0, immature=50)
        self.mine(1)
        self.wallet_balance(trusted=50, immature=0)

        self.log.info("Reorg across maturity evicts the spend and reverses wallet balances")
        node.invalidateblock(maturity_parent)
        assert_equal(node.getblockcount(), START + self.maturity - 2)
        assert_equal(node.getrawmempool(), [])
        self.wallet_balance(trusted=0, immature=50)
        self.check_spend(first, allowed=False)
        node.reconsiderblock(maturity_parent)
        assert_equal(node.getblockcount(), START + self.maturity + 1)
        self.wallet_balance(trusted=50, immature=0)

        if node.getblockcount() < self.release:
            self.mine_to(self.release - 1)
            funding = self.spend(12, fee=Decimal("1"))
            self.submit(self.block([funding["tx"]], fees=COIN, script=self.wallet.get_output_script()))
            self.mine(1)
        self.deployment(active=True, maturity=self.maturity)
        self.log.info("The old release has no 100-block window; rolling depth still controls")
        after_height = self.release - self.maturity + 3
        after = self.spend(after_height)
        self.check_spend(after, allowed=False)
        self.mine(1)
        self.check_spend(after, allowed=True)
        node.sendrawtransaction(after["hex"])
        after_block = self.block([after["tx"]])
        self.submit(after_block)

        self.log.info("Reorg across the old release keeps the rolling rule in force")
        old_boundary = node.getblockhash(self.release)
        node.invalidateblock(old_boundary)
        assert_equal(node.getblockcount(), self.release - 1)
        # With mainnet's relative schedule the first spend was mined at the
        # old release and is still mature for the next block after the reorg.
        expected_pool = {first["txid"], child["txid"]} if self.release == START + self.maturity else {funding["txid"]}
        assert_equal(set(node.getrawmempool()), expected_pool)
        self.deployment(active=True, maturity=self.maturity)
        self.check_spend(after, allowed=False)
        node.reconsiderblock(old_boundary)
        assert_equal(node.getbestblockhash(), after_block.hash)

        self.log.info("Coinbases mined at the old release retain the long depth")
        self.check_depth_pair(self.release)

        self.check_expiry()

        self.log.info("Reindex preserves expiry and the selected chain")
        tip = node.getbestblockhash()
        now = node.getblockheader(tip)["time"] + 1000
        self.stop_node(0)
        node.start(self.args + ["-reindex", f"-mocktime={now}"])
        node.wait_for_rpc_connection(wait_for_import=False)
        self.wait_until(lambda: node.getmempoolinfo()["loaded"], timeout=600)
        assert_equal(node.getbestblockhash(), tip)
        self.deployment(active=False, maturity=self.maturity)

    def check_expiry(self):
        node = self.nodes[0]
        self.log.info("Parent MTP just below expiry still enforces long depth, even when candidate MTP reaches expiry")
        # Fund a young reward explicitly: full-depth regtest has exhausted its subsidy.
        funding = self.spend(16, fee=Decimal("1"))
        self.submit(self.block([funding["tx"]], fees=COIN, script=self.wallet.get_output_script()))
        self.mine(89)
        height = node.getblockcount()
        edge = self.spend(height - 89)
        node.setmocktime(EXPIRY + 10000)
        wallet_reward = None
        wallet_value = 0
        for offset in range(10):
            kwargs = {"script": self.wallet.get_output_script()}
            txs = []
            if offset in (0, 1):
                funding = self.spend(13 + offset, fee=Decimal("1"))
                txs = [funding["tx"]]
                kwargs["fees"] = COIN
            if offset == 0 and self.is_wallet_compiled():
                kwargs["script"] = CScript(bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"]))
            block = self.block(txs, timestamp=EXPIRY - 5 + offset, **kwargs)
            self.submit(block)
            if offset == 0:
                wallet_reward = block.vtx[0].hash
                wallet_value = Decimal(block.vtx[0].vout[0].nValue) / COIN
        fresh_height = height + 2  # Reward mined four seconds before expiry.
        assert_equal(node.getblockheader(node.getbestblockhash())["mediantime"], EXPIRY - 1)
        assert_equal(node.getblockcount() + 1 - (height - 89), 100)
        self.deployment(active=True, maturity=self.maturity)
        self.check_spend(edge, allowed=False)
        crossing = self.block(timestamp=EXPIRY + 5)
        self.submit(crossing)
        assert_equal(node.getblockheader(crossing.hash)["mediantime"], EXPIRY)
        self.deployment(active=False, maturity=self.maturity)
        self.check_spend(edge, allowed=True, policy_allowed=False)
        self.submit(self.block([edge["tx"]]))

        self.log.info("Pre-expiry reward spends after expiry at depth 100, with stricter relay and wallet maturity")
        self.mine_to(fresh_height + 98)
        fresh = self.spend(fresh_height)
        self.check_spend(fresh, allowed=False)
        self.mine(1)
        self.check_spend(fresh, allowed=True, policy_allowed=False)
        self.submit(self.block([fresh["tx"]]))
        if self.is_wallet_compiled():
            assert_equal(node.gettransaction(wallet_reward)["details"][0]["category"], "immature")
            assert all(utxo["txid"] != wallet_reward for utxo in node.listunspent())
            self.wallet_balance(trusted=50, immature=wallet_value)
        tip = node.getbestblockhash()
        self.log.info("Reorg backwards across expiry restores long consensus depth; forwards releases again")
        node.invalidateblock(crossing.hash)
        assert_equal(node.getblockheader(node.getbestblockhash())["mediantime"], EXPIRY - 1)
        assert_equal(node.getrawmempool(), [])
        self.deployment(active=True, maturity=self.maturity)
        self.check_spend(edge, allowed=False)
        node.reconsiderblock(crossing.hash)
        assert_equal(node.getbestblockhash(), tip)
        self.deployment(active=False, maturity=self.maturity)
        assert_equal(node.getrawmempool(), [])
        self.log.info("Post-expiry rewards also spend at depth 100, while relay still uses long depth")
        funding = self.spend(15, fee=Decimal("1"))
        self.submit(self.block([funding["tx"]], fees=COIN, script=self.wallet.get_output_script()))
        late_height = node.getblockcount()
        self.mine_to(late_height + 98)
        late = self.spend(late_height)
        self.check_spend(late, allowed=False)
        self.mine(1)
        self.check_spend(late, allowed=True, policy_allowed=False)
        self.submit(self.block([late["tx"]]))

    def check_depth_pair(self, coin_height):
        node = self.nodes[0]
        self.mine_to(coin_height + 98)
        tx = self.spend(coin_height)
        self.check_spend(tx, allowed=False)
        self.mine(1)
        self.check_spend(tx, allowed=False)
        self.mine_to(coin_height + self.maturity - 2)
        assert_equal(node.getblockcount() + 1 - coin_height, self.maturity - 1)
        self.check_spend(tx, allowed=False)
        self.mine(1)
        assert_equal(node.getblockcount() + 1 - coin_height, self.maturity)
        self.check_spend(tx, allowed=True)
        node.sendrawtransaction(tx["hex"])
        self.submit(self.block([tx["tx"]]))


if __name__ == "__main__":
    RollingCoinbaseMaturityTest(__file__).main()
