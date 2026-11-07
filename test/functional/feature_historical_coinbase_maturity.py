#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The historical maturity window and the rolling rule together, as on mainnet.

Rewards from START wait HISTORICAL blocks for spends below RELEASE; the
rolling rule covers rewards from RELEASE - 1 with depth ROLLING. Node 1 starts
with only the historical rule, as a node upgrading from 29.4.2 would.
"""
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

START = 110
RELEASE = 230
HISTORICAL = RELEASE - START
ROLL = RELEASE - 1
ROLLING = 150
EXPIRY = 1819756800
PREMATURE = "bad-txns-premature-spend-of-coinbase"
COMMON = ["-checkmempool=1", "-corepolicy=0", f"-mocktime={EXPIRY - 100000}"]
UPGRADED = [f"-testcoinbasematuritylong={ROLL}:{ROLL}:{ROLL + ROLLING}", f"-testcoinbasematuritylongexpiry={EXPIRY}",
            f"-testcoinbasematurityhistorical={START}:{RELEASE}"] + COMMON
LEGACY = [f"-testcoinbasematuritylong={START}:{START}:{RELEASE}"] + COMMON


class HistoricalCoinbaseMaturityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [UPGRADED, LEGACY]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def block(self, node, txs):
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=self.mini.get_output_script()),
                             node.getblockheader(tip)["time"] + 1, height=height, txlist=txs)
        add_witness_commitment(block)
        block.solve()
        return block

    def spend(self, height):
        node = self.nodes[0]
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        self.mini.rescan_utxos()
        return self.mini.create_self_transfer(utxo_to_spend=self.mini.get_utxo(txid=txid, mark_as_spent=False))["tx"]

    def accept(self, node, tx):
        result = node.testmempoolaccept([tx.serialize().hex()])[0]
        return result["allowed"], result.get("reject-reason")

    def category(self, height):
        node = self.nodes[0]
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        return node.get_wallet_rpc("w").gettransaction(txid)["details"][0]["category"]

    def deployment(self, keys):
        info = self.nodes[0].getdeploymentinfo()["deployments"]["long_coinbase_maturity"]
        return {key: info.get(key) for key in keys}

    def test_invalid_args(self):
        node = self.nodes[0]
        self.stop_node(0)
        rolling = UPGRADED[:2]
        for args in [
            [f"-testcoinbasematurityhistorical={START}:{RELEASE}"],
            UPGRADED[:1] + [f"-testcoinbasematurityhistorical={START}:{RELEASE}"],
            rolling + [f"-testcoinbasematurityhistorical={START}:{RELEASE + 1}"],
            rolling + [f"-testcoinbasematurityhistorical={START}"],
            rolling + [f"-testcoinbasematurityhistorical=-1:{RELEASE}"],
            rolling + [f"-testcoinbasematurityhistorical={START}:{START + 100}"],
            rolling + [f"-testcoinbasematurityhistorical={START}:-2147483648"],
            rolling + [f"-testcoinbasematurityhistorical={START}:2147483647"],
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg="Invalid historical coinbase maturity",
                                                match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0)
        self.connect_nodes(0, 1)

    def run_test(self):
        self.test_invalid_args()
        n0, n1 = self.nodes
        self.mini = MiniWallet(n0)
        n0.createwallet("w")
        wallet_addr = n0.get_wallet_rpc("w").getnewaddress()

        self.log.info("Consensus holds only rewards from the window start")
        self.generate(self.mini, START + 109)
        lower = self.spend(START - 1)
        first = self.spend(START)
        assert_equal(self.accept(n0, lower), (False, PREMATURE))
        self.disconnect_nodes(0, 1)
        assert_equal(n0.submitblock(self.block(n0, [first]).serialize().hex()), PREMATURE)
        assert_equal(n0.submitblock(self.block(n0, [lower]).serialize().hex()), None)
        self.connect_nodes(0, 1)
        self.sync_all()

        self.generate(self.mini, ROLL - 2 - n0.getblockcount())
        self.log.info("Before the rolling rule, getdeploymentinfo reports the historical window")
        assert_equal(self.deployment(["height", "height_end", "maturity", "active"]),
                     {"height": START, "height_end": RELEASE - 1, "maturity": HISTORICAL, "active": True})
        self.generatetoaddress(n0, 1, wallet_addr)

        self.log.info("At the first rolling block both rules apply")
        window = self.spend(START)
        before = self.spend(START - 2)
        assert_equal(self.accept(n0, window), (False, PREMATURE))
        assert_equal(self.accept(n0, before), (True, None))
        self.disconnect_nodes(0, 1)
        block = self.block(n0, [window])
        assert_equal(n0.submitblock(block.serialize().hex()), PREMATURE)
        assert_equal(n1.submitblock(block.serialize().hex()), PREMATURE)
        self.connect_nodes(0, 1)
        self.generate(self.mini, 1)
        assert_equal(self.deployment(["height", "maturity", "coinbase_expiry_time", "active"]),
                     {"height": ROLL, "maturity": ROLLING, "coinbase_expiry_time": EXPIRY, "active": True})

        self.log.info("At the release height consensus frees window rewards but relay keeps holding them")
        early = self.spend(START + 1)
        late = self.spend(RELEASE - 100)
        assert_equal(self.accept(n0, early), (False, PREMATURE))
        assert_equal(self.accept(n0, late), (False, PREMATURE))
        assert_equal(self.accept(n1, late), (False, PREMATURE))
        self.disconnect_nodes(0, 1)
        block = self.block(n0, [early, late])
        assert_equal(n0.submitblock(block.serialize().hex()), None)
        assert_equal(n1.submitblock(block.serialize().hex()), None)
        self.connect_nodes(0, 1)
        self.sync_all()
        self.generatetoaddress(n0, 1, wallet_addr)

        self.log.info("A rolling reward at depth 100 splits a node that has not upgraded")
        self.generate(self.mini, ROLL + 99 - n0.getblockcount())
        self.disconnect_nodes(0, 1)
        covered = self.spend(ROLL)
        assert_equal(self.accept(n0, covered), (False, PREMATURE))
        block = self.block(n1, [covered])
        assert_equal(n0.submitblock(block.serialize().hex()), PREMATURE)
        assert_equal(n1.submitblock(block.serialize().hex()), None)
        self.generate(n1, 5, sync_fun=self.no_op)
        invalid_tip = n1.getbestblockhash()

        self.log.info("Upgrading rewinds to the rolling start and rejects the branch")
        with n1.assert_debug_log([f"(height {ROLL - 1})"]):
            self.restart_node(1, extra_args=UPGRADED)
        assert_equal(n1.getblockcount(), ROLL + 99)
        assert_equal({tip["hash"]: tip["status"] for tip in n1.getchaintips()}[invalid_tip], "invalid")
        self.connect_nodes(0, 1)
        self.generate(self.mini, 1)
        with n1.assert_debug_log([], unexpected_msgs=["Chainstate revalidation"]):
            self.restart_node(1, extra_args=UPGRADED)
        self.connect_nodes(0, 1)

        self.log.info("The wallet uses each reward's own maturity")
        self.generate(self.mini, ROLL - 1 + HISTORICAL - 1 - n0.getblockcount())
        assert_equal(self.category(ROLL - 1), "immature")
        self.generate(self.mini, 1)
        assert_equal(self.category(ROLL - 1), "generate")
        assert_equal(self.category(RELEASE + 1), "immature")

        self.log.info("A rolling reward matures at the rolling depth")
        self.generate(self.mini, ROLL + ROLLING - 2 - n0.getblockcount())
        assert_equal(self.accept(n0, covered), (False, PREMATURE))
        assert_equal(n0.submitblock(self.block(n0, [covered]).serialize().hex()), PREMATURE)
        self.generate(self.mini, 1)
        assert_equal(self.accept(n0, covered), (True, None))
        n0.sendrawtransaction(covered.serialize().hex())
        self.generate(self.mini, 1)
        assert covered.rehash() in n0.getblock(n0.getbestblockhash())["tx"]
        self.generate(self.mini, RELEASE + 1 + ROLLING - 1 - n0.getblockcount())
        assert_equal(self.category(RELEASE + 1), "immature")
        self.generate(self.mini, 1)
        assert_equal(self.category(RELEASE + 1), "generate")


if __name__ == "__main__":
    HistoricalCoinbaseMaturityTest(__file__).main()
