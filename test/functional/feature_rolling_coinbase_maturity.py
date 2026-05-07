#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Rolling maturity follows reward creation MTP and survives RDTS expiry."""
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

EXPIRY = 1819756800
MATURITY = 120


class RollingCoinbaseMaturityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-testcoinbasematuritylong=2:2:{2 + MATURITY}",
            f"-testcoinbasematuritylongexpiry={EXPIRY}",
            "-checkmempool=1",
            f"-mocktime={EXPIRY + 1000}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def block(self, txs=None, timestamp=None, script=None):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(
            height, script_pubkey=script or self.mini.get_output_script()),
            max(timestamp or EXPIRY - 1000, node.getblockheader(tip)["time"] + 1),
            height=height, txlist=txs)
        add_witness_commitment(block)
        block.solve()
        return block

    def submit(self, block, expected=None):
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), expected)

    def spend(self, height):
        node = self.nodes[0]
        self.mini.rescan_utxos()
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        return self.mini.create_self_transfer(utxo_to_spend=self.mini.get_utxo(txid=txid))

    def run_test(self):
        node = self.nodes[0]
        self.stop_node(0)
        schedule = [f"-testcoinbasematuritylong=2:2:{2 + MATURITY}"]
        for args, message in [
            ([f"-testcoinbasematuritylongexpiry={EXPIRY}"], "Invalid long coinbase maturity expiry"),
            (schedule + ["-testcoinbasematuritylongexpiry=1296688602"], "Invalid long coinbase maturity expiry"),
            (schedule + ["-testcoinbasematuritylongexpiry=invalid"], "Invalid long coinbase maturity expiry"),
            (schedule + ["-testcoinbasematuritylongexpiry=99999999999999999999"], "Invalid long coinbase maturity expiry"),
            (schedule + [f"-testcoinbasematuritylongexpiry={EXPIRY}", "-testactivationheight=blake2b@2", f"-rdtsexpiry={EXPIRY + 1}"], "must match RDTS expiry"),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=message, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=self.extra_args[0].copy())
        node.setmocktime(EXPIRY + 1000)
        self.mini = MiniWallet(node)
        node.createwallet("maturity")
        wallet = node.get_wallet_rpc("maturity")
        wallet_script = CScript(bytes.fromhex(wallet.getaddressinfo(wallet.getnewaddress())["scriptPubKey"]))
        for _ in range(120):
            self.submit(self.block())

        self.log.info("Each covered reward matures independently before expiry")
        spend = self.spend(2)
        self.submit(self.block([spend["tx"]]), "bad-txns-premature-spend-of-coinbase")
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-coinbase", node.sendrawtransaction, spend["hex"])
        self.submit(self.block())
        node.sendrawtransaction(spend["hex"])
        self.log.info("A one-block rollback evicts a newly mature mempool spend and its child")
        child = self.mini.create_self_transfer(utxo_to_spend=spend["new_utxo"])
        node.sendrawtransaction(child["hex"])
        assert_equal(set(node.getrawmempool()), {spend["txid"], child["txid"]})
        maturity_tip = node.getbestblockhash()
        # Keep both transactions unmined: this exercises removal of existing
        # mempool entries, rather than admission of disconnected transactions.
        node.invalidateblock(maturity_tip)
        assert_equal(node.getblockcount(), 120)
        assert_equal(node.getrawmempool(), [])
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-coinbase", node.sendrawtransaction, spend["hex"])
        node.reconsiderblock(maturity_tip)
        node.sendrawtransaction(spend["hex"])
        node.sendrawtransaction(child["hex"])
        self.submit(self.block([spend["tx"], child["tx"]]))
        # This reward is not released at the former height-based release.
        spend = self.spend(4)
        self.submit(self.block([spend["tx"]]), "bad-txns-premature-spend-of-coinbase")
        while node.getblockcount() < 130:
            self.submit(self.block())
        pre_wallet = self.block(script=wallet_script)
        self.submit(pre_wallet)
        fork = node.getbestblockhash()

        self.log.info("Candidate MTP crossing expiry does not release its own reward")
        for _ in range(6):
            self.submit(self.block(timestamp=EXPIRY))
        last_pre = node.getblockcount()
        assert_equal(node.getblockheader(node.getbestblockhash())["mediantime"], EXPIRY)
        assert node.getblockheader(node.getblockhash(last_pre - 1))["mediantime"] < EXPIRY
        self.submit(self.block(timestamp=EXPIRY))
        first_post = node.getblockcount()
        post_wallet = self.block(script=wallet_script, timestamp=EXPIRY + 1)
        self.submit(post_wallet)
        while node.getblockcount() < first_post + 98:
            self.submit(self.block(timestamp=EXPIRY + 100))

        covered_spend = self.spend(last_pre)
        new_spend = self.spend(first_post)
        self.submit(self.block([new_spend["tx"]]), "bad-txns-premature-spend-of-coinbase")
        self.submit(self.block(timestamp=EXPIRY + 100))
        self.submit(self.block([covered_spend["tx"]]), "bad-txns-premature-spend-of-coinbase")
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-coinbase", node.sendrawtransaction, covered_spend["hex"])
        node.sendrawtransaction(new_spend["hex"])
        assert_equal(wallet.gettransaction(post_wallet.vtx[0].rehash())["details"][0]["category"], "immature")
        self.submit(self.block([new_spend["tx"]], timestamp=EXPIRY + 100))
        self.submit(self.block(timestamp=EXPIRY + 100))
        self.submit(self.block(timestamp=EXPIRY + 100))
        assert_equal(wallet.gettransaction(post_wallet.vtx[0].rehash())["details"][0]["category"], "generate")
        assert_equal(wallet.gettransaction(pre_wallet.vtx[0].rehash())["details"][0]["category"], "immature")

        self.log.info("Reorg below expiry restores long maturity, then reorg forward")
        old_tip = node.getbestblockhash()
        first_high = node.getblockhash(last_pre - 5)
        node.invalidateblock(first_high)
        assert_equal(node.getbestblockhash(), fork)
        assert_equal(node.getrawmempool(), [])
        # Rebuild a branch of the same height whose MTP remains before expiry.
        while node.getblockcount() < first_post + 99:
            self.submit(self.block(timestamp=EXPIRY - 500))
        before_expiry_tip = node.getbestblockhash()
        assert node.getblockheader(before_expiry_tip)["mediantime"] < EXPIRY
        still_covered = self.spend(first_post)
        self.submit(self.block([still_covered["tx"]]), "bad-txns-premature-spend-of-coinbase")
        node.reconsiderblock(first_high)
        assert_equal(node.getbestblockhash(), old_tip)

        self.log.info("Pre-expiry reward reaches its full depth after expiry")
        while node.getblockcount() < last_pre + MATURITY - 2:
            self.submit(self.block(timestamp=EXPIRY + 100))
        self.submit(self.block([covered_spend["tx"]]), "bad-txns-premature-spend-of-coinbase")
        self.submit(self.block(timestamp=EXPIRY + 100))
        node.sendrawtransaction(covered_spend["hex"])
        self.submit(self.block([covered_spend["tx"]], timestamp=EXPIRY + 100))
        assert_equal(wallet.gettransaction(pre_wallet.vtx[0].rehash())["details"][0]["category"], "generate")
        deployment = node.getdeploymentinfo()["deployments"]["long_coinbase_maturity"]
        assert_equal(deployment["coinbase_expiry_time"], EXPIRY)
        assert_equal(deployment["maturity"], MATURITY)
        assert_equal(deployment["active"], True)
        assert "height_end" not in deployment
        assert "long_coinbase_maturity" in node.getblocktemplate({"rules": ["segwit"]})["rules"]
        tip = node.getbestblockhash()
        for extra in ([], ["-reindex-chainstate"], []):
            self.restart_node(0, extra_args=self.extra_args[0] + extra)
            assert_equal(node.getbestblockhash(), tip)


if __name__ == "__main__":
    RollingCoinbaseMaturityTest(__file__).main()
