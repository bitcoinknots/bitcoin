#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""Exercise real retargets in the isolated, low-target DCBM regtest fixture."""

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS, add_witness_commitment, create_block, create_coinbase
from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

EXPIRY = 1819756800
INITIAL_MATURITY = 100
INTERVAL = 144


class DynamicCBMRetargetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-testcoinbasematuritylong=2:2:122",
            f"-testcoinbasematuritylongexpiry={EXPIRY}",
            "-testdynamiccbm=1",
            f"-testdynamiccbminitial={INITIAL_MATURITY}",
            "-testdynamiccbmretarget=1",
            "-checkmempool=1",
            f"-mocktime={EXPIRY + 3600}",
        ]]

    def next_block(self, *, slow=False, txs=None, time_step=None):
        node = self.nodes[0]
        parent = node.getblockheader(node.getbestblockhash())
        timestamp = max(EXPIRY + 1, parent["time"] + 4 if slow else parent["mediantime"] + 1)
        if time_step is not None:
            timestamp = parent["time"] + time_step
        node.setmocktime(timestamp + 1)
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        # Keep candidates distinct when revisiting a height after a reorg.
        self.block_counter = getattr(self, "block_counter", 0) + 1
        coinbase = create_coinbase(template["height"], script_pubkey=self.wallet.get_output_script())
        coinbase.vin[0].nSequence = self.block_counter
        coinbase.rehash()
        block = create_block(
            coinbase=coinbase,
            ntime=timestamp, tmpl=template, txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_to(self, height, *, slow=False):
        while self.nodes[0].getblockcount() < height:
            block = self.next_block(slow=slow)
            assert_equal(self.nodes[0].submitblock(block.serialize().hex()), None)

    def target(self, height):
        node = self.nodes[0]
        return uint256_from_compact(int(node.getblockheader(node.getblockhash(height))["bits"], 16))

    def spend(self, height):
        node = self.nodes[0]
        txid = node.getblock(node.getblockhash(height))["tx"][0]
        self.wallet.rescan_utxos()
        return self.wallet.create_self_transfer(utxo_to_spend=self.wallet.get_utxo(txid=txid))

    def rejected(self, spend):
        node = self.nodes[0]
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-coinbase", node.sendrawtransaction, spend["hex"])
        block = self.next_block(slow=True, txs=[spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), "bad-txns-premature-spend-of-coinbase")

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.mine_to(INTERVAL)
        assert_equal(self.target(143), self.target(144))  # initial timespan hits powLimit
        self.mine_to(288)
        increased = max(100, INITIAL_MATURITY * self.target(287) // self.target(288))
        assert increased > INITIAL_MATURITY
        self.log.info(f"Higher difficulty assigns maturity {increased}")
        self.mine_to(432, slow=True)
        decreased = max(100, increased * self.target(431) // self.target(432))
        assert 100 <= decreased < increased
        self.log.info("Earlier rewards retain their maturity after difficulty falls")
        old = self.spend(288)
        self.rejected(old)
        lower = self.spend(432)
        self.mine_to(432 + decreased - 2, slow=True)
        self.rejected(lower)
        self.mine_to(432 + decreased - 1, slow=True)
        node.sendrawtransaction(lower["hex"])
        block = self.next_block(slow=True, txs=[lower["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)

        self.mine_to(576, slow=True)
        minimum = max(100, decreased * self.target(575) // self.target(576))
        assert_equal(minimum, 100)

        self.log.info("Floor reward rejects depth 99 and accepts depth 100")
        floor = self.spend(576)
        self.mine_to(674, slow=True)
        self.rejected(floor)
        self.mine_to(675, slow=True)
        node.sendrawtransaction(floor["hex"])
        block = self.next_block(slow=True, txs=[floor["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        accepted = node.getbestblockhash()

        self.log.info("Disconnecting to depth 99 evicts the now-immature spend")
        rollback = node.getblockhash(675)
        node.invalidateblock(rollback)
        assert_equal(node.getblockcount(), 674)
        assert floor["txid"] not in node.getrawmempool()
        self.rejected(floor)
        node.reconsiderblock(rollback)
        assert_equal(node.getbestblockhash(), accepted)

        self.mine_to(288 + increased - 2, slow=True)
        self.rejected(old)
        self.mine_to(288 + increased - 1, slow=True)
        node.sendrawtransaction(old["hex"])
        block = self.next_block(slow=True, txs=[old["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)

        self.log.info("A competing branch assigns its own maturity across a retarget")
        original_tip = node.getbestblockhash()
        fork_block = node.getblockhash(287)
        node.invalidateblock(fork_block)
        assert_equal(node.getblockcount(), 286)
        block = self.next_block(time_step=1000)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.mine_to(288, slow=True)
        assert_equal(self.target(288), self.target(144))
        alternate = self.spend(288)
        assert alternate["txid"] != old["txid"]
        self.mine_to(288 + INITIAL_MATURITY - 2, slow=True)
        self.rejected(alternate)
        self.mine_to(288 + INITIAL_MATURITY - 1, slow=True)
        node.sendrawtransaction(alternate["hex"])
        block = self.next_block(slow=True, txs=[alternate["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        node.reconsiderblock(fork_block)
        assert_equal(node.getbestblockhash(), original_tip)
        assert alternate["txid"] not in node.getrawmempool()


if __name__ == "__main__":
    DynamicCBMRetargetTest(__file__).main()
