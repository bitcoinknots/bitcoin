#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test startup chainstate revalidation for newly enforced rules."""

import shutil

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

LONG_START_HEIGHT = 2
LONG_ENFORCE_HEIGHT = LONG_START_HEIGHT + COINBASE_MATURITY + 2
LONG_RELEASE_TIME = 4102444800  # 2100-01-01, never reached
LONG_ARGS = [
    f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:{LONG_RELEASE_TIME}",
    "-checkmempool=1",
]


class ChainstateRevalidationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-checkmempool=1"]]

    def create_block_on(self, parent_hash, height, txs=None, block_time=None):
        node = self.nodes[0]
        if block_time is None:
            block_time = node.getblockheader(parent_hash)["time"] + 1
        block = create_block(
            int(parent_hash, 16),
            create_coinbase(height),
            block_time,
            height=height,
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def create_next_block(self, txs=None):
        return self.create_block_on(
            parent_hash=self.nodes[0].getbestblockhash(),
            height=self.nodes[0].getblockcount() + 1,
            txs=txs,
        )

    def get_chaintip_status(self, block_hash):
        for tip in self.nodes[0].getchaintips():
            if tip["hash"] == block_hash:
                return tip["status"]
        raise AssertionError(f"missing chaintip {block_hash}")

    def submit(self, block):
        node = self.nodes[0]
        result = node.submitblock(block.serialize().hex())
        assert_equal(result, None)
        return block

    def reset_chain(self):
        """Drop the chain built by an earlier case and start from genesis."""
        node = self.nodes[0]
        assert not node.running
        shutil.rmtree(node.blocks_path, ignore_errors=True)
        shutil.rmtree(node.chain_path / "chainstate", ignore_errors=True)
        mempool = node.chain_path / "mempool.dat"
        if mempool.exists():
            mempool.unlink()
        self.start_node(0)

    def check_rewind_is_bounded(self):
        """A chain already past the release, with no marker, must not rewind from its tip back to the enforce height."""
        node = self.nodes[0]
        release = node.getblockheader(node.getbestblockhash())["time"] + 10_000
        while node.getblockcount() < LONG_ENFORCE_HEIGHT:
            self.submit(self.create_next_block())

        # Six blocks at the release time are enough for the median of 11 to cross it.
        stamp = release + 1
        for _ in range(20):
            if node.getblockheader(node.getbestblockhash())["mediantime"] >= release:
                break
            self.submit(self.create_next_block_at(stamp))
            stamp += 1
        else:
            raise AssertionError("median time past did not reach the release")

        def last_active():
            height = node.getblockcount()
            while height >= LONG_ENFORCE_HEIGHT:
                parent = node.getblockheader(node.getblockhash(height - 1))
                if parent["mediantime"] < release:
                    return height
                height -= 1
            return None

        active = last_active()
        assert active is not None and active >= LONG_ENFORCE_HEIGHT
        window = active - LONG_ENFORCE_HEIGHT + 1
        # One window of blocks after the release is still rewound. One more is not.
        while node.getblockcount() <= active + window + 1:
            self.submit(self.create_next_block_at(stamp))
            stamp += 1

        self.stop_node(0)
        args = [
            f"-testcoinbasematuritylong={LONG_START_HEIGHT}:{LONG_ENFORCE_HEIGHT}:{release}",
            "-checkmempool=1",
        ]
        node.assert_start_raises_init_error(
            extra_args=args,
            expected_msg="grown too far past the release to rewind",
            match=ErrorMatch.PARTIAL_REGEX,
        )

    def create_next_block_at(self, block_time):
        return self.create_block_on(
            parent_hash=self.nodes[0].getbestblockhash(),
            height=self.nodes[0].getblockcount() + 1,
            block_time=block_time,
        )

    def run_test(self):
        self.log.info("A late upgrade past the release does not rewind from the tip")
        self.check_rewind_is_bounded()
        self.reset_chain()

        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Build a chain accepted before long coinbase maturity is enabled")
        self.generate(wallet, LONG_ENFORCE_HEIGHT - 2)
        parent_spend = wallet.send_self_transfer(
            from_node=node,
            utxo_to_spend=wallet.get_utxo(txid=node.getblock(node.getblockhash(1))["tx"][0]),
        )
        pre_enforce_block = self.create_next_block([parent_spend["tx"]])
        assert_equal(node.submitblock(pre_enforce_block.serialize().hex()), None)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT - 1)

        coinbase_txid = node.getblock(node.getblockhash(3))["tx"][0]
        coinbase_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=coinbase_txid))
        mature_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=parent_spend["txid"]))
        node.sendrawtransaction(coinbase_spend["hex"])
        node.sendrawtransaction(mature_spend["hex"])
        block = self.create_next_block([coinbase_spend["tx"], mature_spend["tx"]])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        invalid_branch_tip = self.create_next_block()
        assert_equal(node.submitblock(invalid_branch_tip.serialize().hex()), None)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT + 1)

        self.log.info("Keep a valid side branch available across the restart")
        fork_hash = node.getblockhash(LONG_ENFORCE_HEIGHT - 1)
        side_block = self.create_block_on(fork_hash, LONG_ENFORCE_HEIGHT)
        assert node.submitblock(side_block.serialize().hex()) in (None, "inconclusive")
        side_tip = self.create_block_on(side_block.hash, LONG_ENFORCE_HEIGHT + 1)
        assert node.submitblock(side_tip.serialize().hex()) in (None, "inconclusive")
        assert_equal(node.getbestblockhash(), invalid_branch_tip.hash)

        self.log.info("Restart with long coinbase maturity and revalidate the inherited chainstate")
        self.restart_node(0, extra_args=LONG_ARGS)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT + 1)
        assert_equal(node.getbestblockhash(), side_tip.hash)
        assert_equal(node.getrawmempool(), [mature_spend["txid"]])

        self.log.info("Restart again and use the persisted revalidation marker")
        self.restart_node(0, extra_args=LONG_ARGS)
        assert_equal(node.getblockcount(), LONG_ENFORCE_HEIGHT + 1)
        assert_equal(node.getbestblockhash(), side_tip.hash)

        self.log.info("Demote stale side-branch validation even when the active chain marker is current")
        self.restart_node(0, extra_args=["-checkmempool=1"])
        stale_coinbase_txid = node.getblock(node.getblockhash(4))["tx"][0]
        stale_spend = wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(txid=stale_coinbase_txid))
        node.sendrawtransaction(stale_spend["hex"])
        stale_side_block = self.create_block_on(fork_hash, LONG_ENFORCE_HEIGHT, [stale_spend["tx"]])
        assert node.submitblock(stale_side_block.serialize().hex()) in (None, "inconclusive")
        stale_side_next = self.create_block_on(stale_side_block.hash, LONG_ENFORCE_HEIGHT + 1)
        assert node.submitblock(stale_side_next.serialize().hex()) in (None, "inconclusive")
        stale_side_tip = self.create_block_on(stale_side_next.hash, LONG_ENFORCE_HEIGHT + 2)
        assert_equal(node.submitblock(stale_side_tip.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), stale_side_tip.hash)

        good_next = self.create_block_on(side_tip.hash, LONG_ENFORCE_HEIGHT + 2)
        assert node.submitblock(good_next.serialize().hex()) in (None, "inconclusive")
        good_tip = self.create_block_on(good_next.hash, LONG_ENFORCE_HEIGHT + 3)
        assert_equal(node.submitblock(good_tip.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), good_tip.hash)
        assert_equal(self.get_chaintip_status(stale_side_tip.hash), "valid-fork")

        self.restart_node(0, extra_args=LONG_ARGS)
        assert_equal(node.getbestblockhash(), good_tip.hash)
        assert_equal(self.get_chaintip_status(stale_side_tip.hash), "valid-headers")

        self.log.info("Continue from the revalidated side branch without redownloading historical blocks")
        current_height = node.getblockcount()
        block = self.create_next_block()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), current_height + 1)


if __name__ == "__main__":
    ChainstateRevalidationTest(__file__).main()
