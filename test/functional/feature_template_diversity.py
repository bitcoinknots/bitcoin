#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test gettemplatediversity: grouping recent blocks by template structure
rather than by the identity their coinbase claims, plus live comparison of
each block's transaction selection against this node's mempool."""

from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase, script_BIP34_coinbase_height
from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal
from test_framework.wallet import MiniWallet


class TemplateDiversityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def custom_block(self, node, *, tag, script_pubkey, version=0x20000004):
        """A block from a different "template maker": two payout outputs, a
        signal bit set, no witness commitment, and a text tag."""
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        coinbase = create_coinbase(height, script_pubkey=script_pubkey, nValue=25)
        coinbase.vout.append(CTxOut(25 * 10**8, script_pubkey))
        coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x01\x02\x03\x04"])))
        coinbase.vin[0].scriptSig = CScript(bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([tag])))
        if hasattr(coinbase, "rehash"):
            coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, node.getblock(tip)["time"] + 1, version=version)
        block.solve()
        assert node.submitblock(block.serialize().hex()) is None
        assert_equal(node.getbestblockhash(), block.hash_hex if hasattr(block, "hash_hex") else block.hash)
        return block

    def structure_with_tag(self, result, tag):
        return [s for s in result["structures"] if any(t["tag"] == tag for t in s["tags"])]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        spk = CScript(bytes.fromhex(node.validateaddress(wallet.get_address())["scriptPubKey"]))

        self.log.info("blocks from one template builder form a single structure")
        self.generate(wallet, 110)
        result = node.gettemplatediversity(50)
        assert_equal(result["blocks"], 50)
        assert_equal(result["distinct_structures"], 1)
        assert_equal(result["effective_template_makers"], 1)
        assert_equal(result["largest_structure_share"], 100)

        self.log.info("a differently-built block template shows up as a second structure")
        for _ in range(10):
            self.custom_block(node, tag=b"/PoolB/", script_pubkey=spk)
        result = node.gettemplatediversity(20)
        assert_equal(result["distinct_structures"], 2)
        assert_equal(result["effective_template_makers"], 2)
        assert_equal(result["largest_structure_share"], 50)
        pool_b = self.structure_with_tag(result, "/PoolB/")
        assert_equal(len(pool_b), 1)
        assert_equal(pool_b[0]["blocks"], 10)

        self.log.info("changing only the coinbase tag does not create a new structure")
        for _ in range(10):
            self.custom_block(node, tag=b"/PoolC/", script_pubkey=spk)
        result = node.gettemplatediversity(20)
        assert_equal(result["distinct_structures"], 1)
        assert_equal(result["claimed_identities"], 2)
        tags = {t["tag"]: t["blocks"] for t in result["structures"][0]["tags"]}
        assert_equal(tags, {"/PoolB/": 10, "/PoolC/": 10})

        self.log.info("changing signalled version bits does create a new structure")
        self.custom_block(node, tag=b"/PoolC/", script_pubkey=spk, version=0x20000008)
        result = node.gettemplatediversity(21)
        assert_equal(result["distinct_structures"], 2)

        self.log.info("a block that leaves out long-waiting, well-paying mempool txs is recorded as skipping them")
        self.generate(wallet, 1)  # confirm the wallet's spendable state before building a mempool
        now = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(now)
        for _ in range(20):
            wallet.send_self_transfer(from_node=node, fee_rate=Decimal("0.0005"))
        assert_equal(node.getmempoolinfo()["size"], 20)
        node.setmocktime(now + 120)
        empty = self.custom_block(node, tag=b"/PoolB/", script_pubkey=spk)
        node.syncwithvalidationinterfacequeue()
        result = node.gettemplatediversity(1, True)
        detail = result["blocks_detail"][0]
        assert_equal(detail["height"], node.getblockcount())
        assert_equal(detail["txs"], 1)
        assert_equal(detail["eligible_txs"], 20)
        assert_equal(detail["skipped_txs"], 20)
        assert_equal(result["live_samples"], 1)

        self.log.info("txs that arrived too recently to be in any template are not counted against a block")
        node.setmocktime(now + 130)
        for _ in range(5):
            wallet.send_self_transfer(from_node=node, fee_rate=Decimal("0.0005"))
        node.setmocktime(now + 140)
        self.custom_block(node, tag=b"/PoolB/", script_pubkey=spk)
        node.syncwithvalidationinterfacequeue()
        detail = node.gettemplatediversity(1, True)["blocks_detail"][0]
        assert_equal(detail["eligible_txs"], 20)
        assert_equal(detail["skipped_txs"], 20)

        self.log.info("a block that includes the whole mempool skips nothing")
        node.setmocktime(now + 300)
        self.generate(node, 1)
        node.syncwithvalidationinterfacequeue()
        detail = node.gettemplatediversity(1, True)["blocks_detail"][0]
        assert_greater_than_or_equal(detail["txs"], 26)
        assert_equal(detail["skipped_txs"], 0)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.log.info("repeated heavy skipping within one structure is summarised per structure")
        result = node.gettemplatediversity(3)
        for s in result["structures"]:
            assert "median_skipped_txs" in s

        self.log.info("nblocks is capped at the chain height")
        result = node.gettemplatediversity(100000)
        assert_equal(result["blocks"], node.getblockcount() + 1)


if __name__ == '__main__':
    TemplateDiversityTest(__file__).main()
