#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Forward Reward Share: from an activation height every coinbase
forwards a share of its subsidy to an output any block can claim once
coinbase maturity has passed."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import COINBASE_MATURITY, create_block, create_coinbase
from test_framework.messages import COIN, CTxOut
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORWARD_HEIGHT = 120
FORWARD_BPS = 1000
FORWARD_SCRIPT = CScript([b"FWD1", OP_DROP, OP_TRUE])
MINER_SCRIPT = CScript([OP_TRUE])
SUBSIDY = 50 * COIN  # regtest subsidy below the first halving at height 150
SHARE = SUBSIDY * FORWARD_BPS // 10000


class ForwardShareTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-forwardshareheight={FORWARD_HEIGHT}", f"-forwardsharebps={FORWARD_BPS}"]]

    def forward_outputs(self, node, height):
        coinbase = node.getblock(node.getblockhash(height), 2)["tx"][0]
        outs = [(o["n"], int(o["value"] * COIN)) for o in coinbase["vout"]
                if o["scriptPubKey"]["hex"] == FORWARD_SCRIPT.hex()]
        return coinbase["txid"], outs

    def submit(self, node, vout, expected):
        tip = node.getbestblockhash()
        coinbase = create_coinbase(node.getblockcount() + 1)
        coinbase.vout = vout
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), expected)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("before activation, coinbases forward nothing")
        self.generatetoaddress(node, FORWARD_HEIGHT - 1, ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(self.forward_outputs(node, FORWARD_HEIGHT - 1)[1], [])

        self.log.info("from activation, the built-in miner forwards the share of the subsidy")
        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE)
        txid_a, outs_a = self.forward_outputs(node, FORWARD_HEIGHT)
        assert_equal([value for _, value in outs_a], [SHARE])

        self.log.info("getblocktemplate reports the required output, and coinbasevalue still covers the whole reward")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["forwardshare"], {"script": FORWARD_SCRIPT.hex(), "amount": SHARE})
        assert_equal(tmpl["coinbasevalue"], SUBSIDY)

        self.log.info("a coinbase that forwards nothing is invalid")
        self.submit(node, [CTxOut(SUBSIDY, MINER_SCRIPT)], "bad-cb-forward-share")
        self.log.info("forwarding one satoshi too little is invalid")
        self.submit(node, [CTxOut(SUBSIDY - SHARE + 1, MINER_SCRIPT), CTxOut(SHARE - 1, FORWARD_SCRIPT)], "bad-cb-forward-share")
        self.log.info("forwarding exactly the share is valid, whoever built the block")
        self.submit(node, [CTxOut(SUBSIDY - SHARE, MINER_SCRIPT), CTxOut(SHARE, FORWARD_SCRIPT)], None)
        txid_b, outs_b = self.forward_outputs(node, FORWARD_HEIGHT + 1)
        assert_equal([value for _, value in outs_b], [SHARE])

        self.log.info("the share stays unspent until coinbase maturity has passed")
        claim_height = FORWARD_HEIGHT + COINBASE_MATURITY
        self.generatetoaddress(node, claim_height - 1 - node.getblockcount(), ADDRESS_BCRT1_UNSPENDABLE)
        assert node.gettxout(txid_a, outs_a[0][0]) is not None

        self.log.info("the next template claims the matured share as a fee")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal([t["fee"] for t in tmpl["transactions"]], [SHARE])

        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(node.getblockcount(), claim_height)
        assert_equal(node.gettxout(txid_a, outs_a[0][0]), None)
        claim_block = node.getblock(node.getblockhash(claim_height), 2)
        assert_equal(claim_block["tx"][1]["vin"][0]["txid"], txid_a)
        stats = node.getblockstats(claim_height, ["subsidy", "totalfee"])
        assert_equal(stats["totalfee"], SHARE)
        assert_equal(sum(int(o["value"] * COIN) for o in claim_block["tx"][0]["vout"]), stats["subsidy"] + SHARE)

        self.log.info("the share forwarded by a hand-built block is claimed the same way")
        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(node.gettxout(txid_b, outs_b[0][0]), None)


if __name__ == '__main__':
    ForwardShareTest(__file__).main()
