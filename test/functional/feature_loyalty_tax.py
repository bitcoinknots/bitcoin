#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Loyalty Tax: coinbases must pay a share of the reward to a treasury
script, or forfeit the whole reward if they don't signal loyalty."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, script_BIP34_coinbase_height
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, SEQUENCE_FINAL
from test_framework.script import CScript, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

LOYALTY_HEIGHT = 120
TAX_BPS = 1000  # 10%
TREASURY_SCRIPT = CScript([OP_TRUE, OP_TRUE])  # distinct from the miner's placeholder payout script below
MINER_SCRIPT = CScript([OP_TRUE])
LOYALTY_SIGNAL = CScript([OP_RETURN, b'LOY1'])
FULL_REWARD = 50 * 100_000_000


def make_coinbase(height, vout):
    cb = CTransaction()
    cb.vin.append(CTxIn(COutPoint(0, 0xffffffff), script_BIP34_coinbase_height(height), SEQUENCE_FINAL))
    cb.vout = vout
    cb.calc_sha256()
    return cb


class LoyaltyTaxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-loyaltyheight={LOYALTY_HEIGHT}",
            f"-loyaltytaxbps={TAX_BPS}",
            f"-loyaltytreasury={TREASURY_SCRIPT.hex()}",
        ]]

    def submit(self, node, tip, height, vout, *, expect_reject=None):
        block = create_block(int(tip, 16), make_coinbase(height, vout), node.getblock(tip)["time"] + 1)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        if expect_reject:
            assert_equal(result, expect_reject)
        else:
            assert_equal(result, None)
        return block

    def run_test(self):
        node = self.nodes[0]

        self.log.info("before activation, a plain coinbase is fine")
        self.generatetoaddress(node, LOYALTY_HEIGHT - 1, ADDRESS_BCRT1_UNSPENDABLE)
        cb = node.getblock(node.getblockhash(LOYALTY_HEIGHT - 1), 2)["tx"][0]
        # vout[0] is the payout, vout[1] (if present) is the segwit witness
        # commitment; neither a treasury payment nor a loyalty signal exists yet.
        assert_equal(int(cb["vout"][0]["value"] * 100_000_000), FULL_REWARD)
        assert not any(o["scriptPubKey"]["hex"] == TREASURY_SCRIPT.hex() for o in cb["vout"])

        self.log.info("from activation, the miner's own block already complies")
        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE)
        cb = node.getblock(node.getblockhash(LOYALTY_HEIGHT), 2)["tx"][0]
        treasury_paid = sum(int(o["value"] * 100_000_000) for o in cb["vout"]
                            if o["scriptPubKey"]["hex"] == TREASURY_SCRIPT.hex())
        assert_equal(treasury_paid, FULL_REWARD * TAX_BPS // 10000)
        assert any(o["scriptPubKey"]["hex"] == LOYALTY_SIGNAL.hex() for o in cb["vout"])

        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        required_tax = FULL_REWARD * TAX_BPS // 10000

        self.log.info("a signaled block that underpays the treasury is rejected")
        underpaid = [
            CTxOut(FULL_REWARD - required_tax + 1, MINER_SCRIPT),
            CTxOut(required_tax - 1, TREASURY_SCRIPT),
            CTxOut(0, LOYALTY_SIGNAL),
        ]
        self.submit(node, tip, height, underpaid, expect_reject="bad-loyalty-tax")

        self.log.info("an unsignaled block that keeps any reward at all is rejected")
        unsignaled_keeps_reward = [CTxOut(FULL_REWARD, MINER_SCRIPT)]
        self.submit(node, tip, height, unsignaled_keeps_reward, expect_reject="bad-loyalty-tax")

        self.log.info("an unsignaled block that fully confiscates the reward is accepted")
        fully_confiscated = [CTxOut(FULL_REWARD, TREASURY_SCRIPT)]
        self.submit(node, tip, height, fully_confiscated)
        assert_equal(node.getblockcount(), height)


if __name__ == '__main__':
    LoyaltyTaxTest(__file__).main()
