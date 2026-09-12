#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the temporary extended generation maturity.

A generation output created at a height inside the scheduled window must be the
extended depth rather than COINBASE_MATURITY. Coverage is fixed when the output
is created, so outputs mined before the window keep the ordinary rule and
outputs mined inside it serve the full period even past the end height.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

SHORT = 100
LONG = 150
START = 200
END = 260

PREMATURE = 'bad-txns-premature-spend-of-coinbase'


class CoinbaseMaturityLongTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f'-coinbasematuritylong={START}:{END}:{LONG}', '-checkmempool=1']]

    def coinbase_utxo(self, height):
        for utxo in self.wallet.get_utxos(include_immature_coinbase=True, mark_as_spent=False):
            if utxo['coinbase'] and utxo['height'] == height:
                return utxo
        raise AssertionError(f'no unspent generation output at height {height}')

    def spend(self, height, *, expect_depth):
        depth = self.nodes[0].getblockcount() + 1 - height
        assert_equal(depth, expect_depth)
        return self.wallet.create_self_transfer(utxo_to_spend=self.coinbase_utxo(height))

    def block_with(self, tx):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height),
                             ntime=node.getblockheader(tip)['time'] + 1,
                             txlist=[tx], height=height)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_to(self, height):
        if height > self.nodes[0].getblockcount():
            self.generate(self.wallet, height - self.nodes[0].getblockcount())

    def check_rejected_schedules(self):
        """The option must refuse anything that would weaken or silently
        disable the rule."""
        node = self.nodes[0]
        self.stop_node(0)
        for args, msg in [
            # A depth below the ordinary rule would weaken the network rule
            # itself, and CTxMemPool::check asserts against COINBASE_MATURITY.
            ([f'-coinbasematuritylong={START}:{END}:{SHORT - 1}'], 'a depth of at least'),
            ([f'-coinbasematuritylong={START}:{END}:0'], 'a depth of at least'),
            # An empty or inverted window would silently cover nothing.
            ([f'-coinbasematuritylong={START}:{START}:{LONG}'], 'need 0 <= start < end'),
            ([f'-coinbasematuritylong={END}:{START}:{LONG}'], 'need 0 <= start < end'),
            ([f'-coinbasematuritylong=-1:{END}:{LONG}'], 'need 0 <= start < end'),
            # Malformed and out of range.
            ([f'-coinbasematuritylong={START}:{END}'], 'Invalid format'),
            ([f'-coinbasematuritylong={START}:{END}:{LONG}:7'], 'Invalid format'),
            ([f'-coinbasematuritylong=abc:{END}:{LONG}'], 'Invalid format'),
            ([f'-coinbasematuritylong={START}:{END}:'], 'Invalid format'),
            (['-coinbasematuritylong='], 'Invalid format'),
            ([f'-coinbasematuritylong=99999999999999999999:{END}:{LONG}'], 'Invalid format'),
        ]:
            node.assert_start_raises_init_error(extra_args=args, expected_msg=msg, match=ErrorMatch.PARTIAL_REGEX)
        # Exactly the ordinary depth is the weakest schedule allowed.
        self.start_node(0, extra_args=[f'-coinbasematuritylong={START}:{END}:{SHORT}'])
        self.stop_node(0)
        self.start_node(0, extra_args=self.extra_args[0])

    def run_test(self):
        node = self.nodes[0]
        self.log.info("The regtest schedule refuses depths and heights that would break the rule")
        self.check_rejected_schedules()

        self.wallet = MiniWallet(node)

        self.log.info("A pre-window output is spendable at the ordinary depth even with the tip inside the window")
        self.mine_to(START + 50)
        tx = self.spend(START - 50, expect_depth=SHORT + 1)
        node.sendrawtransaction(tx['hex'])
        block = self.block_with(tx['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert START <= node.getblockcount() < END, 'setup: the spend must land inside the window'
        self.wallet.rescan_utxos()

        self.mine_to(300)

        # Heights 199 and 200 straddle the flag day, so at this tip the two
        # outputs are one block apart in age and differ only in which rule
        # covers them.
        self.log.info("An output mined before the flag day keeps the ordinary maturity")
        tx = self.spend(START - 1, expect_depth=102)
        node.sendrawtransaction(tx['hex'])
        assert tx['txid'] in node.getrawmempool()
        block = self.block_with(tx['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.wallet.rescan_utxos()

        self.log.info("...while the very next output is held to the extended one")
        assert_raises_rpc_error(-26, PREMATURE, node.sendrawtransaction, self.spend(START, expect_depth=102)['hex'])
        block = self.block_with(self.spend(START, expect_depth=102)['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), PREMATURE)
        assert_equal(node.getblockcount(), 301)

        self.log.info("One block short of the extended depth is still rejected")
        self.mine_to(START + LONG - 2)
        assert_equal(node.getblockcount(), 348)
        block = self.block_with(self.spend(START, expect_depth=LONG - 1)['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), PREMATURE)
        assert_equal(node.getblockcount(), 348)

        self.log.info("...and accepted at exactly the extended depth")
        self.mine_to(START + LONG - 1)
        tx = self.spend(START, expect_depth=LONG)
        node.sendrawtransaction(tx['hex'])
        block = self.block_with(tx['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.wallet.rescan_utxos()

        self.log.info("A reorg evicts a covered spend the shorter chain no longer matures, and templates drop it")
        assert_equal(node.getblockcount(), START + LONG)
        disconnect = node.getblockhash(START + LONG - 1)
        ordinary_tx = self.wallet.create_self_transfer(utxo_to_spend=self.coinbase_utxo(START - 2))
        node.sendrawtransaction(ordinary_tx['hex'])
        covered_tx = self.spend(START + 1, expect_depth=LONG)
        node.sendrawtransaction(covered_tx['hex'])
        node.invalidateblock(disconnect)
        assert_equal(node.getblockcount(), START + LONG - 2)
        assert covered_tx['txid'] not in node.getrawmempool()
        assert ordinary_tx['txid'] in node.getrawmempool(), 'the ordinary rule still matures it at this depth'
        template = [entry['txid'] for entry in node.getblocktemplate({'rules': ['segwit', 'blake2b']})['transactions']]
        assert covered_tx['txid'] not in template
        assert ordinary_tx['txid'] in template, 'the template must still be built, minus the covered spend'
        node.reconsiderblock(disconnect)
        assert_equal(node.getblockcount(), START + LONG)

        self.log.info("An output mined after the window ends takes the ordinary maturity")
        self.mine_to(END + SHORT - 1)
        self.wallet.rescan_utxos()
        assert_equal(node.getblockcount() + 1 - SHORT, END)
        tx = self.spend(END, expect_depth=SHORT)
        node.sendrawtransaction(tx['hex'])
        block = self.block_with(tx['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.wallet.rescan_utxos()

        self.log.info("...while an output mined inside it still serves the full period past the end")
        covered = END - 1
        depth = node.getblockcount() + 1 - covered
        assert SHORT <= depth < LONG, f'setup: needs a covered output at depth {SHORT}..{LONG}, got {depth}'
        assert_raises_rpc_error(-26, PREMATURE, node.sendrawtransaction, self.spend(covered, expect_depth=depth)['hex'])
        block = self.block_with(self.spend(covered, expect_depth=depth)['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), PREMATURE)

        self.log.info("...and becomes spendable only once it reaches the extended depth")
        self.mine_to(covered + LONG - 1)
        tx = self.spend(covered, expect_depth=LONG)
        node.sendrawtransaction(tx['hex'])
        block = self.block_with(tx['tx'])
        assert_equal(node.submitblock(block.serialize().hex()), None)


if __name__ == '__main__':
    CoinbaseMaturityLongTest(__file__).main()
