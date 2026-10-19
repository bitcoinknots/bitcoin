#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Refuse a maturity upgrade needing pruned history before disconnecting."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class PrunedCoinbaseMaturityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-prune=1", "-fastprune"]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(MiniWallet(node), 1200)
        tip = node.getbestblockhash()
        node.pruneblockchain(900)
        assert node.getblockchaininfo()["pruneheight"] > 103
        self.stop_node(0)
        # A node without a deployment marker must revalidate from enforcement.
        # Pruning has removed required history, although the tip data survives.
        with node.assert_debug_log(
            ["required block or undo data has been pruned"],
            unexpected_msgs=["Chainstate revalidation: rewinding"],
        ):
            node.assert_start_raises_init_error(
                extra_args=self.extra_args[0] + ["-testcoinbasematuritylong=2:2:103"],
                expected_msg=r"required block data has been pruned[\s\S]*Please restart with -reindex to recover",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        # The failed startup must leave the original active chain untouched.
        self.start_node(0)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getblockcount(), 1200)


if __name__ == "__main__":
    PrunedCoinbaseMaturityTest(__file__).main()
