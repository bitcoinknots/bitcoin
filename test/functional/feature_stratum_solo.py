#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""Basic embedded Stratum solo startup smoke test."""

from test_framework.test_framework import BitcoinTestFramework


class StratumSoloTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        addr = self.nodes[0].getnewaddress()
        self.restart_node(0, extra_args=[
            '-regtest=1',
            '-server=1',
            '-stratum=1',
            '-stratumbind=127.0.0.1',
            '-stratumport=3333',
            f'-stratumpayoutaddress={addr}',
        ])
        info = self.nodes[0].getstratuminfo()
        assert info['enabled']


if __name__ == '__main__':
    StratumSoloTest(__file__).main()
