#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that wallet names cannot forge creation or startup log lines."""
import platform
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletLogInjectionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Test that a wallet name cannot forge log lines through startup warnings")
        forged_log_line = "ERROR: ConnectTip: ConnectBlock 0000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef failed, bad-txns-inputs-missingorspent"
        wallet_name = f"w5\n{forged_log_line}"
        if platform.system() == 'Windows':
            # Windows disallows newlines in filenames
            assert_raises_rpc_error(None, None, node.createwallet, wallet_name, load_on_startup=True)
            return

        with node.assert_debug_log([f"[{wallet_name}]".replace("\n", "\\x0a")]):
            assert_equal(node.createwallet(wallet_name=wallet_name, load_on_startup=True)["name"], wallet_name)
        self.stop_node(0)

        wallet_path = node.wallets_path / wallet_name
        shutil.rmtree(wallet_path)
        warning = f"Skipping -wallet path that doesn't exist. Failed to load database path '{wallet_path}'. Path does not exist."
        with node.assert_debug_log([warning.replace("\n", "\\x0a")], unexpected_msgs=[f"[warning] {forged_log_line}"]):
            self.start_node(0)
        self.stop_node(0, expected_stderr=f"Warning: {warning}")


if __name__ == '__main__':
    WalletLogInjectionTest(__file__).main()
