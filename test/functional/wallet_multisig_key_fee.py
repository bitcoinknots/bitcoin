#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise unsigned Taproot key-fee funding through the public PSBT RPC."""

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.key import H_POINT
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class WalletMultisigKeyFeeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-corepolicy=0", "-minrelaymultisigexcesskeyfee=1000"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("funder", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        mining_address = funder.getnewaddress()
        self.generatetoaddress(node, 101, mining_address)
        node.createwallet("watcher", disable_private_keys=True, blank=True, descriptors=True)
        watcher = node.get_wallet_rpc("watcher")
        node.createwallet("signer", blank=True, descriptors=True)
        signer = node.get_wallet_rpc("signer")

        private, public = generate_keypair(wif=True)
        others = [generate_keypair()[1].hex() for _ in range(2)]
        public = public.hex()
        public_leaf = f"multi_a(1,{public},{','.join(others)})"
        private_leaf = f"multi_a(1,{private},{','.join(others)})"
        destinations = []
        for public_internal, private_internal in [(public, private), (H_POINT, H_POINT)]:
            desc = descsum_create(f"tr({public_internal},{public_leaf})")
            private_desc = descsum_create(f"tr({private_internal},{private_leaf})")
            assert watcher.importdescriptors([{"desc": desc, "timestamp": "now"}])[0]["success"]
            assert signer.importdescriptors([{"desc": private_desc, "timestamp": "now"}])[0]["success"]
            address = node.deriveaddresses(desc)[0]
            funder.sendtoaddress(address, Decimal("0.01"))
            destinations.append(address)
        self.generatetoaddress(node, 1, mining_address)

        options = {
            "add_inputs": False,
            "includeWatching": True,
            "changeAddress": funder.getnewaddress(),
            "fee_rate": 1,
        }
        outputs = {funder.getnewaddress(): Decimal("0.001")}

        def fund(address, **overrides):
            coin = watcher.listunspent(1, 9999999, [address])[0]
            return watcher.walletcreatefundedpsbt(
                [{"txid": coin["txid"], "vout": coin["vout"]}], outputs,
                options=options | overrides,
            )

        self.log.info("An unsigned PSBT with a recovery leaf funds without an existing witness")
        reserved = fund(destinations[0])
        assert_equal(reserved["fee"], Decimal("0.00001000"))
        hinted = fund(destinations[0], multisig_fee=0)
        assert hinted["fee"] < reserved["fee"]
        assert_equal(fund(destinations[0], multisig_fee=2000)["fee"], Decimal("0.00002000"))

        for invalid in [-1, 2_100_000_000_000_001]:
            assert_raises_rpc_error(-8, "multisig_fee must be nonnegative", fund, destinations[0], multisig_fee=invalid)

        def signed_transaction(result):
            processed = signer.walletprocesspsbt(result["psbt"])
            final = node.finalizepsbt(processed["psbt"])
            assert final["complete"]
            return final["hex"]

        self.log.info("A selected key-path spend does not pay for its unused recovery leaf")
        key_path = signed_transaction(hinted)
        assert_equal(len(node.decoderawtransaction(key_path)["vin"][0]["txinwitness"]), 1)
        assert node.testmempoolaccept([key_path])[0]["allowed"]

        self.log.info("A funding hint cannot override the relay floor on a script-path spend")
        underfunded = signed_transaction(fund(destinations[1], multisig_fee=0))
        rejected = node.testmempoolaccept([underfunded])[0]
        assert_equal(rejected["allowed"], False)
        assert_equal(rejected["reject-reason"], "min multisig excess key fee not met")
        funded = signed_transaction(fund(destinations[1]))
        assert node.testmempoolaccept([funded])[0]["allowed"]


if __name__ == "__main__":
    WalletMultisigKeyFeeTest(__file__).main()
