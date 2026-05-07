#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""combinerawtransaction must merge legacy multisig variants under unified rules."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.key import ECKey
from test_framework.wallet_util import bytes_to_wif
from decimal import Decimal

class T(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-testactivationheight=blake2b@1"]]

    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("w")
        w = node.get_wallet_rpc("w")
        self.generatetoaddress(node, 101, w.getnewaddress())

        keys, wifs, pubs = [], [], []
        for _ in range(2):
            k = ECKey()
            k.generate()
            keys.append(k)
            wifs.append(bytes_to_wif(k.get_bytes()))
            pubs.append(k.get_pubkey().get_bytes().hex())

        # "legacy" so the whole thing lives in the scriptSig, which is what
        # makes each co-signer's variant a different transaction by txid.
        ms = node.createmultisig(2, pubs, "legacy")
        txid = w.sendtoaddress(ms["address"], 2)
        raw = node.getrawtransaction(txid, True)
        vout = next(o["n"] for o in raw["vout"]
                    if o["scriptPubKey"].get("address") == ms["address"])
        spk = next(o["scriptPubKey"]["hex"] for o in raw["vout"] if o["n"] == vout)
        self.generate(node, 1)

        unsigned = node.createrawtransaction(
            [{"txid": txid, "vout": vout}], [{w.getnewaddress(): Decimal("1.999")}])
        prevtx = {"txid": txid, "vout": vout, "scriptPubKey": spk,
                  "redeemScript": ms["redeemScript"], "amount": 2}

        partials = []
        for wif in wifs:
            r = node.signrawtransactionwithkey(unsigned, [wif], [prevtx])
            assert not r["complete"], "one of two keys must not complete it"
            partials.append(r["hex"])

        a, b = partials
        assert a != b, "the two partials must differ"
        ta = node.decoderawtransaction(a)["txid"]
        tb = node.decoderawtransaction(b)["txid"]
        self.log.info(f"variant txids differ: {ta[:12]} vs {tb[:12]} -> {ta != tb}")

        combined = node.combinerawtransaction(partials)
        res = node.testmempoolaccept([combined])[0]
        self.log.info(f"combined accepted: {res['allowed']}  reason={res.get('reject-reason')}")
        assert res["allowed"], f"combining dropped signatures: {res}"
        self.log.info("legacy multisig variants combined into a valid transaction")

if __name__ == '__main__':
    T(__file__).main()
