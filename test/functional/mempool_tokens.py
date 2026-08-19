#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test token protocol filtering (-rejecttokens)."""

from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet

from random import randbytes


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


class RejectTokensTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # Set both ends explicitly rather than relying on the compiled-in default.
        self.extra_args = [
            ["-rejecttokens=1"],
            ["-rejecttokens=0"],
        ]

    def test_counterparty(self, node: TestNode, success: bool, wrong_key: bool = False) -> None:
        # A Counterparty message is the "CNTRPRTY" magic followed by the message body, obfuscated
        # with RC4 keyed by the first input's txid in RPC byte order.
        tx = self.wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
        txid = "%064x" % tx.vin[0].prevout.hash
        key = randbytes(32) if wrong_key else bytes.fromhex(txid)
        payload = rc4(key, b'CNTRPRTY' + randbytes(23))
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, payload])))
        tx.vout[0].nValue -= tx.get_vsize()

        tx_hex = tx.serialize().hex()

        if success:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
            assert tx.rehash() in node.getrawmempool(True), f'{tx_hex} not in mempool'
        else:
            assert_raises_rpc_error(-26, "tokens-counterparty",
                                    self.wallet.sendrawtransaction, from_node=node, tx_hex=tx_hex)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.log.info("Testing a Counterparty issuance with -rejecttokens=1.")
        self.test_counterparty(node=self.nodes[0], success=False)

        self.log.info("Testing a Counterparty issuance with -rejecttokens=0.")
        self.test_counterparty(node=self.nodes[1], success=True)

        self.log.info("Testing that a payload not keyed to the first input is left alone.")
        self.test_counterparty(node=self.nodes[0], success=True, wrong_key=True)


if __name__ == '__main__':
    RejectTokensTest(__file__).main()
