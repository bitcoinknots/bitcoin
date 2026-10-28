#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test token protocol filtering (-rejecttokens)."""

from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

from random import randbytes

# Token messages as written on mainnet: a JSON mint (715863e04b618a6818eaec826b8ea900a75a43a5c22859c6b408c68246c4ebcb)
# and an Omni Layer simple send (7134e618c5970bc3d7346cb4dce83aaf081213c122601caa8e64ff5e32296f38), and random
# data that begins with '{' (444c708b2b6e41d170d37ad9dbbdd2e7d2e942072be27f398b347b830c9a2255), which is neither.
JSON_MINT = b'{"p":"ico-20","op":"mint","tick":"LEAF"}'
OMNI_SEND = bytes.fromhex("6f6d6e690000000000000003000000000000009d")
BRACE_DATA = bytes.fromhex("7ba0149edc5646e8b3385eb62c9d2dbe")


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
        self.num_nodes = 4
        # Nodes 0 and 1 set the option explicitly. The framework starts every node with -corepolicy,
        # which turns it off, so node 2 takes the Knots default with -corepolicy=0 and node 3 the
        # Core policy reset.
        self.extra_args = [
            ["-rejecttokens=1"],
            ["-rejecttokens=0"],
            ["-corepolicy=0"],
            ["-corepolicy=1"],
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

    def send(self, node: TestNode, payload: bytes, reason: str | None) -> None:
        tx = self.wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, payload])))
        tx.vout[0].nValue -= 10 * tx.get_vsize()
        tx_hex = tx.serialize().hex()
        if reason is None:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
            assert tx.rehash() in node.getrawmempool(), f'{tx_hex} not in mempool'
        else:
            assert_raises_rpc_error(-26, reason, self.wallet.sendrawtransaction, from_node=node, tx_hex=tx_hex)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.log.info("Testing a Counterparty issuance with -rejecttokens=1.")
        self.test_counterparty(node=self.nodes[0], success=False)

        self.log.info("Testing a Counterparty issuance with -rejecttokens=0.")
        self.test_counterparty(node=self.nodes[1], success=True)

        self.log.info("Testing that a payload not keyed to the first input is left alone.")
        self.test_counterparty(node=self.nodes[0], success=True, wrong_key=True)

        self.log.info("A JSON token mint is refused with -rejecttokens=1 and accepted with =0.")
        assert_equal(len(CScript([OP_RETURN, JSON_MINT])), 42)  # OP_RETURN, one push opcode, 40 bytes
        self.send(self.nodes[0], JSON_MINT, "tokens-json")
        self.send(self.nodes[1], JSON_MINT, None)

        self.log.info("An Omni Layer message is refused with -rejecttokens=1 and accepted with =0.")
        self.send(self.nodes[0], OMNI_SEND, "tokens-omni")
        self.send(self.nodes[1], OMNI_SEND, None)

        self.log.info("Random data that begins with '{' is not a token message.")
        self.send(self.nodes[0], BRACE_DATA, None)

        self.log.info("Both are refused at the Knots default and relayed under -corepolicy.")
        self.send(self.nodes[2], JSON_MINT, "tokens-json")
        self.send(self.nodes[2], OMNI_SEND, "tokens-omni")
        self.send(self.nodes[3], JSON_MINT, None)
        self.send(self.nodes[3], OMNI_SEND, None)

        self.log.info("Two OP_RETURN outputs are refused before either is read; with that refusal ignored, both are read.")
        tx = self.wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, b"memo"])))
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, JSON_MINT])))
        tx.vout[0].nValue -= 10 * tx.get_vsize()
        node = self.nodes[0]
        assert_equal(node.testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]["reject-reason"], "multi-op-return")
        assert_equal(node.testmempoolaccept([tx.serialize().hex()], maxfeerate=0, ignore_rejects=["multi-op-return"])[0]["reject-reason"], "tokens-json")
        tx.vout[2].scriptPubKey = CScript([OP_RETURN, b"memo"])
        assert node.testmempoolaccept([tx.serialize().hex()], maxfeerate=0, ignore_rejects=["multi-op-return"])[0]["allowed"]


if __name__ == '__main__':
    RejectTokensTest(__file__).main()
