#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the revocation leaf of an LND simple taproot channel relays within -datacarriersize.

LND commits the local delayed key in its to_local revocation leaf by pushing and dropping it, so
that a third party can read the key and sweep the anchor:

    <local_delayedpubkey> OP_DROP <revocationkey> OP_CHECKSIG

(lnd input/script_utils.go, TaprootLocalCommitRevokeScript). The drop rule read that key as
non-standard data and refused the penalty spend of a revoked commitment with
txn-datacarrier-nonstandard. For that exact leaf, spent through the script path, the 34 bytes the
drop rule reads (push opcode, key, OP_DROP) count toward the -datacarriersize budget instead, like
an OP_RETURN payload. Every script near it stays non-standard data.
"""
from random import randbytes

from test_framework.key import ECKey, compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    OP_1,
    OP_2DROP,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_NOP,
    OP_TRUE,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

FUNDING = 100_000
# The spends are checked under the rules in force on mainnet, with the hardfork and RDTS active
FORK_HEIGHT = 100
NONSTANDARD = "txn-datacarrier-nonstandard"
EXCEEDED = "txn-datacarrier-exceeded"
# What the drop rule reads for the leaf's first key: push opcode, 32 byte key, OP_DROP
LEAF_BYTES = 34
BASE_ARGS = ["-corepolicy=0", f"-testactivationheight=blake2b@{FORK_HEIGHT}", "-rdtsexpiry=2000000000"]


def xonly_key():
    priv = generate_privkey()
    return priv, compute_xonly_pubkey(priv)[0]


class DataCarrierLnTaprootRevokeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        # -corepolicy=0 undoes the framework's -corepolicy, so each node runs the defaults plus one setting
        self.extra_args = [
            BASE_ARGS,                                   # 0: the defaults, -datacarriersize=83
            BASE_ARGS + ["-acceptnonstddatacarrier=1"],  # 1: non-standard data too, within the budget
            BASE_ARGS + ["-datacarriersize=42"],         # 2: room for one leaf, not two
            BASE_ARGS + ["-datacarriersize=67"],         # 3: one byte short of two leaves
            BASE_ARGS + ["-datacarriersize=0"],          # 4: no data at all
            BASE_ARGS + ["-datacarrierfullcount=0"],     # 5: no budget
            BASE_ARGS + ["-datacarriercost=2"],          # 6: data bytes weigh 8 WU each
        ]

    def fund(self, script_pubkey, n=1):
        outs = [self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=FUNDING) for _ in range(n)]
        self.generate(self.wallet, 1)
        return [COutPoint(int(f["txid"], 16), f["sent_vout"]) for f in outs]

    def spend(self, outpoints):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(op) for op in outpoints]
        tx.vout = [CTxOut(FUNDING * len(outpoints) - 10_000, script_to_p2wsh_script(CScript([OP_TRUE])))]
        tx.wit.vtxinwit = [CTxInWitness() for _ in outpoints]
        return tx

    def tapscript_spend(self, leaf, signer, siblings=(), n_inputs=1):
        """Script path spends of leaf, with a Schnorr signature by signer as the only stack item of each."""
        internal = compute_xonly_pubkey(generate_privkey())[0]
        tap = taproot_construct(internal, [("leaf", leaf)] + [(f"sibling{i}", s) for i, s in enumerate(siblings)])
        tx = self.spend(self.fund(tap.scriptPubKey, n_inputs))
        info = tap.leaves["leaf"]
        control = bytes([info.version | tap.negflag]) + tap.internal_pubkey + info.merklebranch
        for i in range(n_inputs):
            sighash = TaprootSignatureHash(tx, [CTxOut(FUNDING, tap.scriptPubKey)] * n_inputs, 0, i, scriptpath=True, leaf_script=leaf)
            tx.wit.vtxinwit[i].scriptWitness.stack = [sign_schnorr(signer, sighash), bytes(leaf), control]
        return tx

    def p2wsh_spend(self, script, signer):
        tx = self.spend(self.fund(script_to_p2wsh_script(script)))
        sig = signer.sign_ecdsa(SegwitV0SignatureHash(script, tx, 0, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, bytes(script)]
        return tx

    def check(self, what, tx, verdicts):
        """verdicts maps a node to True or to the reject reason it must give; nodes left out are not asked."""
        self.log.info(what)
        tx_hex = tx.serialize().hex()
        for node, want in verdicts.items():
            res = self.nodes[node].testmempoolaccept([tx_hex])[0]
            assert_equal(res["allowed"] or res["reject-reason"], want)

    def check_weight(self, tx):
        """-datacarriercost weights the 34 bytes as data: 4 WU each at the default of 1, 8 at 2, against 1 as witness bytes."""
        tx_hex = tx.serialize().hex()
        weight = self.nodes[0].decoderawtransaction(tx_hex)["weight"]
        assert_equal(self.nodes[0].testmempoolaccept([tx_hex])[0]["vsize"], (weight + LEAF_BYTES * 3 + 3) // 4)
        assert_equal(self.nodes[6].testmempoolaccept([tx_hex])[0]["vsize"], (weight + LEAF_BYTES * 7 + 3) // 4)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 310)

        delayed_priv, delayed = xonly_key()
        revoke_priv, revoke = xonly_key()
        # LND's to_local tree holds the delay leaf and the revocation leaf
        delay_leaf = CScript([delayed, OP_CHECKSIG, 144, OP_CHECKSEQUENCEVERIFY, OP_DROP])
        revoke_leaf = CScript([delayed, OP_DROP, revoke, OP_CHECKSIG])

        self.log.info("One revocation leaf input fits every budget but 0, and relays")
        tx = self.tapscript_spend(revoke_leaf, revoke_priv, siblings=[delay_leaf])
        self.check("The revocation leaf of LND's to_local tree", tx, {0: True, 1: True, 2: True, 3: True, 4: EXCEEDED, 5: True, 6: True})
        self.check_weight(tx)
        self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        # The nodes form a chain; node 4 drops it, so the three behind node 0 are the ones that see it
        self.sync_mempools(self.nodes[:4])
        assert tx.rehash() in self.nodes[3].getrawmempool()
        assert tx.rehash() not in self.nodes[4].getrawmempool()
        self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        self.check("The revocation leaf alone in its tree", self.tapscript_spend(revoke_leaf, revoke_priv), {0: True, 4: EXCEEDED})

        self.log.info("Each input adds 34 bytes: two fit 83 but not 67 or 42, three fit nothing but no budget")
        two = self.tapscript_spend(revoke_leaf, revoke_priv, siblings=[delay_leaf], n_inputs=2)
        self.check("Two revocation leaf inputs, 68 bytes", two, {0: True, 1: True, 2: EXCEEDED, 3: EXCEEDED, 4: EXCEEDED, 5: True})
        three = self.tapscript_spend(revoke_leaf, revoke_priv, siblings=[delay_leaf], n_inputs=3)
        self.check("Three revocation leaf inputs, 102 bytes", three, {0: EXCEEDED, 1: EXCEEDED, 5: True})

        self.log.info("Every script near it is still non-standard data, whatever the budget")
        junk = randbytes(32)
        key_priv, key = xonly_key()
        near = {0: NONSTANDARD, 1: True, 4: NONSTANDARD, 5: NONSTANDARD}
        for what, leaf in [
            ("A 33 byte dropped push", CScript([randbytes(33), OP_DROP, key, OP_CHECKSIG])),
            ("Two dropped pushes", CScript([junk, OP_DROP, randbytes(32), OP_DROP, key, OP_CHECKSIG])),
            ("Two pushes under one OP_2DROP", CScript([junk, randbytes(32), OP_2DROP, key, OP_CHECKSIG])),
            ("Something before the leaf", CScript([OP_NOP, junk, OP_DROP, key, OP_CHECKSIG])),
            ("Something after the OP_CHECKSIG", CScript([junk, OP_DROP, key, OP_CHECKSIG, OP_NOP])),
            ("OP_CHECKSIGVERIFY in place of OP_CHECKSIG", CScript([junk, OP_DROP, key, OP_CHECKSIGVERIFY, OP_1])),
        ]:
            self.check(what, self.tapscript_spend(leaf, key_priv), near)
        # Under P2WSH OP_CHECKSIG takes no 32 byte key, so a compressed key stands in for the second one
        ecdsa = ECKey()
        ecdsa.generate(compressed=True)
        p2wsh = CScript([junk, OP_DROP, ecdsa.get_pubkey().get_bytes(), OP_CHECKSIG])
        self.check("The same script under P2WSH", self.p2wsh_spend(p2wsh, ecdsa), near)

        self.log.info("The boundary is exact: two inputs fit a budget of 68")
        self.restart_node(3, extra_args=BASE_ARGS + ["-datacarriersize=68"])
        self.check("Two revocation leaf inputs at -datacarriersize=68", two, {3: True})


if __name__ == '__main__':
    DataCarrierLnTaprootRevokeTest(__file__).main()
