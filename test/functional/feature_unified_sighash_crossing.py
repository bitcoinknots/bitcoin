#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A mempool crossing the activation height must not wedge block production.

An entry accepted under one fork state can be invalid under the other, and the
block assembler cannot skip an entry that has become invalid. A reorg across the
height is swept; an ordinary forward advance disconnects nothing, so it needs a
sweep of its own or the node stops making blocks."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, COIN
from test_framework.script import CScript, sign_input_legacy, SIGHASH_ALL, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_DROP, OP_TRUE, hash160
from test_framework.key import ECKey
from test_framework.script_util import script_to_p2sh_script
from test_framework.wallet import MiniWallet

SIGHASH_UNIFIED = 0x20
ACTIVATION = 250

class T(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = [f"-testactivationheight=blake2b@{ACTIVATION}", "-acceptnonstdtxn=1"]
        # The miner takes no transactions from the wire, so a spend given to the
        # victim below cannot be relayed to it and mined away. Without that the
        # entry leaves the victim's mempool by confirmation and the check below
        # cannot tell that apart from eviction. It still accepts its own RPC
        # submissions, which is how the funding transaction gets in.
        self.extra_args = [args + ["-blocksonly"], list(args)]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 120)

        key = ECKey()
        key.generate()
        pub = key.get_pubkey().get_bytes()
        spk = CScript([OP_DUP, OP_HASH160, hash160(pub), OP_EQUALVERIFY, OP_CHECKSIG])
        funding = wallet.send_to(from_node=node, scriptPubKey=spk, amount=3 * COIN)

        # A second output whose redeemScript holds signature-shaped bytes that
        # carry the opt-in bit. A scan of the scriptSig alone sees one push of a
        # hundred-odd bytes and nothing signature-shaped, so this is what the
        # detector has to look inside a push for. Nothing verifies these bytes;
        # a signature that CHECKSIG really evaluates cannot be hidden here,
        # because the P2SH address commits to the script that would contain it
        # and the signature commits to the prevout. The detector reads bytes
        # rather than deciding what is a signature, and treats what it cannot
        # rule out as one, which is what this pins down.
        looks_like_sig = bytes([0x30, 0x44, 0x02, 0x20]) + bytes(32) + bytes([0x02, 0x20]) + bytes(32) \
            + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        embed_redeem = CScript([looks_like_sig, OP_DROP, OP_TRUE])
        embed_funding = wallet.send_to(from_node=node,
                                       scriptPubKey=script_to_p2sh_script(embed_redeem),
                                       amount=3 * COIN)
        self.generate(wallet, 1)

        # A legacy signature carrying the opt-in bit. Valid now, because the
        # legacy algorithm reads 0x21 by its low bits and spends it as ALL.
        # Invalid from activation, where that byte means the signature opted in.
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
        tx.vout = [CTxOut(3 * COIN - 10000, spk)]
        tx.vin[0].scriptSig = CScript([pub])
        sign_input_legacy(tx, 0, spk, key, SIGHASH_ALL | SIGHASH_UNIFIED)
        raw = tx.serialize().hex()

        # Give the poison to the node that does NOT mine, so it stays in that
        # mempool instead of being confirmed into the next block. This is the
        # ordinary case: a node's mempool reaches activation by receiving
        # blocks, disconnecting nothing.
        victim = self.nodes[1]
        txid = victim.sendrawtransaction(hexstring=raw, ignore_rejects=["non-mandatory-script-verify-flag"])
        assert txid in victim.getrawmempool(), "the poison must be in the mempool to matter"
        self.log.info(f"poison sitting in the non-mining node's mempool at height {victim.getblockcount()}")

        # An ordinary transaction alongside it, opting in nowhere. The crossing
        # must not touch this one: evicting on the recorded state alone would
        # empty every mempool on the network at that block and drop payments
        # already in flight, for a rule that does not apply to them.
        ordinary = wallet.create_self_transfer()["hex"]
        ordinary_txid = victim.sendrawtransaction(ordinary)
        assert ordinary_txid in victim.getrawmempool()
        assert ordinary_txid not in node.getrawmempool(), \
            "the miner must not learn of it, or it leaves by confirmation"

        # And the one whose opt-in bytes sit inside the redeemScript.
        embed_tx = CTransaction()
        embed_tx.vin = [CTxIn(COutPoint(int(embed_funding["txid"], 16),
                                        embed_funding["sent_vout"]),
                              CScript([bytes(embed_redeem)]))]
        embed_tx.vout = [CTxOut(3 * COIN - 10000, spk)]
        embed_txid = victim.sendrawtransaction(
            hexstring=embed_tx.serialize().hex(),
            ignore_rejects=["non-mandatory-script-verify-flag", "scriptpubkey"])
        assert embed_txid in victim.getrawmempool()

        assert victim.getblockcount() < ACTIVATION
        self.generate(wallet, ACTIVATION + 1 - node.getblockcount(), sync_fun=self.no_op)
        self.sync_blocks(timeout=120)
        assert_equal(victim.getblockcount(), ACTIVATION + 1)
        self.log.info(f"victim crossed activation to {victim.getblockcount()} by receiving blocks")

        still_there = txid in victim.getrawmempool()
        self.log.info(f"poison still in mempool after crossing: {still_there}")
        try:
            # "blake2b" is declared too: combined with the proof-of-work
            # change the node requires a client to name that rule, and a
            # rule this node knows but has not scheduled is accepted here.
            victim.getblocktemplate({"rules": ["segwit", "blake2b"]})
            self.log.info("victim can still build a block template")
        except Exception as e:
            self.log.info(f"BLOCK PRODUCTION HALTED: {str(e)[:120]}")
            raise AssertionError("template generation wedged after forward crossing")
        assert not still_there, "the poison should have been evicted by the crossing"
        assert ordinary_txid in victim.getrawmempool(), \
            "a transaction that opted in nowhere must survive the crossing"
        assert embed_txid not in victim.getrawmempool(), \
            "opt-in bytes inside a redeemScript must be found: the scan has to " \
            "look inside a push, not only at top level"
        self.log.info("poison evicted by the forward-crossing sweep, the ordinary spend kept")

if __name__ == '__main__':
    T(__file__).main()
