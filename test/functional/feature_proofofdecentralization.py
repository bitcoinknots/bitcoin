#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Proof of Decentralization chain.

Blocks are mined by proof of work, but every coinbase is escrowed to a 2-of-3
multisig of the authority sitting when it was mined. The authority may release a
coinbase to its payee or claim it behind a timelock, but not redirect it. The
authority is re-elected by coinbase votes each term.
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, create_block, create_coinbase
from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import (
    CScript, LegacySignatureHash, SIGHASH_ALL,
    OP_0, OP_2, OP_3, OP_CHECKMULTISIG, OP_DROP, OP_TRUE, hash160,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import bytes_to_wif

TERM = 6            # short term so an election fits in the test
CLAIM_MATURITY = 20
FEE_SAT = 1000


def make_key(secret):
    k = ECKey()
    k.set(secret.to_bytes(32, 'big'), True)
    return k


class ProofOfDecentralizationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.chain = "decentral"
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Bootstrap authority: three keys we control.
        self.committee = [make_key(1001), make_key(1002), make_key(1003)]
        self.committee_pubs = [k.get_pubkey().get_bytes() for k in self.committee]
        # Candidates that miners can vote into a later authority.
        self.candidates = [make_key(2001), make_key(2002), make_key(2003)]
        self.base_args = [f"-decentralbootstrap={p.hex()}" for p in self.committee_pubs]
        self.base_args += [f"-decentraltermlength={TERM}", f"-decentralclaimmaturity={CLAIM_MATURITY}"]
        self.extra_args = [self.base_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def escrow_spk(self, payee_spk, committee_pubs):
        return CScript([payee_spk, OP_DROP, OP_2, *committee_pubs, OP_3, OP_CHECKMULTISIG])

    def spend_escrow(self, coinbase_txid, escrow_spk, value_sat, dest_spk, signers, fee=FEE_SAT):
        """Spend a bare-multisig escrow with the given committee keys."""
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(coinbase_txid, 16), 0), b"", 0xffffffff)]
        tx.vout = [CTxOut(value_sat - fee, dest_spk)]
        sighash, _ = LegacySignatureHash(escrow_spk, tx, 0, SIGHASH_ALL)
        # Signatures must be in committee key order for CHECKMULTISIG.
        script = CScript([OP_0] + [k.sign_ecdsa(sighash) + bytes([SIGHASH_ALL]) for k in signers])
        tx.vin[0].scriptSig = script
        return tx.serialize().hex()

    def run_test(self):
        node = self.nodes[0]
        wifs = [bytes_to_wif(k.get_bytes()) for k in self.committee]

        self.log.info("the chain reports its authority")
        info = node.getdecentinfo()
        assert_equal(info["active"], True)
        assert_equal(info["term_length"], TERM)
        assert_equal(info["authority"], [p.hex() for p in self.committee_pubs])

        self.log.info("a mined coinbase is escrowed to the authority, not paid out")
        payee = node.getnewaddress()
        payee_spk = bytes.fromhex(node.getaddressinfo(payee)["scriptPubKey"])
        self.generatetoaddress(node, 1, payee)
        cb = node.getblock(node.getblockhash(1), 2)["tx"][0]
        assert_equal(cb["vout"][0]["scriptPubKey"]["hex"], bytes(self.escrow_spk(payee_spk, self.committee_pubs)).hex())
        assert_equal(node.getreceivedbyaddress(payee, 0), 0)
        assert_equal(node.getpendingcoinbases()[0]["payee"], payee)

        # Mature the first coinbase.
        self.generatetoaddress(node, COINBASE_MATURITY + 1, node.getnewaddress())

        self.log.info("two of three authority keys release a coinbase to its payee")
        value = int(cb["vout"][0]["value"] * 100_000_000)
        escrow = self.escrow_spk(payee_spk, self.committee_pubs)
        release = node.decidecoinbase(cb["txid"], 0, "release", wifs[:2])
        assert_equal(release["complete"], True)
        assert_equal(release["destination"], payee)
        node.sendrawtransaction(release["hex"])
        self.generatetoaddress(node, 1, node.getnewaddress())
        assert_equal(node.getreceivedbyaddress(payee), Decimal("50") - Decimal(FEE_SAT) / 100_000_000)

        self.log.info("the authority cannot redirect a coinbase to an outsider")
        cb2 = node.getblock(node.getblockhash(2), 2)["tx"][0]
        cb2_escrow = CScript(bytes.fromhex(cb2["vout"][0]["scriptPubKey"]["hex"]))
        cb2_value = int(cb2["vout"][0]["value"] * 100_000_000)
        outsider = CScript([OP_0, hash160(self.candidates[0].get_pubkey().get_bytes())])
        redirect = self.spend_escrow(cb2["txid"], cb2_escrow, cb2_value, outsider, self.committee[:2])
        assert_raises_rpc_error(-26, "bad-decent-destination", node.sendrawtransaction, redirect)

        self.log.info("an outsider's two signatures cannot move a coinbase")
        raw = bytes(cb2_escrow)
        payee2 = CScript(raw[1:1 + raw[0]])  # the escrow opens with a direct push of the payee
        forged = self.spend_escrow(cb2["txid"], cb2_escrow, cb2_value, payee2, self.candidates[:2])
        assert_raises_rpc_error(-26, "script-verify-flag-failed", node.sendrawtransaction, forged)

        self.log.info("a claim locks the coinbase behind the authority timelock")
        claim = node.decidecoinbase(cb2["txid"], 0, "claim", wifs[1:3])
        assert_equal(claim["complete"], True)
        node.sendrawtransaction(claim["hex"])
        self.generatetoaddress(node, 1, node.getnewaddress())
        assert node.gettxout(claim["txid"], 0) is not None

        self.log.info("a coinbase paid out directly, not escrowed, is rejected")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=CScript([OP_TRUE])),
                             node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "bad-decent-coinbase")

        self.log.info("miners elect a new authority by voting over a term")
        # Fill the rest of the current term, then a full term voting three
        # candidates, so the next term's authority becomes those three.
        height = node.getblockcount()
        term_end = ((height - 0) // TERM + 1) * TERM
        self.generatetoaddress(node, term_end - height, node.getnewaddress())  # finish current term

        for cand in self.candidates:
            self.restart_node(0, extra_args=self.base_args + [f"-decentralvote={cand.get_pubkey().get_bytes().hex()}"])
            node = self.nodes[0]
            self.generatetoaddress(node, TERM // len(self.candidates), node.getnewaddress())

        # Into the next term: the authority should now be the three candidates.
        self.restart_node(0, extra_args=self.base_args)
        node = self.nodes[0]
        self.generatetoaddress(node, 1, node.getnewaddress())
        elected = sorted(node.getdecentinfo()["authority"])
        assert_equal(elected, sorted(c.get_pubkey().get_bytes().hex() for c in self.candidates))
        self.log.info("authority rotated to the elected candidates")


if __name__ == '__main__':
    ProofOfDecentralizationTest(__file__).main()
