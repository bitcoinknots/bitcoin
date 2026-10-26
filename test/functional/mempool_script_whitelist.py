#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the known-shape policy for revealed input scripts (-rejectunknownscripts) and the unproven field budget.

Node 0 runs the Knots defaults, node 1 has the shape check off (and logs what it would have refused), node 2 has the
field allowance raised past #422's 10 so the bpub reveal passes the budget there.
"""
from test_framework.key import ECKey, compute_xonly_pubkey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_0,
    OP_1,
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_IFDUP,
    OP_NOTIF,
    OP_SIZE,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    hash160,
    taproot_construct,
)
from test_framework.script_util import script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

FUND = 100_000
FEE = 20_000
UNKNOWN = "bad-witness-script-unknown"
EXCEEDED = "txn-datacarrier-exceeded"


def fake_key(i):
    """A key-shaped 33-byte push that no signature will ever prove."""
    return bytes([0x02 + (i & 1)]) + bytes([i & 0xff]) * 32


def new_key(compressed=True):
    k = ECKey()
    k.generate(compressed=compressed)
    return k


class ScriptWhitelistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # The framework starts nodes with -corepolicy, which soft-sets the shape check and the datacarrier
        # count off; set the Knots policy explicitly, like the other Knots policy tests do.
        knots = ["-datacarrierfullcount=1", "-acceptnonstddatacarrier=0", "-datacarriersize=83", "-datacarriercost=1"]
        self.extra_args = [
            knots + ["-rejectunknownscripts=1"],
            knots + ["-rejectunknownscripts=0", "-debug=mempool"],
            knots + ["-rejectunknownscripts=1", "-unprovenfieldallowance=14"],
        ]

    def fund(self, spk, n=1, mature=1):
        outs = [self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=FUND) for _ in range(n)]
        self.generate(self.wallet, mature)
        return outs

    def spend(self, outs, spk_out, sequence=0):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(o["txid"], 16), o["sent_vout"]), nSequence=sequence) for o in outs]
        tx.vout = [CTxOut((FUND - FEE) * len(outs), spk_out)]
        tx.wit.vtxinwit = [CTxInWitness() for _ in outs]
        return tx

    def check(self, label, tx, expect):
        """expect: one entry per node, None for accepted or the reject reason."""
        tx_hex = tx.serialize().hex()
        for node, exp in zip(self.nodes, expect):
            res = node.testmempoolaccept([tx_hex])[0]
            if exp is None:
                assert res["allowed"], (label, node.index, res)
            else:
                assert not res["allowed"], (label, node.index, res)
                assert_equal(res["reject-reason"], exp)
        self.log.info(f"{label}: {['accept' if e is None else e for e in expect]}")

    def p2wsh_tx(self, script, witness_items, n=1, sequence=0, mature=1):
        """Spend n P2WSH outputs of `script`; witness_items(sighash) returns the items below the script."""
        spk = script_to_p2wsh_script(script)
        outs = self.fund(spk, n, mature)
        tx = self.spend(outs, spk, sequence)
        for i in range(n):
            sighash = SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, FUND)
            tx.wit.vtxinwit[i].scriptWitness.stack = witness_items(sighash) + [bytes(script)]
        return tx

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 120)
        k1, k2, k3 = new_key(), new_key(), new_key()
        pk1, pk2, pk3 = (k.get_pubkey().get_bytes() for k in (k1, k2, k3))

        def ecdsa(key, sighash):
            return key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])

        self.log.info("Sane miniscript: a 2-of-3 P2WSH relays everywhere")
        multisig23 = CScript([OP_2, pk1, pk2, pk3, OP_3, OP_CHECKMULTISIG])
        self.check("2-of-3", self.p2wsh_tx(multisig23, lambda h: [b"", ecdsa(k1, h), ecdsa(k2, h)]), [None, None, None])

        self.log.info("BOLT-3 to_local, revocation path")
        to_local = CScript([OP_IF, pk1, OP_ELSE, 144, OP_CHECKSEQUENCEVERIFY, OP_DROP, pk2, OP_ENDIF, OP_CHECKSIG])
        self.check("to_local", self.p2wsh_tx(to_local, lambda h: [ecdsa(k1, h), b"\x01"]), [None, None, None])

        self.log.info("BOLT-3 anchor swept by anyone after 16 blocks: not sane miniscript, a template")
        anchor = CScript([pk1, OP_CHECKSIG, OP_IFDUP, OP_NOTIF, 16, OP_CHECKSEQUENCEVERIFY, OP_ENDIF])
        self.check("anchor sweep", self.p2wsh_tx(anchor, lambda h: [b""], sequence=16, mature=16), [None, None, None])

        self.log.info("Ark (Bark) unilateral exit leaf: timelock first, then the key")
        internal = new_key()
        leafkey = new_key()
        leaf_x = compute_xonly_pubkey(leafkey.get_bytes())[0]
        exit_script = CScript([2, OP_CHECKSEQUENCEVERIFY, OP_DROP, leaf_x, OP_CHECKSIG])
        tap = taproot_construct(compute_xonly_pubkey(internal.get_bytes())[0], [("exit", exit_script)])
        outs = self.fund(tap.scriptPubKey, mature=2)
        tx = self.spend(outs, tap.scriptPubKey, sequence=2)
        sighash = TaprootSignatureHash(tx, [CTxOut(FUND, tap.scriptPubKey)], SIGHASH_DEFAULT, 0, scriptpath=True, leaf_script=exit_script)
        control = bytes([LEAF_VERSION_TAPSCRIPT + tap.negflag]) + tap.internal_pubkey + tap.leaves["exit"].merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [sign_schnorr(leafkey.get_bytes(), sighash), bytes(exit_script), control]
        self.check("ark exit leaf", tx, [None, None, None])

        self.log.info("LND taproot channel leaves: anchor (a bare timelock), to_local delay, HTLC success")
        def tapleaf_tx(script, items, sequence=0, mature=1):
            tapi = taproot_construct(compute_xonly_pubkey(internal.get_bytes())[0], [("leaf", script)])
            outs = self.fund(tapi.scriptPubKey, mature=mature)
            tx = self.spend(outs, tapi.scriptPubKey, sequence=sequence)
            sighash = TaprootSignatureHash(tx, [CTxOut(FUND, tapi.scriptPubKey)], SIGHASH_DEFAULT, 0, scriptpath=True, leaf_script=script)
            ctrl = bytes([LEAF_VERSION_TAPSCRIPT + tapi.negflag]) + tapi.internal_pubkey + tapi.leaves["leaf"].merklebranch
            tx.wit.vtxinwit[0].scriptWitness.stack = items(sighash) + [bytes(script), ctrl]
            return tx
        ln_anchor = CScript([16, OP_CHECKSEQUENCEVERIFY])
        self.check("LND taproot anchor sweep", tapleaf_tx(ln_anchor, lambda h: [], sequence=16, mature=16), [None, None, None])
        ln_delay = CScript([leaf_x, OP_CHECKSIGVERIFY, 2, OP_CHECKSEQUENCEVERIFY])
        self.check("LND taproot to_local delay", tapleaf_tx(ln_delay, lambda h: [sign_schnorr(leafkey.get_bytes(), h)], sequence=2, mature=2), [None, None, None])
        preimage = b"\x42" * 32
        ln_success = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH160, hash160(preimage), OP_EQUALVERIFY, leaf_x, OP_CHECKSIGVERIFY, 1, OP_CHECKSEQUENCEVERIFY])
        self.check("LND taproot HTLC success", tapleaf_tx(ln_success, lambda h: [sign_schnorr(leafkey.get_bytes(), h), preimage], sequence=1), [None, None, None])

        self.log.info("Legacy P2SH 2-of-3 with an uncompressed key")
        ku = new_key(compressed=False)
        redeem = CScript([OP_2, pk1, ku.get_pubkey().get_bytes(), pk3, OP_3, OP_CHECKMULTISIG])
        p2sh = script_to_p2sh_script(redeem)
        outs = self.fund(p2sh)
        tx = self.spend(outs, p2sh)
        sighash, _ = LegacySignatureHash(redeem, tx, 0, SIGHASH_ALL)
        tx.vin[0].scriptSig = CScript([OP_0, ecdsa(k1, sighash), ecdsa(ku, sighash), bytes(redeem)])
        self.check("legacy 2-of-3 uncompressed", tx, [None, None, None])

        self.log.info("The bpub reveal: 1-of-15 is sane miniscript, the budget prices 14 unproven keys")
        one_of_15 = CScript([OP_1] + [fake_key(i) for i in range(14)] + [pk1, 15, OP_CHECKMULTISIG])
        self.check("1-of-15", self.p2wsh_tx(one_of_15, lambda h: [b"", ecdsa(k1, h)]), [EXCEEDED, EXCEEDED, None])
        one_of_6 = CScript([OP_1] + [fake_key(i) for i in range(5)] + [pk1, 6, OP_CHECKMULTISIG])
        self.check("1-of-6 (at the allowance)", self.p2wsh_tx(one_of_6, lambda h: [b"", ecdsa(k1, h)]), [None, None, None])
        one_of_7 = CScript([OP_1] + [fake_key(i) for i in range(6)] + [pk1, 7, OP_CHECKMULTISIG])
        self.check("1-of-7, one input (33 bytes)", self.p2wsh_tx(one_of_7, lambda h: [b"", ecdsa(k1, h)]), [None, None, None])
        self.check("1-of-7, three inputs (99 bytes)", self.p2wsh_tx(one_of_7, lambda h: [b"", ecdsa(k1, h)], n=3), [EXCEEDED, EXCEEDED, None])

        self.log.info("bpub's dummy-push fallback: dropped items and a dead branch are not a known shape")
        fallback = CScript([OP_DROP] * 13 + [OP_1] + [fake_key(i) for i in range(14)] + [pk1, 15, OP_CHECKMULTISIG, OP_IF, OP_1, OP_ELSE] + [OP_CHECKSIG] * 13 + [OP_ENDIF])
        dummies = [bytes([0x30]) + bytes(64) for _ in range(13)]
        self.check("dummy-push fallback", self.p2wsh_tx(fallback, lambda h: [b"", ecdsa(k1, h)] + dummies), [UNKNOWN, None, UNKNOWN])

        self.log.info("A dead branch holding data: refused as unknown; node 1 relays it and logs the shape")
        dead = CScript([OP_1, OP_NOTIF, b"\xaa" * 80, OP_ENDIF, OP_1])
        tx = self.p2wsh_tx(dead, lambda h: [])
        with self.nodes[1].assert_debug_log(expected_msgs=["unknown P2WSH script shape"]):
            self.check("dead-branch data", tx, [UNKNOWN, None, UNKNOWN])

        self.log.info("64-byte items are not signatures in P2WSH: a hash chain satisfied with them pays for its bytes")
        pre = [bytes([i + 1]) * 64 for i in range(17)]
        chain = CScript(sum([[OP_HASH160, hash160(pre[16 - i]), OP_EQUALVERIFY] for i in range(17)], []) + [pk1, OP_CHECKSIG])
        self.check("HASH160 chain, 64-byte preimages", self.p2wsh_tx(chain, lambda h: [ecdsa(k1, h)] + pre), [EXCEEDED, EXCEEDED, EXCEEDED])

        self.log.info("65-byte pushes are not keys in P2WSH: a PowPeg layout with uncompressed slots is unknown there")
        junk65 = [b"\x04" + bytes([i + 1]) * 64 for i in range(15)]
        powpeg = CScript([OP_NOTIF, OP_1] + junk65 + [pk1, 16, OP_CHECKMULTISIG, OP_ELSE, 100, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1, pk1, OP_1, OP_CHECKMULTISIG, OP_ENDIF])
        self.check("PowPeg layout in P2WSH, 65-byte slots", self.p2wsh_tx(powpeg, lambda h: [b"", ecdsa(k1, h), b""]), [UNKNOWN, None, UNKNOWN])

        self.log.info("Tagged 2-of-2 leaf: the 66-byte tag is counted as datacarrier bytes")
        ka, kb = new_key(), new_key()
        xa, xb = (compute_xonly_pubkey(k.get_bytes())[0] for k in (ka, kb))
        tagged = CScript([xa, OP_CHECKSIGVERIFY, xb, OP_CHECKSIGVERIFY, b"a" * 64 + b":0"])
        tap2 = taproot_construct(compute_xonly_pubkey(internal.get_bytes())[0], [("tag", tagged)])
        control2 = bytes([LEAF_VERSION_TAPSCRIPT + tap2.negflag]) + tap2.internal_pubkey + tap2.leaves["tag"].merklebranch
        for n, expect in ((1, [None, None, None]), (2, [EXCEEDED, EXCEEDED, EXCEEDED])):
            outs = self.fund(tap2.scriptPubKey, n)
            tx = self.spend(outs, tap2.scriptPubKey)
            spent = [CTxOut(FUND, tap2.scriptPubKey)] * n
            for i in range(n):
                sighash = TaprootSignatureHash(tx, spent, SIGHASH_DEFAULT, i, scriptpath=True, leaf_script=tagged)
                tx.wit.vtxinwit[i].scriptWitness.stack = [sign_schnorr(kb.get_bytes(), sighash), sign_schnorr(ka.get_bytes(), sighash), bytes(tagged), control2]
            self.check(f"tagged 2-of-2, {n} input(s)", tx, expect)


if __name__ == "__main__":
    ScriptWhitelistTest(__file__).main()
