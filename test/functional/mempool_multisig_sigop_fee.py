#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the minimum fee policy for excess keys in canonical multisig inputs."""

from test_framework.key import ECKey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_FROMALTSTACK,
    OP_NUMEQUAL,
    OP_NOTIF,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    OP_TRUE,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    hash160,
    ripemd160,
    sha256,
    taproot_construct,
)
from test_framework.script_util import script_to_p2sh_p2wsh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


FUNDING_VALUE = 1_000_000


class MultisigSigOpFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # The framework selects Core policy by default. Disable it here so this
        # test exercises the Knots default without restating the default value.
        self.extra_args = [["-corepolicy=0"]]

    def create_multisig(self, required, total):
        keys = []
        for _ in range(total):
            key = ECKey()
            key.generate(compressed=True)
            keys.append(key)
        script = CScript([
            OP_2 if required == 2 else required,
            *[key.get_pubkey().get_bytes() for key in keys],
            OP_2 if total == 2 else OP_3 if total == 3 else total,
            OP_CHECKMULTISIG,
        ])
        return keys, script

    def fund(self, script, *, nested=False, count=1):
        script_pubkey = script_to_p2sh_p2wsh_script(script) if nested else script_to_p2wsh_script(script)
        return [
            self.wallet.send_to(
                from_node=self.nodes[0],
                scriptPubKey=script_pubkey,
                amount=FUNDING_VALUE,
            )
            for _ in range(count)
        ]

    def make_spend(self, fundings, script, keys, required, fee, *, nested=False, witness_padding=0):
        tx = CTransaction()
        tx.vin = [
            CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))
            for funding in fundings
        ]
        tx.vout = [CTxOut(FUNDING_VALUE * len(fundings) - fee, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness() for _ in fundings]

        witness_program = script_to_p2wsh_script(script)
        for index in range(len(fundings)):
            if nested:
                tx.vin[index].scriptSig = CScript([bytes(witness_program)])
            sighash = SegwitV0SignatureHash(script, tx, index, SIGHASH_ALL, FUNDING_VALUE)
            signatures = [
                key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])
                for key in keys[:required]
            ]
            tx.wit.vtxinwit[index].scriptWitness.stack = [b""] + signatures + [b"\x01" * 64] * witness_padding + [bytes(script)]
        tx.rehash()
        return tx.serialize().hex()

    def check_fee(self, fundings, script, keys, required, fee, allowed, *, nested=False, ignore_rejects=None, witness_padding=0):
        result = self.nodes[0].testmempoolaccept(
            [self.make_spend(fundings, script, keys, required, fee, nested=nested, witness_padding=witness_padding)],
            0,
            ignore_rejects or [],
        )[0]
        assert_equal(result["allowed"], allowed)
        if not allowed:
            assert_equal(result["reject-reason"], "min multisig excess key fee not met")

    def check_taproot_identities(self, keys):
        variants = []
        identities = [[], [OP_SWAP, OP_SWAP], [OP_DUP, OP_DROP], [OP_TOALTSTACK, OP_FROMALTSTACK]]
        for required, total, floor in [(1, 15, 13_000), (2, 3, 0)]:
            selected = keys[:total]
            for identity in identities:
                script_items = []
                for index, key in enumerate(selected):
                    script_items += [key.get_pubkey().get_bytes()[1:]] + identity
                    script_items += [OP_CHECKSIG if index == 0 else OP_CHECKSIGADD]
                script = CScript(script_items + [required, OP_NUMEQUAL])
                tap = taproot_construct(selected[0].get_pubkey().get_bytes()[1:], [("multisig", script)])
                funding = self.wallet.send_to(
                    from_node=self.nodes[0], scriptPubKey=tap.scriptPubKey, amount=FUNDING_VALUE,
                )
                variants.append((required, floor, selected, script, tap, funding))
        self.generate(self.wallet, 1)

        for required, floor, selected, script, tap, funding in variants:
            for fee, allowed in ([(floor - 1, False), (floor, True)] if floor else [(500, True)]):
                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
                tx.vout = [CTxOut(FUNDING_VALUE - fee, self.wallet.get_output_script())]
                sighash = TaprootSignatureHash(
                    tx, [CTxOut(FUNDING_VALUE, tap.scriptPubKey)], 0,
                    scriptpath=True, leaf_script=script,
                )
                signatures = [sign_schnorr(key.get_bytes(), sighash) if i < required else b"" for i, key in enumerate(selected)]
                leaf = tap.leaves["multisig"]
                control = bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = list(reversed(signatures)) + [bytes(script), control]
                result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], 0)[0]
                assert_equal(result["allowed"], allowed)
                if not allowed:
                    assert_equal(result["reject-reason"], "min multisig excess key fee not met")

    def check_lightning_spends(self):
        """All BOLT #3 to_local/HTLC paths, including revocation and anchors."""
        local, remote, revocation = [ECKey() for _ in range(3)]
        for key in (local, remote, revocation):
            key.generate(compressed=True)
        local_pub, remote_pub, revocation_pub = [
            key.get_pubkey().get_bytes() for key in (local, remote, revocation)
        ]
        preimage = sha256(b"Lightning key-fee regression")
        payment_hash = ripemd160(sha256(preimage))
        delay = 2
        expiry = self.nodes[0].getblockcount()
        cases = []
        delayed = CScript([
            OP_IF, revocation_pub, OP_ELSE, delay, OP_CHECKSEQUENCEVERIFY,
            OP_DROP, local_pub, OP_ENDIF, OP_CHECKSIG,
        ])
        cases.append(("to_local", delayed, self.fund(delayed)[0], ["delayed", "revocation"]))
        for anchors in (False, True):
            for received in (False, True):
                items = [
                    OP_DUP, OP_HASH160, hash160(revocation_pub), OP_EQUAL,
                    OP_IF, OP_CHECKSIG, OP_ELSE, remote_pub, OP_SWAP, OP_SIZE, 32, OP_EQUAL,
                ]
                if received:
                    items += [
                        OP_IF, OP_HASH160, payment_hash, OP_EQUALVERIFY,
                        2, OP_SWAP, local_pub, 2, OP_CHECKMULTISIG,
                        OP_ELSE, OP_DROP, expiry, OP_CHECKLOCKTIMEVERIFY,
                        OP_DROP, OP_CHECKSIG, OP_ENDIF,
                    ]
                    paths = ["received_success", "received_timeout", "revocation"]
                else:
                    items += [
                        OP_NOTIF, OP_DROP, 2, OP_SWAP, local_pub, 2, OP_CHECKMULTISIG,
                        OP_ELSE, OP_HASH160, payment_hash, OP_EQUALVERIFY,
                        OP_CHECKSIG, OP_ENDIF,
                    ]
                    paths = ["offered_timeout", "offered_preimage", "revocation"]
                if anchors:
                    items += [1, OP_CHECKSEQUENCEVERIFY, OP_DROP]
                script = CScript(items + [OP_ENDIF])
                cases.append((f"HTLC received={received} anchors={anchors}", script, self.fund(script)[0], paths))

        self.generate(self.wallet, delay)
        for name, script, funding, paths in cases:
            for path in paths:
                tx = CTransaction()
                tx.nVersion = 2
                tx.nLockTime = expiry
                tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]), nSequence=delay)]
                tx.vout = [CTxOut(FUNDING_VALUE - 500, self.wallet.get_output_script())]
                sighash = SegwitV0SignatureHash(script, tx, 0, SIGHASH_ALL, FUNDING_VALUE)
                local_sig, remote_sig, revocation_sig = [
                    key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL]) for key in (local, remote, revocation)
                ]
                stacks = {
                    "delayed": [local_sig, b""],
                    "revocation": [revocation_sig, b"\x01" if name == "to_local" else revocation_pub],
                    "offered_timeout": [b"", remote_sig, local_sig, b""],
                    "offered_preimage": [remote_sig, preimage],
                    "received_success": [b"", remote_sig, local_sig, preimage],
                    "received_timeout": [remote_sig, b""],
                }
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = stacks[path] + [bytes(script)]
                result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], 0)[0]
                assert result["allowed"], f"{name}: {path}: {result}"

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        keys_2_of_2, script_2_of_2 = self.create_multisig(2, 2)
        keys_2_of_3, script_2_of_3 = self.create_multisig(2, 3)
        keys_3_of_5, script_3_of_5 = self.create_multisig(3, 5)
        keys_2_of_5, script_2_of_5 = self.create_multisig(2, 5)
        keys_1_of_15, script_1_of_15 = self.create_multisig(1, 15)
        dropped_count_script = CScript([
            1, *[key.get_pubkey().get_bytes() for key in keys_1_of_15],
            15, OP_DROP, 15, OP_CHECKMULTISIG,
        ])
        padded_branch_script = CScript([OP_DROP] * 13) + script_1_of_15 + CScript(
            [OP_IF, OP_TRUE, OP_ELSE] + [OP_CHECKSIG] * 13 + [OP_ENDIF]
        )
        funding_2_of_2 = self.fund(script_2_of_2)
        funding_2_of_3 = self.fund(script_2_of_3)
        funding_3_of_5 = self.fund(script_3_of_5)
        funding_2_of_5 = self.fund(script_2_of_5)
        funding_1_of_15 = self.fund(script_1_of_15)
        dropped_count_funding = self.fund(dropped_count_script)
        padded_branch_funding = self.fund(padded_branch_script)
        nested_funding_1_of_15 = self.fund(script_1_of_15, nested=True)
        multi_funding_2_of_5 = self.fund(script_2_of_5, count=3)
        self.generate(self.wallet, 1)

        self.log.info("Valid signed 2-of-2 and 2-of-3 P2WSH spends have no excess-key floor")
        self.check_fee(funding_2_of_2, script_2_of_2, keys_2_of_2, 2, 500, True)
        self.check_fee(funding_2_of_3, script_2_of_3, keys_2_of_3, 2, 500, True)

        self.log.info("A valid signed 3-of-5 has one charged excess key")
        self.check_fee(funding_3_of_5, script_3_of_5, keys_3_of_5, 3, 999, False)
        self.check_fee(funding_3_of_5, script_3_of_5, keys_3_of_5, 3, 1_000, True)

        self.log.info("A valid signed 2-of-5 has two charged excess keys")
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 1_999, False)
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 2_000, True)

        self.log.info("A valid signed 1-of-15 has thirteen charged excess keys")
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False)
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 13_000, True)

        self.log.info("Dropping and re-pushing the key count cannot bypass the floor")
        self.check_fee(dropped_count_funding, dropped_count_script, keys_1_of_15, 1, 13_999, False)
        self.check_fee(dropped_count_funding, dropped_count_script, keys_1_of_15, 1, 14_000, True)

        self.log.info("Dropped witness padding and unused CHECKSIGs cannot cancel multisig keys")
        self.check_fee(padded_branch_funding, padded_branch_script, keys_1_of_15, 1, 12_999, False, witness_padding=13)
        self.check_fee(padded_branch_funding, padded_branch_script, keys_1_of_15, 1, 13_000, True, witness_padding=13)

        self.log.info("A valid signed nested P2SH-P2WSH spend is counted identically")
        self.check_fee(nested_funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False, nested=True)
        self.check_fee(nested_funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 13_000, True, nested=True)

        self.log.info("The floor scales over every input in the complete transaction")
        self.check_fee(multi_funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 5_999, False)
        self.check_fee(multi_funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 6_000, True)

        self.log.info("Only the policy's own reject key bypasses it")
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, False, ignore_rejects=["min relay fee not met"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 12_999, True, ignore_rejects=["min multisig excess key fee not met"])

        self.log.info("Three stack-identity families preserve signed Taproot key counts and the free key allowance")
        self.check_taproot_identities(keys_1_of_15)

        self.log.info("Standard Lightning close, recovery and HTLC paths have no key-fee floor")
        self.check_lightning_spends()

        self.log.info("The per-excess-key amount is configurable")
        self.restart_node(0, extra_args=["-minrelaymultisigexcesskeyfee=1500"])
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 2_999, False)
        self.check_fee(funding_2_of_5, script_2_of_5, keys_2_of_5, 2, 3_000, True)

        self.log.info("A value of zero disables the additional policy")
        self.restart_node(0, extra_args=["-minrelaymultisigexcesskeyfee=0"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 500, True)

        self.log.info("Core policy disables the Knots-specific fee floor")
        self.restart_node(0, extra_args=["-corepolicy=1"])
        self.check_fee(funding_1_of_15, script_1_of_15, keys_1_of_15, 1, 500, True)


if __name__ == "__main__":
    MultisigSigOpFeeTest(__file__).main()
