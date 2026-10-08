#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Price additional 1-of-N witness keys without prohibiting their spends."""

from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey, ECPubKey, compute_xonly_pubkey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, COIN
from test_framework.script import (
    CScript, OP_CHECKMULTISIG, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG,
    OP_CHECKSIGADD, OP_DROP, OP_NUMEQUAL, SIGHASH_ALL, SIGHASH_UNIFIED,
    UNIFIED_SCRIPT_TYPE_TAPSCRIPT, UnifiedSignatureHash, taproot_construct,
)
from test_framework.script_util import PAY_TO_ANCHOR, key_to_p2pkh_script, key_to_p2wpkh_script, script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


class OneOfNCostTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = []
        common = ["-testactivationheight=blake2b@1", "-corepolicy=0", "-acceptnonstdtxn=0", "-minrelaytxfee=0.00001000", "-mempooltruc=enforce"]
        self.extra_args = [common, common + ["-oneofnkeypenalty=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    @staticmethod
    def data_key(index):
        # BPUB stores 31 payload bytes in X and grinds its final byte until
        # the compressed key is valid. No private key for this point is used.
        payload = (f"BPUB payload chunk {index:02d}".encode()).ljust(31, b".")
        for nonce in range(256):
            encoded = b"\x02" + payload + bytes([nonce])
            pub = ECPubKey()
            pub.set(encoded)
            if pub.is_valid:
                return encoded
        raise AssertionError("No valid data key")

    def fund(self, kind, n, threshold=1, payload=False, timelock=False):
        keys = [self.data_key(i) if payload and i < n - 1 else self.keys[i].get_pubkey().get_bytes() for i in range(n)]
        info = None
        if kind == "taproot":
            ops = []
            for i, key in enumerate(keys):
                ops += [key[1:], OP_CHECKSIG if i == 0 else OP_CHECKSIGADD]
            script = CScript(ops + [threshold, OP_NUMEQUAL])
            internal = compute_xonly_pubkey(self.keys[-1].get_bytes())[0]
            info = taproot_construct(internal, [("multisig", script)])
            spk = info.scriptPubKey
        else:
            prefix = [0, OP_CHECKSEQUENCEVERIFY, OP_DROP] if timelock else []
            script = CScript(prefix + [threshold] + keys + [n, OP_CHECKMULTISIG])
            spk = script_to_p2sh_script(script) if kind == "legacy" else script_to_p2wsh_script(script)
            if kind == "nested":
                spk = script_to_p2sh_script(spk)
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=COIN)
        self.generate(self.wallet, 1)
        return dict(kind=kind, n=n, threshold=threshold, script=script, info=info,
                    outpoint=COutPoint(int(funding["txid"], 16), funding["sent_vout"]), utxo=CTxOut(COIN, spk))

    def spend(self, case, fee=10000):
        tx = CTransaction()
        tx.version = case.get("version", 2)
        tx.vin = [CTxIn(case["outpoint"], nSequence=case.get("sequence", 1))]
        tx.vout = [CTxOut(case["utxo"].nValue - fee, key_to_p2wpkh_script(self.keys[0].get_pubkey().get_bytes()))]
        for i in range(case.get("padding_outputs", 0)):
            tx.vout[0].nValue -= 1000
            tx.vout.append(CTxOut(1000, CScript([0, (i + 1).to_bytes(20, "big")])))
        if case.get("anchor", False):
            tx.vout.append(CTxOut(0, PAY_TO_ANCHOR))
        tx.wit.vtxinwit = [CTxInWitness()]
        hash_type = SIGHASH_ALL | SIGHASH_UNIFIED
        if case["kind"] == "taproot":
            leaf = case["info"].leaves["multisig"]
            sighash = UnifiedSignatureHash(None, tx, 0, hash_type, [case["utxo"]], False,
                                          script_type=UNIFIED_SCRIPT_TYPE_TAPSCRIPT, leaf_script=leaf.script, leaf_ver=leaf.version)
            sigs = [b""] * case["n"]
            for i in range(case["n"] - case["threshold"], case["n"]):
                sigs[i] = sign_schnorr(self.keys[i].get_bytes(), sighash) + bytes([hash_type])
            control = bytes([leaf.version + case["info"].negflag]) + case["info"].internal_pubkey + leaf.merklebranch
            tx.wit.vtxinwit[0].scriptWitness.stack = list(reversed(sigs)) + [leaf.script, control]
        else:
            witness = case["kind"] != "legacy"
            sighash = UnifiedSignatureHash(case["script"], tx, 0, hash_type, [case["utxo"]], witness)
            sigs = [self.keys[i].sign_ecdsa(sighash) + bytes([hash_type]) for i in range(case["n"] - case["threshold"], case["n"])]
            stack = [b""] + sigs + [case["script"]]
            if witness:
                tx.wit.vtxinwit[0].scriptWitness.stack = stack
                if case["kind"] == "nested":
                    tx.vin[0].scriptSig = CScript([script_to_p2wsh_script(case["script"])])
            else:
                tx.vin[0].scriptSig = CScript(stack)
        tx.rehash()
        return tx

    def check_cost(self, case, extra_weight):
        tx = self.spend(case)
        results = [node.testmempoolaccept([tx.serialize().hex()])[0] for node in self.nodes]
        for result in results:
            assert result["allowed"], (case, result)
        sigops = 0 if case["kind"] == "taproot" else case["n"] * (4 if case["kind"] == "legacy" else 1)
        assert_equal(results[0]["vsize"], results[1]["vsize"])
        assert_equal(results[1]["vsize"], (max(tx.get_weight(), sigops * 20) + 3) // 4)
        penalty = (extra_weight + 3) // 4  # minrelaytxfee is 1 sat/vbyte
        assert_equal(results[0]["fees"]["effective-feerate"], Decimal((10000 - penalty) * 1000 // results[0]["vsize"]) / COIN)
        return tx, results

    def check_wallet(self, wrapper):
        node = self.nodes[0]
        name = "oneofn_" + wrapper
        node.createwallet(name, blank=True, descriptors=True)
        wallet = node.get_wallet_rpc(name)
        wifs = [bytes_to_wif(key.get_bytes()) for key in self.keys[:4]]
        multi = f"multi(1,{','.join(wifs)})"
        if wrapper == "taproot":
            # An unowned internal key forces script-path signing.
            nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            desc = f"tr({nums},multi_a(1,{','.join(wifs)}))"
        else:
            desc = f"wsh({multi})"
            if wrapper == "nested":
                desc = f"sh({desc})"
        desc = descsum_create(desc)
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now"}])[0]["success"], True)
        public = wallet.getdescriptorinfo(desc)["descriptor"]
        address = wallet.deriveaddresses(public)[0]
        self.wallet.send_to(from_node=node, scriptPubKey=address_to_scriptpubkey(address), amount=COIN)
        self.generate(self.wallet, 1)
        options = {"fee_rate": 1, "changeAddress": self.wallet.get_address()}
        inputs = []
        if wrapper == "taproot":
            # TRDescriptor currently assumes key-path satisfaction. Supply the
            # existing input weight override for this script-only spend; the
            # wallet must still add the new policy cost to that physical weight.
            coin = wallet.listunspent()[0]
            script_size = 4 * 34 + 2
            input_weight = 41 * 4 + 1 + 66 + 3 + 1 + script_size + 1 + 33
            inputs = [{"txid": coin["txid"], "vout": coin["vout"], "weight": input_weight}]
        funded = wallet.walletcreatefundedpsbt(inputs, [{self.wallet.get_address(): Decimal("0.5")}],
                                             options=options)
        signed = wallet.walletprocesspsbt(funded["psbt"])
        assert_equal(signed["complete"], True)
        analyzed = node.analyzepsbt(signed["psbt"])
        final = node.finalizepsbt(signed["psbt"])
        result = node.testmempoolaccept([final["hex"]])[0]
        assert_equal(result["allowed"], True)
        assert_equal(analyzed["estimated_vsize"], result["vsize"])
        penalty = 72 if wrapper == "taproot" else 75
        assert funded["fee"] * COIN >= result["vsize"] + penalty, (wrapper, funded["fee"], result["vsize"], analyzed)
        node.sendrawtransaction(final["hex"])
        self.generate(self.wallet, 1)

    def check_package(self, zero_fee_parent=False):
        case = self.fund("witness", 15, payload=True)
        if zero_fee_parent:
            case.update(version=3, anchor=True)
        parent_fee = 0 if zero_fee_parent else 10000
        parent = self.spend(case, fee=parent_fee)
        child = CTransaction()
        child.version = parent.version
        child.vin = [CTxIn(COutPoint(int(parent.hash, 16), 0), nSequence=0xfffffffd)]
        child.vout = [CTxOut(parent.vout[0].nValue - 10000, address_to_scriptpubkey(self.wallet.get_address()))]
        child.wit.vtxinwit = [CTxInWitness()]
        if zero_fee_parent:
            child.vin.append(CTxIn(COutPoint(int(parent.hash, 16), 1), nSequence=0xfffffffd))
            child.wit.vtxinwit.append(CTxInWitness())
        hash_type = SIGHASH_ALL | SIGHASH_UNIFIED
        pubkey = self.keys[0].get_pubkey().get_bytes()
        sighash = UnifiedSignatureHash(key_to_p2pkh_script(pubkey), child, 0, hash_type, parent.vout, True)
        child.wit.vtxinwit[0].scriptWitness.stack = [self.keys[0].sign_ecdsa(sighash) + bytes([hash_type]), pubkey]
        child.rehash()
        raw = [tx.serialize().hex() for tx in (parent, child)]
        if not zero_fee_parent:
            results = self.nodes[0].testmempoolaccept(raw)
            assert all(result["allowed"] for result in results), results
            assert_equal(results[0]["vsize"], parent.get_vsize())
        assert_equal(self.nodes[0].submitpackage(raw)["package_msg"], "success")
        assert_equal(self.nodes[0].getmempoolentry(parent.hash)["vsize"], parent.get_vsize())
        assert_equal(self.nodes[0].getmempoolentry(parent.hash)["fees"]["modified"], Decimal(parent_fee - 347) / COIN)
        self.generate(self.wallet, 1, sync_fun=self.sync_blocks)

    def run_test(self):
        self.keys = []
        for i in range(16):
            key = ECKey()
            key.set((100 + i).to_bytes(32, "big"), True)
            self.keys.append(key)
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 110)

        self.log.info("BPUB-shaped payloads remain spendable at the adjusted fee")
        bpub = self.fund("witness", 15, payload=True)
        _, results = self.check_cost(bpub, 14 * 33 * 3)
        low = self.spend(bpub, fee=results[1]["vsize"] + 5)
        assert_equal(self.nodes[1].testmempoolaccept([low.serialize().hex()])[0]["allowed"], True)
        rejected = self.nodes[0].testmempoolaccept([low.serialize().hex()])[0]
        assert_equal(rejected["reject-reason"], "min relay fee not met")
        self.log.info(f"BPUB example: vsize remains {results[0]['vsize']}; modified fee is reduced by 347 sat")

        self.log.info("Matching wallet scripts have the same cost; other thresholds and wrappers retain their behavior")
        for kind, n, threshold, timelock in [
            ("witness", 1, 1, False), ("witness", 4, 1, False),
            ("witness", 3, 2, False), ("witness", 15, 2, False),
            ("nested", 15, 1, False), ("legacy", 4, 1, False),
            ("taproot", 15, 1, False), ("taproot", 3, 2, False),
            ("witness", 4, 1, True),
        ]:
            case = self.fund(kind, n, threshold, timelock=timelock)
            extra = (n - 1) * (32 if kind == "taproot" else 33) * 3 if threshold == 1 and kind != "legacy" and not timelock else 0
            self.check_cost(case, extra)

        self.log.info("A transaction below the new relay fee remains valid in a block")
        self.nodes[1].sendrawtransaction(low.serialize().hex())
        self.generatetoaddress(self.nodes[1], 1, self.wallet.get_address(), sync_fun=self.sync_blocks)
        assert_equal(self.nodes[0].gettxout(bpub["outpoint"].hash.to_bytes(32, "big").hex(), bpub["outpoint"].n), None)

        self.log.info("Package admission uses the same policy cost")
        self.check_package()

        self.log.info("The fee penalty does not reduce the TRUC child size allowance")
        script = CScript([1] + [key.get_pubkey().get_bytes() for key in self.keys[:15]] + [15, OP_CHECKMULTISIG])
        parent = self.wallet.create_self_transfer()["tx"]
        parent.version = 3
        parent.vout[0].scriptPubKey = script_to_p2wsh_script(script)
        parent.rehash()
        case = dict(kind="witness", n=15, threshold=1, script=script,
                    utxo=parent.vout[0], outpoint=COutPoint(int(parent.hash, 16), 0),
                    version=3, sequence=0, padding_outputs=20)
        child = self.spend(case)
        # Charging this as extra vsize would exceed TRUC's 1000-vbyte child
        # limit even though the original transaction fits.
        assert child.get_vsize() < 1000 < child.get_vsize() + 347
        raw = [tx.serialize().hex() for tx in (parent, child)]
        results = self.nodes[0].testmempoolaccept(raw)
        assert all(result["allowed"] for result in results), results
        assert_equal(results[1]["vsize"], child.get_vsize())
        assert_equal(self.nodes[0].submitpackage(raw)["package_msg"], "success")
        self.generate(self.wallet, 1)

        self.log.info("Descriptor wallets fund and spend under the default cost")
        for wrapper in ("witness", "nested", "taproot"):
            self.check_wallet(wrapper)

        self.log.info("The child can pay the penalty for a zero-fee ephemeral parent")
        # Isolate this penalty from the existing automatic dust-fee penalty.
        self.restart_node(0, self.extra_args[0] + ["-subdustfeepenalty=0"])
        self.connect_nodes(0, 1)
        self.check_package(zero_fee_parent=True)


if __name__ == '__main__':
    OneOfNCostTest(__file__).main()
