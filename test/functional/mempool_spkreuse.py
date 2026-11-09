#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Script reuse is enforced inside a package, and the reuse index survives package updates."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.crypto.ripemd160 import ripemd160
from test_framework.messages import (
    CInv,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    gen_return_txouts,
)
from test_framework.wallet import MiniWallet


def fee_for(rate, vsize):
    """Satoshi fee for a feerate in BTC/kvB. Rounds up."""
    return int(Decimal(rate) * COIN * vsize / 1000) + 1


def amount_sat(utxo):
    if "sat" in utxo:
        return utxo["sat"]
    return int(utxo["value"] * COIN)


def utxo_from(tx, vout):
    return {
        "txid": tx.rehash(),
        "vout": vout,
        "value": Decimal(tx.vout[vout].nValue) / COIN,
        "sat": tx.vout[vout].nValue,
    }


def sign_inputs(tx, wallets):
    assert_equal(len(wallets), len(tx.vin))
    tx.wit.vtxinwit = [CTxInWitness() for _ in wallets]
    for i, wallet in enumerate(wallets):
        assert_equal(len(wallet._taproot_info.leaves), 1)
        leaf_info = list(wallet._taproot_info.leaves.values())[0]
        tx.wit.vtxinwit[i].scriptWitness.stack = [
            leaf_info.script,
            bytes([leaf_info.version | wallet._taproot_info.negflag]) + wallet._taproot_info.internal_pubkey,
        ]
    tx.rehash()


def make_tx(signers, inputs, scripts, fee, version=2):
    total_in = sum(amount_sat(u) for u in inputs)
    total_out = total_in - fee
    assert total_out > len(scripts) * 1000
    base, rem = divmod(total_out, len(scripts))
    amounts = [base] * len(scripts)
    amounts[0] += rem
    tx = CTransaction()
    tx.version = version
    tx.vin = [CTxIn(COutPoint(int(u["txid"], 16), u["vout"])) for u in inputs]
    tx.vout = [CTxOut(amount, script) for amount, script in zip(amounts, scripts)]
    sign_inputs(tx, signers)
    return tx


def make_at_rate(signers, inputs, scripts, rate, version=2, extra=0):
    probe = make_tx(signers, inputs, scripts, fee=max(len(scripts), 1) * 5000, version=version)
    return make_tx(signers, inputs, scripts, fee_for(rate, probe.get_vsize()) + extra, version=version)


def tx_fee(tx, inputs):
    return sum(amount_sat(u) for u in inputs) - sum(out.nValue for out in tx.vout)


class SpkReusePackageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [
                "-spkreuse=conflict",
                "-maxmempool=5",
                "-datacarriersize=100000",
                "-mempooltruc=enforce",
            ],
            [
                "-spkreuse=allow",
                "-mempooltruc=enforce",
            ],
        ]
        self.supports_cli = False

    def setup_network(self):
        self.setup_nodes()

    def fresh(self, node, tag):
        return MiniWallet(node, tag_name=tag)

    def fund_distinct_inputs(self, count):
        """Confirmed outputs with distinct scripts.

        Once one output of a script is spent in the mempool, every other output of that script conflicts with it.
        """
        node = self.nodes[0]
        self.fund.rescan_utxos()
        self.inputs = [self.fresh(node, f"in-{i}") for i in range(count)]
        relay, _pool = self.rates()
        tx = make_at_rate(
            [self.fund],
            [self.fund.get_utxo()],
            [wallet.get_output_script() for wallet in self.inputs],
            relay,
            extra=2000,
        )
        node.sendrawtransaction(tx.serialize().hex(), 0)
        self.generate(node, 1, sync_fun=self.no_op)
        for wallet in self.inputs:
            wallet.rescan_utxos(include_mempool=False)

    def take_input(self):
        wallet = self.inputs.pop()
        return wallet, wallet.get_utxo()

    def run_test(self):
        self.test_allow_accepts_reuse()
        self.prepare_conflict_coins()
        self.test_direct_package_rules()
        self.fund_distinct_inputs(24)
        self.log.info("Fill the mempool so a parent can clear the relay fee and miss the mempool fee")
        self.fill_conflict_mempool()
        assert_greater_than(self.nodes[0].getmempoolinfo()["mempoolminfee"], self.nodes[0].getmempoolinfo()["minrelaytxfee"])
        self.confirmed_b.rescan_utxos()
        for wallet in self.inputs:
            wallet.rescan_utxos(include_mempool=False)
        self.test_low_fee_package_rejected_and_index_clear()
        self.test_low_fee_package_without_reuse_keeps_index()
        self.test_high_fee_parent_rejects_reusing_child()
        self.test_ancestor_spend_then_create()
        self.test_two_parents()
        self.test_truc_package()
        self.test_parent_already_in_mempool()
        self.test_package_rbf_with_reuse()
        self.test_p2p_child_then_parent()
        self.test_p2p_parent_then_child()

    def test_allow_accepts_reuse(self):
        node = self.nodes[1]
        fund = MiniWallet(node)
        self.generate(fund, 2, sync_fun=self.no_op)
        self.generate(node, COINBASE_MATURITY, sync_fun=self.no_op)
        reused = self.fresh(node, "allow-reused")
        spent = self.fresh(node, "allow-spent")
        rate = node.getmempoolinfo()["mempoolminfee"]

        self.log.info("With spkreuse=allow, a 0-fee TRUC parent and a child that pays to the parent's other script are accepted together")
        parent = make_tx([fund], [fund.get_utxo()], [spent.get_output_script(), reused.get_output_script()], fee=0, version=3)
        child_probe = make_tx([spent], [utxo_from(parent, 0)], [reused.get_output_script()], fee=5000, version=3)
        child_fee = fee_for(rate, parent.get_vsize() + child_probe.get_vsize()) + 2000
        child = make_tx([spent], [utxo_from(parent, 0)], [reused.get_output_script()], fee=child_fee, version=3)
        res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert parent.rehash() in node.getrawmempool()
        assert child.rehash() in node.getrawmempool()

        self.log.info("With spkreuse=allow, a child submitted after its parent may pay to a script the parent created")
        parent_hi = make_at_rate([fund], [fund.get_utxo()], [spent.get_output_script(), reused.get_output_script()], rate, extra=2000)
        node.sendrawtransaction(parent_hi.serialize().hex(), 0)
        child_hi = make_at_rate([spent], [utxo_from(parent_hi, 0)], [reused.get_output_script()], rate, extra=2000)
        node.sendrawtransaction(child_hi.serialize().hex(), 0)
        assert child_hi.rehash() in node.getrawmempool()

    def prepare_conflict_coins(self):
        node = self.nodes[0]
        self.fund = MiniWallet(node)
        self.confirmed_b = MiniWallet(node, tag_name="confirmed-b")
        # One output per coinbase. A single transaction cannot pay the same script twice.
        self.generate(self.fund, 30, sync_fun=self.no_op)
        self.generate(self.confirmed_b, 8, sync_fun=self.no_op)
        self.generate(node, COINBASE_MATURITY, sync_fun=self.no_op)
        assert_greater_than(len(self.fund.get_utxos(mark_as_spent=False)), 20)
        assert_greater_than(len(self.confirmed_b.get_utxos(mark_as_spent=False)), 5)

    def fill_conflict_mempool(self):
        """Same shape as fill_mempool, but the filler transactions may pay their own script.

        -spkreuse=conflict rejects that as change, and rejects the repeated OP_RETURN as twin outputs.
        Ignoring txn-spk-reused on these fillers leaves the reuse index empty.
        """
        node = self.nodes[0]
        txouts = gen_return_txouts()
        minrelayfee = node.getnetworkinfo()["relayfee"]
        num_of_batches = 75
        ephemeral = MiniWallet(node, tag_name="fill_mempool_ephemeral_wallet")
        self.generate(ephemeral, 1 + num_of_batches, sync_fun=self.no_op)
        self.generate(node, COINBASE_MATURITY - 1, sync_fun=self.no_op)
        confirmed = [ephemeral.get_utxo(confirmed_only=True) for _ in range(num_of_batches + 1)]
        assert_equal(len(confirmed), num_of_batches + 1)

        probe = ephemeral.create_self_transfer(utxo_to_spend=confirmed[0])["tx"]
        probe.vout.extend(txouts)
        probed = node.testmempoolaccept([probe.serialize().hex()], 0, ["txn-spk-reused"])[0]
        assert probed["allowed"], probed
        target_tx_usage = 68064
        if probed["usage"] > target_tx_usage:
            excess_outputs = len(txouts) - (target_tx_usage * len(txouts) // probed["usage"])
            txouts = txouts[excess_outputs:]

        def send_filler(utxo, fee):
            tx = ephemeral.create_self_transfer(utxo_to_spend=utxo, fee=fee)["tx"]
            tx.vout.extend(txouts)
            return node.sendrawtransaction(tx.serialize().hex(), 0, 0, ["txn-spk-reused"])

        small = ephemeral.create_self_transfer(utxo_to_spend=confirmed.pop(0), fee_rate=minrelayfee)["tx"]
        evicted = node.sendrawtransaction(small.serialize().hex(), 0, 0, ["txn-spk-reused"])
        base_fee = minrelayfee * 130
        batch_fees = [(i + 1) * base_fee for i in range(num_of_batches)]
        for fee in batch_fees[:-3]:
            send_filler(confirmed.pop(0), fee)
        assert_equal(node.getmempoolinfo()["mempoolminfee"], minrelayfee)
        for fee in batch_fees[-3:]:
            send_filler(confirmed.pop(0), fee)
        assert_greater_than(num_of_batches, len(node.getrawmempool()))
        assert evicted not in node.getrawmempool()
        assert_equal(node.getmempoolinfo()["minrelaytxfee"], minrelayfee)
        assert_greater_than(node.getmempoolinfo()["mempoolminfee"], minrelayfee)

    def rates(self):
        info = self.nodes[0].getmempoolinfo()
        return info["minrelaytxfee"], info["mempoolminfee"]

    def test_direct_package_rules(self):
        """testmempoolaccept evaluates every member before any of them enters the mempool."""
        node = self.nodes[0]
        relay, _pool = self.rates()
        fund_utxo = self.fund.get_utxo()
        fund_utxo_2 = self.fund.get_utxo()
        b_utxo = self.confirmed_b.get_utxo()
        b_utxo_2 = self.confirmed_b.get_utxo()
        script_a = self.fresh(node, "direct-a")
        script_b = self.fresh(node, "direct-b")
        script_c = self.fresh(node, "direct-c")
        c1 = self.fresh(node, "direct-c1")
        c2 = self.fresh(node, "direct-c2")
        dest = self.fresh(node, "direct-dest")

        self.log.info("A package whose child pays to a script its parent creates is rejected before either is admitted")
        parent = make_at_rate([self.fund], [fund_utxo], [script_a.get_output_script(), script_b.get_output_script()], relay, extra=2000)
        child = make_at_rate([script_a], [utxo_from(parent, 0)], [script_b.get_output_script()], relay, extra=2000)
        self.assert_direct_rejected([parent, child])
        self.assert_direct_rejected([parent, child], ignore_rejects=["txn-spk-reused-in-package"])
        self.assert_direct_allowed([parent, child], ["txn-spk-reused"])
        self.assert_direct_allowed([parent, child], ["txn-spk-reused-chained"])

        self.log.info("A package whose child only spends the output its parent created is accepted")
        clean_child = make_at_rate([script_a], [utxo_from(parent, 0)], [script_c.get_output_script()], relay, extra=2000)
        accepted = node.testmempoolaccept([parent.serialize().hex(), clean_child.serialize().hex()], 0)
        assert accepted[0]["allowed"]
        assert accepted[1]["allowed"]

        self.log.info("A child that pays to a script its parent spent is rejected")
        spender = make_at_rate([self.confirmed_b], [b_utxo], [script_a.get_output_script()], relay, extra=2000)
        creator = make_at_rate([script_a], [utxo_from(spender, 0)], [self.confirmed_b.get_output_script()], relay, extra=2000)
        self.assert_direct_rejected([spender, creator])
        self.assert_direct_allowed([spender, creator], ["txn-spk-reused-chained"])

        self.log.info("Two parents that create one script are rejected, and so are two parents that spend one script")
        p_create_1 = make_at_rate([self.fund], [fund_utxo], [script_b.get_output_script(), c1.get_output_script()], relay, extra=2000)
        p_create_2 = make_at_rate([self.fund], [fund_utxo_2], [script_b.get_output_script(), c2.get_output_script()], relay, extra=2000)
        child_creates = make_at_rate(
            [c1, c2],
            [utxo_from(p_create_1, 1), utxo_from(p_create_2, 1)],
            [dest.get_output_script()],
            relay,
            extra=2000,
        )
        self.assert_direct_rejected([p_create_1, p_create_2, child_creates], "txn-spk-reused-in-package")
        self.assert_direct_rejected([p_create_1, p_create_2, child_creates], "txn-spk-reused-in-package", ["txn-spk-reused-chained"])
        self.assert_direct_allowed([p_create_1, p_create_2, child_creates], ["txn-spk-reused-in-package"])

        p_spend_1 = make_at_rate([self.confirmed_b], [b_utxo], [c1.get_output_script()], relay, extra=2000)
        p_spend_2 = make_at_rate([self.confirmed_b], [b_utxo_2], [c2.get_output_script()], relay, extra=2000)
        child_spends = make_at_rate(
            [c1, c2],
            [utxo_from(p_spend_1, 0), utxo_from(p_spend_2, 0)],
            [dest.get_output_script()],
            relay,
            extra=2000,
        )
        self.assert_direct_rejected([p_spend_1, p_spend_2, child_spends], "txn-spk-reused-in-package")
        self.assert_direct_rejected([p_spend_1, p_spend_2, child_spends], "txn-spk-reused-in-package", ["txn-spk-reused-chained"])
        self.assert_direct_allowed([p_spend_1, p_spend_2, child_spends], ["txn-spk-reused-in-package"])

        self.log.info("Ignoring the in-package reject still rejects a creator that descends from either spender")
        for spend_parent, spend_wallet in ((p_spend_1, c1), (p_spend_2, c2)):
            recreate = make_at_rate([spend_wallet], [utxo_from(spend_parent, 0)], [self.confirmed_b.get_output_script()], relay, extra=2000)
            self.assert_direct_rejected([p_spend_1, p_spend_2, recreate], ignore_rejects=["txn-spk-reused-in-package"])

        self.log.info("A creator with an unrelated creator and an ancestor spender of one script is reported as chained first")
        other_creator = make_at_rate([self.fund], [fund_utxo], [self.confirmed_b.get_output_script()], relay, extra=2000)
        recreate = make_at_rate([c1], [utxo_from(p_spend_1, 0)], [self.confirmed_b.get_output_script()], relay, extra=2000)
        package = [other_creator, p_spend_1, recreate]
        self.assert_direct_rejected(package)
        self.assert_direct_rejected(package, "txn-spk-reused-in-package", ["txn-spk-reused-chained"])
        self.assert_direct_allowed(package, ["txn-spk-reused-chained", "txn-spk-reused-in-package"])

        self.log.info("Chained reuse is reported first even when an in-package reuse is on a script the node checks earlier")
        # The node walks a member's scripts in RIPEMD160 order, so put the in-package script first.
        early, late = sorted((self.fresh(node, "order-1"), self.fresh(node, "order-2")), key=lambda w: ripemd160(bytes(w.get_output_script())))
        order_w = self.fresh(node, "order-w")
        unrelated = make_at_rate([self.fund], [fund_utxo], [early.get_output_script()], relay, extra=2000)
        order_parent = make_at_rate([self.confirmed_b], [b_utxo], [late.get_output_script(), order_w.get_output_script()], relay, extra=2000)
        order_child = make_at_rate([order_w], [utxo_from(order_parent, 1)], [early.get_output_script(), late.get_output_script()], relay, extra=2000)
        package = [unrelated, order_parent, order_child]
        self.assert_direct_rejected(package)
        self.assert_direct_rejected(package, "txn-spk-reused-in-package", ["txn-spk-reused-chained"])

        self.log.info("With txn-spk-reused-change ignored, a member that both spends and pays to a script is checked on both sides")
        b_utxo_3 = self.confirmed_b.get_utxo()
        c3 = self.fresh(node, "direct-c3")
        change = ["txn-spk-reused-change"]
        both = make_at_rate([self.confirmed_b], [b_utxo_3], [self.confirmed_b.get_output_script(), c3.get_output_script()], relay, extra=2000)
        both_child = make_at_rate([c3], [utxo_from(both, 1)], [dest.get_output_script()], relay, extra=2000)
        self.assert_direct_allowed([both, both_child], change)
        beside = make_at_rate([c1, c3], [utxo_from(p_spend_1, 0), utxo_from(both, 1)], [dest.get_output_script()], relay, extra=2000)
        self.assert_direct_rejected([p_spend_1, both, beside], "txn-spk-reused-in-package", change)
        both_desc = make_at_rate([c1, self.confirmed_b], [utxo_from(p_spend_1, 0), b_utxo_3], [self.confirmed_b.get_output_script()], relay, extra=2000)
        self.assert_direct_rejected([p_spend_1, both_desc], ignore_rejects=change)

        self.log.info("Ignoring the in-package reject still rejects a creator that descends from either creator")
        for create_parent, create_wallet in ((p_create_1, c1), (p_create_2, c2)):
            recreate = make_at_rate([create_wallet], [utxo_from(create_parent, 1)], [script_b.get_output_script()], relay, extra=2000)
            self.assert_direct_rejected([p_create_1, p_create_2, recreate], ignore_rejects=["txn-spk-reused-in-package"])

        self.log.info("One parent creating a script and another spending an older output of it is accepted in either order")
        p_creator = make_at_rate([self.fund], [fund_utxo_2], [self.confirmed_b.get_output_script(), c1.get_output_script()], relay, extra=2000)
        p_spender = make_at_rate([self.confirmed_b], [b_utxo_2], [c2.get_output_script()], relay, extra=2000)
        child_mixed = make_at_rate(
            [c1, c2],
            [utxo_from(p_creator, 1), utxo_from(p_spender, 0)],
            [dest.get_output_script()],
            relay,
            extra=2000,
        )
        for package in ([p_creator, p_spender, child_mixed], [p_spender, p_creator, child_mixed]):
            res = node.testmempoolaccept([tx.serialize().hex() for tx in package], 0)
            assert res[0]["allowed"] and res[1]["allowed"] and res[2]["allowed"]

        self.log.info("A grandchild that pays to a script its grandparent spent is rejected")
        grand = make_at_rate([self.confirmed_b], [b_utxo], [script_a.get_output_script()], relay, extra=2000)
        mid = make_at_rate([script_a], [utxo_from(grand, 0)], [script_c.get_output_script()], relay, extra=2000)
        grand_child = make_at_rate([script_c], [utxo_from(mid, 0)], [self.confirmed_b.get_output_script()], relay, extra=2000)
        self.assert_direct_rejected([grand, mid, grand_child])

    def assert_direct_rejected(self, txs, reason="txn-spk-reused-chained", ignore_rejects=None):
        res = self.nodes[0].testmempoolaccept([tx.serialize().hex() for tx in txs], 0, ignore_rejects or [])
        assert_equal(len(res), len(txs))
        for entry in res:
            self.assert_package_reason(entry.get("package-error", entry), reason, txs)
            assert "allowed" not in entry

    def assert_package_reason(self, msg, reason, txs):
        assert msg.startswith(f"{reason}, "), msg
        assert msg.removeprefix(f"{reason}, ") in [tx.getwtxid() for tx in txs[1:]], msg

    def assert_direct_allowed(self, txs, ignore_rejects):
        res = self.nodes[0].testmempoolaccept([tx.serialize().hex() for tx in txs], 0, ignore_rejects)
        assert_equal([entry["allowed"] for entry in res], [True] * len(txs))

    def assert_submit_rejected(self, txs, reason="txn-spk-reused-chained"):
        res = self.nodes[0].submitpackage([tx.serialize().hex() for tx in txs], 0)
        self.assert_package_reason(res["package_msg"], reason, txs)
        mempool = self.nodes[0].getrawmempool()
        for tx in txs:
            assert tx.rehash() not in mempool
        return res

    def below_pool_parent(self, signers, inputs, scripts, version=2):
        relay, pool = self.rates()
        parent = make_at_rate(signers, inputs, scripts, relay, version=version)
        assert tx_fee(parent, inputs) < fee_for(pool, parent.get_vsize())
        return parent

    def child_paying_for(self, parents, spend_wallets, vouts, scripts, version=2):
        _relay, pool = self.rates()
        child_in = [utxo_from(parent, vout) for parent, vout in zip(parents, vouts)]
        probe = make_tx(spend_wallets, child_in, scripts, fee=5000, version=version)
        parent_vsize = sum(parent.get_vsize() for parent in parents)
        child_fee = fee_for(pool, parent_vsize + probe.get_vsize()) * 2 + 5000
        return make_tx(spend_wallets, child_in, scripts, fee=child_fee, version=version)

    def test_low_fee_package_rejected_and_index_clear(self):
        node = self.nodes[0]
        self.log.info("submitpackage of a below-mempool-fee parent and a child that reuses its script is rejected, and the script stays free")
        script_a = self.fresh(node, "low-a")
        script_b = self.fresh(node, "low-b")
        signer, utxo = self.take_input()
        parent = self.below_pool_parent(
            [signer], [utxo], [script_a.get_output_script(), script_b.get_output_script()],
        )
        child = self.child_paying_for([parent], [script_a], [0], [script_b.get_output_script()])
        self.assert_submit_rejected([parent, child])
        _relay, pool = self.rates()
        pay_signer, pay_utxo = self.take_input()
        payment = make_at_rate([pay_signer], [pay_utxo], [script_b.get_output_script()], pool, extra=2000)
        node.sendrawtransaction(payment.serialize().hex(), 0)
        assert payment.rehash() in node.getrawmempool()

    def test_low_fee_package_without_reuse_keeps_index(self):
        node = self.nodes[0]
        self.log.info("A package that only spends what its parent created is accepted, and replacing the child leaves the parent's script claimed")
        script_a = self.fresh(node, "keep-a")
        script_b = self.fresh(node, "keep-b")
        script_c = self.fresh(node, "keep-c")
        script_d = self.fresh(node, "keep-d")
        signer, utxo = self.take_input()
        parent = self.below_pool_parent(
            [signer], [utxo], [script_a.get_output_script(), script_b.get_output_script()],
        )
        child = self.child_paying_for([parent], [script_a], [0], [script_c.get_output_script()])
        res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert parent.rehash() in node.getrawmempool()
        assert child.rehash() in node.getrawmempool()

        _relay, pool = self.rates()
        replacement_fee = tx_fee(child, [utxo_from(parent, 0)]) + fee_for(pool, child.get_vsize()) + 5000
        replacement = make_tx([script_a], [utxo_from(parent, 0)], [script_d.get_output_script()], fee=replacement_fee)
        node.sendrawtransaction(replacement.serialize().hex(), 0)
        assert child.rehash() not in node.getrawmempool()
        assert replacement.rehash() in node.getrawmempool()
        assert parent.rehash() in node.getrawmempool()

        chal_signer, chal_utxo = self.take_input()
        challenger = make_at_rate([chal_signer], [chal_utxo], [script_b.get_output_script()], pool, extra=2000)
        assert_raises_rpc_error(-26, "insufficient fee", node.sendrawtransaction, challenger.serialize().hex(), 0)
        assert challenger.rehash() not in node.getrawmempool()
        assert parent.rehash() in node.getrawmempool()

    def test_high_fee_parent_rejects_reusing_child(self):
        node = self.nodes[0]
        self.log.info("A child sent after a parent that already pays the mempool fee is still rejected")
        _relay, pool = self.rates()
        script_a = self.fresh(node, "seq-a")
        script_b = self.fresh(node, "seq-b")
        signer, utxo = self.take_input()
        parent = make_at_rate(
            [signer], [utxo], [script_a.get_output_script(), script_b.get_output_script()], pool, extra=5000,
        )
        child = make_at_rate([script_a], [utxo_from(parent, 0)], [script_b.get_output_script()], pool, extra=5000)
        res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()], 0)
        assert_equal(res["package_msg"], "transaction failed")
        assert_equal(res["tx-results"][child.getwtxid()]["error"], "txn-spk-reused-chained")
        assert parent.rehash() in node.getrawmempool()
        assert child.rehash() not in node.getrawmempool()

    def test_ancestor_spend_then_create(self):
        node = self.nodes[0]
        self.log.info("A below-mempool-fee parent that spends a script, packaged with a child that pays to it, is rejected")
        script_a = self.fresh(node, "spend-then-a")
        b_utxo = self.confirmed_b.get_utxo()
        parent = self.below_pool_parent([self.confirmed_b], [b_utxo], [script_a.get_output_script()])
        child = self.child_paying_for([parent], [script_a], [0], [self.confirmed_b.get_output_script()])
        self.assert_submit_rejected([parent, child])

    def test_two_parents(self):
        node = self.nodes[0]
        relay, pool = self.rates()
        script_b = self.fresh(node, "two-b")
        c1 = self.fresh(node, "two-c1")
        c2 = self.fresh(node, "two-c2")
        dest = self.fresh(node, "two-dest")

        self.log.info("Two below-mempool-fee parents that create the same script are rejected")
        w1, u1 = self.take_input()
        w2, u2 = self.take_input()
        p1 = make_at_rate([w1], [u1], [script_b.get_output_script(), c1.get_output_script()], relay)
        p2 = make_at_rate([w2], [u2], [script_b.get_output_script(), c2.get_output_script()], relay)
        assert tx_fee(p1, [u1]) < fee_for(pool, p1.get_vsize())
        assert tx_fee(p2, [u2]) < fee_for(pool, p2.get_vsize())
        child = self.child_paying_for([p1, p2], [c1, c2], [1, 1], [dest.get_output_script()])
        self.assert_submit_rejected([p1, p2, child], "txn-spk-reused-in-package")

        self.log.info("Two below-mempool-fee parents that spend the same script are rejected")
        b1 = self.confirmed_b.get_utxo()
        b2 = self.confirmed_b.get_utxo()
        s1 = make_at_rate([self.confirmed_b], [b1], [c1.get_output_script()], relay)
        s2 = make_at_rate([self.confirmed_b], [b2], [c2.get_output_script()], relay)
        assert tx_fee(s1, [b1]) < fee_for(pool, s1.get_vsize())
        child_spend = self.child_paying_for([s1, s2], [c1, c2], [0, 0], [dest.get_output_script()])
        self.assert_submit_rejected([s1, s2, child_spend], "txn-spk-reused-in-package")

        self.log.info("A parent that creates a script and a parent that spends an older output of it are accepted together")
        mc1 = self.fresh(node, "mixed-c1")
        mc2 = self.fresh(node, "mixed-c2")
        creator_wallet, creator_in = self.take_input()
        spender_in = self.confirmed_b.get_utxo()
        creator = make_at_rate([creator_wallet], [creator_in], [self.confirmed_b.get_output_script(), mc1.get_output_script()], relay)
        spender = make_at_rate([self.confirmed_b], [spender_in], [mc2.get_output_script()], relay)
        assert tx_fee(creator, [creator_in]) < fee_for(pool, creator.get_vsize())
        mixed_child = self.child_paying_for([creator, spender], [mc1, mc2], [1, 0], [dest.get_output_script()])
        res = node.submitpackage([creator.serialize().hex(), spender.serialize().hex(), mixed_child.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert creator.rehash() in node.getrawmempool()
        assert spender.rehash() in node.getrawmempool()
        chal_signer, chal_utxo = self.take_input()
        challenger = make_at_rate([chal_signer], [chal_utxo], [self.confirmed_b.get_output_script()], pool, extra=2000)
        assert_raises_rpc_error(-26, "insufficient fee", node.sendrawtransaction, challenger.serialize().hex(), 0)
        assert creator.rehash() in node.getrawmempool()

        self.log.info("The same pair is accepted with the spender first, and the creator's script stays claimed")
        sc1 = self.fresh(node, "spender-first-c1")
        sc2 = self.fresh(node, "spender-first-c2")
        sdest = self.fresh(node, "spender-first-dest")
        reused_wallet, reused_in = self.take_input()
        creator_wallet, creator_in = self.take_input()
        spender = make_at_rate([reused_wallet], [reused_in], [sc2.get_output_script()], relay)
        creator = make_at_rate([creator_wallet], [creator_in], [reused_wallet.get_output_script(), sc1.get_output_script()], relay)
        assert tx_fee(spender, [reused_in]) < fee_for(pool, spender.get_vsize())
        assert tx_fee(creator, [creator_in]) < fee_for(pool, creator.get_vsize())
        mixed_child = self.child_paying_for([spender, creator], [sc2, sc1], [0, 1], [sdest.get_output_script()])
        res = node.submitpackage([spender.serialize().hex(), creator.serialize().hex(), mixed_child.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert spender.rehash() in node.getrawmempool()
        assert creator.rehash() in node.getrawmempool()
        chal_signer, chal_utxo = self.take_input()
        challenger = make_at_rate([chal_signer], [chal_utxo], [reused_wallet.get_output_script()], pool, extra=2000)
        assert_raises_rpc_error(-26, "insufficient fee", node.sendrawtransaction, challenger.serialize().hex(), 0)
        assert creator.rehash() in node.getrawmempool()

    def test_parent_already_in_mempool(self):
        node = self.nodes[0]
        _relay, pool = self.rates()
        self.log.info("A package whose first parent is already in the mempool is still checked between the remaining members")
        p_out = self.fresh(node, "dedup-p")
        q_out = self.fresh(node, "dedup-q")
        reused = self.fresh(node, "dedup-x")
        p_signer, p_utxo = self.take_input()
        in_pool = make_at_rate([p_signer], [p_utxo], [p_out.get_output_script()], pool, extra=2000)
        node.sendrawtransaction(in_pool.serialize().hex(), 0)
        q_signer, q_utxo = self.take_input()
        low = self.below_pool_parent([q_signer], [q_utxo], [q_out.get_output_script(), reused.get_output_script()])
        child = self.child_paying_for([in_pool, low], [p_out, q_out], [0, 0], [reused.get_output_script()])
        res = node.submitpackage([tx.serialize().hex() for tx in (in_pool, low, child)], 0)
        self.assert_package_reason(res["package_msg"], "txn-spk-reused-chained", [in_pool, low, child])
        mempool = node.getrawmempool()
        assert in_pool.rehash() in mempool
        assert low.rehash() not in mempool
        assert child.rehash() not in mempool

    def test_package_rbf_with_reuse(self):
        node = self.nodes[0]
        _relay, pool = self.rates()
        self.log.info("A package that replaces a mempool transaction through script reuse is still checked between its members")
        shared = self.fresh(node, "rbf-y")
        script_a = self.fresh(node, "rbf-a")
        script_b = self.fresh(node, "rbf-b")
        script_d = self.fresh(node, "rbf-d")
        m_signer, m_utxo = self.take_input()
        in_pool = make_at_rate([m_signer], [m_utxo], [shared.get_output_script()], pool, extra=2000)
        node.sendrawtransaction(in_pool.serialize().hex(), 0)
        p_signer, p_utxo = self.take_input()
        parent = self.below_pool_parent(
            [p_signer], [p_utxo], [shared.get_output_script(), script_a.get_output_script(), script_b.get_output_script()],
        )
        replace_fee = tx_fee(in_pool, [m_utxo]) * 20
        bad = make_tx([script_a], [utxo_from(parent, 1)], [script_b.get_output_script()], fee=replace_fee)
        self.assert_submit_rejected([parent, bad])
        assert in_pool.rehash() in node.getrawmempool()

        self.log.info("The same parent with a child that does not reuse a script replaces the mempool transaction")
        good = make_tx([script_a], [utxo_from(parent, 1)], [script_d.get_output_script()], fee=replace_fee)
        res = node.submitpackage([parent.serialize().hex(), good.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert_equal(res["replaced-transactions"], [in_pool.rehash()])
        mempool = node.getrawmempool()
        assert in_pool.rehash() not in mempool
        assert parent.rehash() in mempool
        assert good.rehash() in mempool

    def test_truc_package(self):
        node = self.nodes[0]
        _relay, pool = self.rates()
        self.log.info("A 0-fee TRUC package is accepted when the child does not reuse a script, and rejected when it does")
        ok_a = self.fresh(node, "truc-ok-a")
        ok_c = self.fresh(node, "truc-ok-c")
        ok_signer, ok_utxo = self.take_input()
        parent_ok = make_tx([ok_signer], [ok_utxo], [ok_a.get_output_script()], fee=0, version=3)
        child_ok = self.child_paying_for([parent_ok], [ok_a], [0], [ok_c.get_output_script()], version=3)
        res = node.submitpackage([parent_ok.serialize().hex(), child_ok.serialize().hex()], 0)
        assert_equal(res["package_msg"], "success")
        assert parent_ok.rehash() in node.getrawmempool()

        bad_a = self.fresh(node, "truc-bad-a")
        bad_b = self.fresh(node, "truc-bad-b")
        bad_signer, bad_utxo = self.take_input()
        parent_bad = make_tx(
            [bad_signer], [bad_utxo], [bad_a.get_output_script(), bad_b.get_output_script()], fee=0, version=3,
        )
        child_bad = self.child_paying_for([parent_bad], [bad_a], [0], [bad_b.get_output_script()], version=3)
        # child_paying_for uses the current pool fee, which is what a 0-fee parent needs the child to cover.
        assert child_bad.get_vsize() <= 1000
        assert fee_for(pool, parent_bad.get_vsize() + child_bad.get_vsize()) < tx_fee(child_bad, [utxo_from(parent_bad, 0)])
        self.assert_submit_rejected([parent_bad, child_bad])

    def relay_package(self, parent, child, child_first):
        node = self.nodes[0]
        if child_first:
            peer = node.add_p2p_connection(P2PInterface())
        else:
            peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, connection_type="outbound-full-relay")
        parent_wtxid = int(parent.getwtxid(), 16)
        child_wtxid = int(child.getwtxid(), 16)
        parent_txid = int(parent.rehash(), 16)
        try:
            if child_first:
                peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child_wtxid)]))
                peer.wait_for_getdata([child_wtxid])
                peer.send_and_ping(msg_tx(child))
                peer.wait_for_getdata([parent_txid])
                peer.send_and_ping(msg_tx(parent))
            else:
                peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid)]))
                peer.wait_for_getdata([parent_wtxid])
                peer.send_and_ping(msg_tx(parent))
                assert parent.rehash() not in node.getrawmempool()
                peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child_wtxid)]))
                peer.wait_for_getdata([child_wtxid])
                peer.send_and_ping(msg_tx(child))
                peer.wait_for_getdata([parent_txid])
                peer.send_and_ping(msg_tx(parent))
        finally:
            node.disconnect_p2ps()

    def test_p2p_child_then_parent(self):
        node = self.nodes[0]
        self.log.info("A peer that relays the child and then the low-fee parent does not get a reused script into the mempool")
        script_a = self.fresh(node, "p2p-ctop-a")
        script_b = self.fresh(node, "p2p-ctop-b")
        signer, utxo = self.take_input()
        parent = self.below_pool_parent(
            [signer], [utxo], [script_a.get_output_script(), script_b.get_output_script()],
        )
        child = self.child_paying_for([parent], [script_a], [0], [script_b.get_output_script()])
        self.relay_package(parent, child, child_first=True)
        assert parent.rehash() not in node.getrawmempool()
        assert child.rehash() not in node.getrawmempool()
        _relay, pool = self.rates()
        pay_signer, pay_utxo = self.take_input()
        payment = make_at_rate([pay_signer], [pay_utxo], [script_b.get_output_script()], pool, extra=2000)
        node.sendrawtransaction(payment.serialize().hex(), 0)
        assert payment.rehash() in node.getrawmempool()

    def test_p2p_parent_then_child(self):
        node = self.nodes[0]
        self.log.info("A peer that relays the low-fee parent and then the child does not get a reused script into the mempool")
        script_a = self.fresh(node, "p2p-ptoc-a")
        script_b = self.fresh(node, "p2p-ptoc-b")
        signer, utxo = self.take_input()
        parent = self.below_pool_parent(
            [signer], [utxo], [script_a.get_output_script(), script_b.get_output_script()],
        )
        child = self.child_paying_for([parent], [script_a], [0], [script_b.get_output_script()])
        self.relay_package(parent, child, child_first=False)
        assert parent.rehash() not in node.getrawmempool()
        assert child.rehash() not in node.getrawmempool()

        self.log.info("After that rejection, an honest child of the same parent still gets both into the mempool")
        script_c = self.fresh(node, "p2p-ptoc-c")
        honest = self.child_paying_for([parent], [script_a], [0], [script_c.get_output_script()])
        self.relay_package(parent, honest, child_first=True)
        assert parent.rehash() in node.getrawmempool()
        assert honest.rehash() in node.getrawmempool()


if __name__ == '__main__':
    SpkReusePackageTest(__file__).main()
