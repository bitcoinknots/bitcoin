#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recent-ancestor template validation uses historical native UTXOs and fees."""

import copy
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import candidate
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, uint256_from_compact
from test_framework.script import CScript, OP_FALSE, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolAncestorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]]

    def make(self, *, parent=None, fees=0, transactions=(), seconds=1):
        node = self.nodes[0]
        parent = node.getbestblockhash() if parent is None else parent
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16),
            height=info["height"] + 1, ntime=info["time"] + seconds, pool=0xabc123,
            secret=(1).to_bytes(32, "big"), payout_script=self.script,
            parent_manifest=self.manifests.get(parent), fees=fees, transactions=transactions,
            witness=bool(transactions))

    def publish(self, block, manifest, *, active=True):
        block.solve()
        result = self.nodes[0].submitblock(block.serialize().hex())
        if active:
            assert_equal(result, None)
            assert_equal(self.nodes[0].getbestblockhash(), block.hash)
        else:
            assert result in (None, "inconclusive"), result
        self.manifests[block.hash] = manifest

    def unchanged_state(self):
        node = self.nodes[0]
        return (node.getbestblockhash(), node.getchaintips(), node.getrawmempool(),
                node.gettxout(self.coinbase_txid, 0), node.gettxout(self.active_txid, 0))

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        self.script = b"\x00\x20" + hashlib.sha256(bytes(CScript([OP_TRUE]))).digest()
        self.manifests = {}
        first, manifest = self.make()
        self.publish(first, manifest)
        self.coinbase_txid = first.vtx[0].rehash()
        while node.getblockcount() < 101:
            block, manifest = self.make()
            self.publish(block, manifest)
        common = node.getbestblockhash()

        def spend(fee):
            transaction = CTransaction()
            transaction.vin = [CTxIn(COutPoint(int(self.coinbase_txid, 16), 0), CScript(), 0xffffffff)]
            transaction.vout = [CTxOut(5000000000 - fee, CScript(self.script))]
            transaction.wit.vtxinwit = [CTxInWitness()]
            transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(CScript([OP_TRUE]))]
            transaction.rehash()
            return transaction

        self.log.info("An unsolved current-tip template passes full native UTXO and fee validation")
        historical_spend = spend(12345)
        origin, origin_manifest = self.make(fees=12345, transactions=(historical_spend,))
        while origin.rehash() <= uint256_from_compact(origin.nBits):
            origin.nNonce += 1
        validated = node.validatesharepooltemplate(origin.serialize().hex())
        assert_equal(validated["valid"], True)
        assert_equal(validated["native_tip"], common)
        assert_equal(validated["native_parent"], common)
        assert_equal(validated["origin_height"], 102)
        assert_equal(validated["commitment"], f"{origin_manifest.envelope.root:064x}")

        self.log.info("The active chain spends the same coin differently, while the old template stays valid at its parent")
        active_spend = spend(23456)
        self.active_txid = active_spend.rehash()
        active_block, active_manifest = self.make(fees=23456, transactions=(active_spend,), seconds=2)
        self.publish(active_block, active_manifest)
        assert_equal(node.gettxout(self.coinbase_txid, 0), None)
        assert node.gettxout(self.active_txid, 0) is not None
        before = self.unchanged_state()
        for _ in range(3):
            checked = node.validatesharepooltemplate(origin.serialize().hex())
            assert_equal(checked["native_tip"], active_block.hash)
            assert_equal(checked["native_parent"], common)
            assert_equal(self.unchanged_state(), before)
        assert_equal(node.getblocktemplate({"mode": "proposal", "data": origin.serialize().hex(),
            "rules": ["segwit", "blake2b", "sharepool"]}), "inconclusive-not-best-prevblk")

        self.log.info("Invalid historical scripts, missing inputs and fee underpayment fail without changing UTXOs")
        invalid_spend = copy.deepcopy(historical_spend)
        invalid_spend.wit.vtxinwit[0].scriptWitness.stack = [bytes(CScript([OP_FALSE]))]
        invalid_script, _ = self.make(parent=common, fees=12345, transactions=(invalid_spend,))
        assert_raises_rpc_error(-26, "mandatory-script-verify-flag-failed", node.validatesharepooltemplate,
                                invalid_script.serialize().hex())
        underpaid, _ = self.make(parent=common, transactions=(historical_spend,))
        assert_raises_rpc_error(-26, "bad-sharepool-payout", node.validatesharepooltemplate, underpaid.serialize().hex())
        missing_spend = copy.deepcopy(historical_spend)
        missing_spend.vin[0].prevout.hash ^= 1
        missing_spend.rehash()
        missing, _ = self.make(parent=common, fees=12345, transactions=(missing_spend,))
        assert_raises_rpc_error(-26, "bad-txns-inputs-missingorspent", node.validatesharepooltemplate, missing.serialize().hex())
        assert_raises_rpc_error(-22, "Noncanonical", node.validatesharepooltemplate, origin.serialize().hex() + "00")
        assert_equal(self.unchanged_state(), before)

        self.log.info("Templates attached to a known valid side branch are ineligible")
        sibling, sibling_manifest = self.make(parent=common, seconds=3)
        self.publish(sibling, sibling_manifest, active=False)
        side_origin, _ = self.make(parent=sibling.hash)
        assert_raises_rpc_error(-8, "eligible active native ancestor", node.validatesharepooltemplate,
                                side_origin.serialize().hex())
        assert_equal(node.getbestblockhash(), active_block.hash)

        self.log.info("The three-block historical boundary survives restart and rejects the fourth block")
        for _ in range(2):
            block, manifest = self.make()
            self.publish(block, manifest)
        assert_equal(node.getblockcount(), 104)
        before = self.unchanged_state()
        assert_equal(node.validatesharepooltemplate(origin.serialize().hex())["valid"], True)
        assert_equal(self.unchanged_state(), before)
        self.restart_node(0)
        assert_equal(node.validatesharepooltemplate(origin.serialize().hex())["valid"], True)
        assert_equal(self.unchanged_state(), before)
        self.log.info("Missing historical undo fails closed without losing the active chain")
        undo_file = node.blocks_path / "rev00000.dat"
        missing_undo = node.blocks_path / "rev00000.dat.test-hidden"
        assert undo_file.is_file()
        assert not missing_undo.exists()
        # This is a disposable test node. Temporarily hide its undo file from
        # read-only historical validation, then restore it even on failure.
        undo_file.rename(missing_undo)
        try:
            assert_raises_rpc_error(-25, "undo data unavailable", node.validatesharepooltemplate,
                                    origin.serialize().hex())
            assert_equal(self.unchanged_state(), before)
        finally:
            missing_undo.rename(undo_file)
        assert_equal(node.validatesharepooltemplate(origin.serialize().hex())["valid"], True)
        block, manifest = self.make()
        self.publish(block, manifest)
        assert_raises_rpc_error(-8, "eligible active native ancestor", node.validatesharepooltemplate,
                                origin.serialize().hex())


if __name__ == "__main__":
    SharePoolAncestorTest(__file__).main()
