#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test of the hardfork signature hash.

Drives a real node across the activation height and checks, against an
independent Python implementation of the sighash:

  * the new signature hash is opt-in, selected by a bit in the hash type byte,
  * before activation, opting in is not valid, so it cannot be used early,
  * from activation both forms are valid, and a spender who never sets the bit
    is unaffected,
  * an opted-in transaction does not verify on a node that has not activated the
    fork, which is what stops it being replayed there,
  * the value of every input is committed to (CVE-2020-14199),
  * SIGHASH_SINGLE with no matching output is no longer spendable via the
    legacy sentinel hash,
  * non-canonical sighash bytes are rejected,
  * taproot opts in through the byte BIP341 already commits, so it is protected
    too, at the cost of SIGHASH_DEFAULT.
"""

import os
import subprocess
from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import COINBASE_MATURITY, create_block, create_coinbase
from test_framework.key import ECKey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey
from test_framework.descriptors import descsum_create
from test_framework.wallet_util import bytes_to_wif
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, COIN, msg_tx, tx_from_hex
from test_framework.p2p import P2PDataStore, P2PInterface
from test_framework.messages import CTxInWitness
from test_framework.script_util import (
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.script import (
    CScript,
    OP_2,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CODESEPARATOR,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_UNIFIED,
    SIGHASH_SINGLE,
    UnifiedSignatureHash,
    UNIFIED_SCRIPT_TYPE_TAPROOT,
    UNIFIED_SCRIPT_TYPE_TAPSCRIPT,
    TaprootSignatureHash,
    taproot_construct,
    sign_input_unified,
    sign_input_legacy,
    sign_input_segwitv0,
    SegwitV0SignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# An internal key nobody holds, so a tr() built on it is script-path only.
NUMS_INTERNAL_KEY = "4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768"

# The fork is scheduled at a height, the same buried deployment the proof of
# work change activates at. Blocks are still mocked forward at a fixed spacing
# so times in the log are readable, but nothing keys off them.
BLOCK_SPACING = 600
ACTIVATION_HEIGHT = 150
FIRST_BLOCK_TIME = 1_600_000_000


class UnifiedSighashTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        # A second node is started later, to check that a peer syncing the
        # chain from scratch reaches the same tip.
        self.num_nodes = 2
        self.setup_clean_chain = True
        # -corepolicy=0 so Knots datacarrier/spam policy does not mask results.
        args = [
            f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}",
            "-corepolicy=0",
        ]
        self.extra_args = [args, list(args)]

    def make_p2pk_utxo(self, value):
        """Fund a P2PKH output we control, and return (outpoint, txout).

        P2PKH rather than bare P2PK because Knots caps output scripts at
        MAX_OUTPUT_SCRIPT_SIZE (34 bytes) and P2PK is 35.
        """
        spk = key_to_p2pkh_script(self.pubkey)
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=value)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"]), CTxOut(value, spk)

    def make_taproot_utxo(self, value):
        """Fund a key-path-only taproot output we control."""
        internal_key = compute_xonly_pubkey(self.privkey.get_bytes())[0]
        info = taproot_construct(internal_key)
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=info.scriptPubKey, amount=value)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"]), CTxOut(value, info.scriptPubKey), info

    def make_tapscript_utxo(self, value):
        """Fund a script-path-only taproot output: <our pubkey> OP_CHECKSIG in a leaf."""
        internal_key = compute_xonly_pubkey(self.privkey.get_bytes())[0]
        leaf = CScript([internal_key, OP_CHECKSIG])
        info = taproot_construct(internal_key, [("only", leaf)])
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=info.scriptPubKey, amount=value)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"]), CTxOut(value, info.scriptPubKey), info

    def sign_tapscript(self, tx, spent_utxos, info, hash_type, index=0):
        """Sign a script-path spend against the independent implementation."""
        leaf = info.leaves["only"]
        msg = UnifiedSignatureHash(None, tx, index, hash_type, spent_utxos, False,
                              script_type=UNIFIED_SCRIPT_TYPE_TAPSCRIPT, leaf_script=leaf.script,
                              leaf_ver=leaf.version)
        assert msg is not None, f"hash type {hash_type:#x} rejected by the spec implementation"
        sig = sign_schnorr(self.privkey.get_bytes(), msg) + bytes([hash_type])
        control = bytes([leaf.version + info.negflag]) + info.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit[index].scriptWitness.stack = [sig, leaf.script, control]

    def build_taproot_spend(self, outpoint, utxo):
        tx = CTransaction()
        tx.version = 2
        tx.vin.append(CTxIn(outpoint, b"", 0xfffffffe))
        tx.vout.append(CTxOut(utxo.nValue - 5000, self.sink_spk))
        tx.wit.vtxinwit.append(CTxInWitness())
        return tx

    def sign_taproot_keypath(self, tx, spent_utxos, info, hash_type, index=0):
        """Sign a key-path spend, opting in when the bit is set.

        Opting in means the same algorithm every other script type uses, not
        BIP341's, so this routes to the independent implementation of it."""
        if hash_type & SIGHASH_UNIFIED:
            msg = UnifiedSignatureHash(None, tx, index, hash_type, spent_utxos, False,
                                  script_type=UNIFIED_SCRIPT_TYPE_TAPROOT)
            assert msg is not None, f"hash type {hash_type:#x} rejected by the spec implementation"
        else:
            msg = TaprootSignatureHash(tx, spent_utxos, hash_type, input_index=index)
        sig = sign_schnorr(tweak_add_privkey(self.privkey.get_bytes(), info.tweak), msg)
        if hash_type:
            sig += bytes([hash_type])
        tx.wit.vtxinwit[index].scriptWitness.stack = [sig]

    def build_spend(self, outpoints, spent_utxos, n_outputs=1):
        tx = CTransaction()
        tx.version = 2
        for op in outpoints:
            # The pubkey push; sign_input_* prepends the signature to this.
            tx.vin.append(CTxIn(op, bytes(CScript([self.pubkey])), 0xfffffffe))
        total = sum(u.nValue for u in spent_utxos)
        share = (total - 5000) // n_outputs
        for _ in range(n_outputs):
            tx.vout.append(CTxOut(share, self.sink_spk))
        return tx

    def mine(self, n=1):
        """Mine n blocks, one per BLOCK_SPACING, so block times are exact."""
        hashes = []
        for _ in range(n):
            self.mocktime += BLOCK_SPACING
            # Both nodes, so the second one's clock tracks the chain and it can
            # leave initial block download once synced. A node in IBD neither
            # accepts nor relays transactions.
            for n in self.nodes:
                n.setmocktime(self.mocktime)
            hashes += self.generate(self.wallet, 1, sync_fun=self.no_op)
        return hashes

    def fork_active_for_next_block(self):
        return self.nodes[0].getblockcount() + 1 >= ACTIVATION_HEIGHT

    def make_utxo(self, value, spk):
        """Fund an arbitrary scriptPubKey and return (outpoint, txout)."""
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=value)
        return COutPoint(int(funding["txid"], 16), funding["sent_vout"]), CTxOut(value, spk)

    def build_witness_spend(self, outpoints, spent_utxos):
        tx = CTransaction()
        tx.version = 2
        for op in outpoints:
            tx.vin.append(CTxIn(op, b"", 0xfffffffe))
        tx.wit.vtxinwit = [CTxInWitness() for _ in outpoints]
        total = sum(u.nValue for u in spent_utxos)
        tx.vout.append(CTxOut(total - 5000, self.sink_spk))
        return tx

    def bitcoin_tx_path(self):
        # bitcoin-tx has no framework option of its own, so take its directory
        # from one that does. They are installed side by side, which gets both
        # the executable suffix and the build layout right; joining BUILDDIR by
        # hand misses the suffix on Windows and the per-configuration directory
        # a multi-config generator adds.
        return os.path.join(os.path.dirname(self.options.bitcoinutil),
                            "bitcoin-tx" + self.config["environment"]["EXEEXT"])

    def run_bitcoin_tx(self, args):
        out = subprocess.run([self.bitcoin_tx_path(), "-regtest"] + args,
                             capture_output=True, text=True)
        assert_equal(out.returncode, 0)
        return out.stdout.strip()

    def submit(self, tx):
        """Try to accept tx into the mempool; return None on success or the reject reason."""
        res = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        return None if res["allowed"] else res.get("reject-reason", "rejected")

    def setup_network(self):
        # Bring both up but leave them unconnected: node 1 syncs at the end so
        # it validates the whole chain in one go, the way a new node would.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        key = ECKey()
        key.generate()
        self.privkey = key
        self.pubkey = key.get_pubkey().get_bytes()
        self.privkey_wif = bytes_to_wif(key.get_bytes(), key.is_compressed)
        self.sink_spk = self.wallet.get_output_script()
        self.mocktime = FIRST_BLOCK_TIME - BLOCK_SPACING

        self.mine(COINBASE_MATURITY + 20)
        assert node.getblockcount() < ACTIVATION_HEIGHT
        assert not self.fork_active_for_next_block()

        # The schedule must actually have reached consensus. Twice during
        # development the option parsed and was then silently dropped, leaving
        # a fork that could never activate while every other test still passed.
        hf = node.getdeploymentinfo().get("hardfork")
        assert hf is not None, "the hardfork schedule did not reach consensus params"
        assert_equal(hf["height"], ACTIVATION_HEIGHT)
        assert_equal(hf["active"], False)

        self.log.info("Before activation: legacy is valid, opting in is not yet")
        op_a, utxo_a = self.make_p2pk_utxo(10 * COIN)
        op_b, utxo_b = self.make_p2pk_utxo(7 * COIN)
        self.mine(1)

        legacy_tx = self.build_spend([op_a, op_b], [utxo_a, utxo_b])
        sign_input_legacy(legacy_tx, 0, utxo_a.scriptPubKey, self.privkey)
        sign_input_legacy(legacy_tx, 1, utxo_b.scriptPubKey, self.privkey)
        assert_equal(self.submit(legacy_tx), None)

        unified_tx = self.build_spend([op_a, op_b], [utxo_a, utxo_b])
        sign_input_unified(unified_tx, 0, utxo_a.scriptPubKey, self.privkey, [utxo_a, utxo_b])
        sign_input_unified(unified_tx, 1, utxo_b.scriptPubKey, self.privkey, [utxo_a, utxo_b])
        reason = self.submit(unified_tx)
        assert reason is not None, "opting in must not be usable before activation"
        self.log.info(f"  pre-activation rejection of opt-in signature: {reason}")

        # The mempool refusing it is policy. A miner can skip the mempool, so
        # prove consensus refuses it too: a block below the activation height
        # carrying a valid opt-in signature must be rejected outright. If it
        # were accepted, this node would follow a chain other nodes reject.
        early_peer = node.add_p2p_connection(P2PDataStore())
        early_tip = int(node.getbestblockhash(), 16)
        early_height = node.getblockcount() + 1
        assert early_height < ACTIVATION_HEIGHT, "this must be below activation to mean anything"
        early_block = create_block(early_tip, create_coinbase(early_height),
                                   node.getblock(node.getbestblockhash())["time"] + 1)
        early_block.vtx.append(unified_tx)
        early_block.hashMerkleRoot = early_block.calc_merkle_root()
        early_block.solve()
        early_peer.send_blocks_and_test([early_block], node, success=False,
                                        reject_reason="mandatory-script-verify-flag-failed")
        assert_equal(node.getblockcount(), early_height - 1)
        node.disconnect_p2ps()
        self.log.info("  a pre-activation block carrying one is rejected at consensus")

        # Taproot opts in through the same bit. Kept until after activation so
        # both sides of the boundary are exercised on one output.
        self.op_tr, self.utxo_tr, self.info_tr = self.make_taproot_utxo(4 * COIN)
        self.mine(1)
        tr_tx = self.build_taproot_spend(self.op_tr, self.utxo_tr)
        self.sign_taproot_keypath(tr_tx, [self.utxo_tr], self.info_tr, SIGHASH_ALL | SIGHASH_UNIFIED)
        reason = self.submit(tr_tx)
        assert reason is not None, "taproot opt-in must not be usable before activation"
        self.log.info(f"  pre-activation rejection of opt-in taproot signature: {reason}")

        # Reserved for the reorg-eviction test far below: it must stay confirmed
        # across a rollback, or the spend is dropped for missing inputs and the
        # eviction path under test is never exercised.
        self.op_reserved, self.utxo_reserved = self.make_p2pk_utxo(3 * COIN)
        # Two more for the competing-branch test, which forks below this point
        # so both stay confirmed on either branch, plus a legacy-signed control
        # that must survive the same reorg.
        self.op_branch, self.utxo_branch = self.make_p2pk_utxo(3 * COIN)
        self.op_branch_ctl, self.utxo_branch_ctl = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        self.branch_fork_height = node.getblockcount()

        # Control: the same two-step multisig flow under the legacy rules, so a
        # failure after activation can be attributed to this change rather than
        # to how the RPC handles partial multisig generally.
        keyC, keyD = ECKey(), ECKey()
        keyC.generate()
        keyD.generate()
        pubC, pubD = keyC.get_pubkey().get_bytes(), keyD.get_pubkey().get_bytes()
        wifC = bytes_to_wif(keyC.get_bytes(), keyC.is_compressed)
        wifD = bytes_to_wif(keyD.get_bytes(), keyD.is_compressed)
        ms_ctl = CScript([OP_2, pubC, pubD, OP_2, OP_CHECKMULTISIG])
        op_ctl, utxo_ctl = self.make_utxo(3 * COIN, script_to_p2wsh_script(ms_ctl))
        self.mine(1)
        unsigned_ctl = self.build_witness_spend([op_ctl], [utxo_ctl])
        prevtxs_ctl = [{
            "txid": f"{op_ctl.hash:064x}", "vout": op_ctl.n,
            "scriptPubKey": script_to_p2wsh_script(ms_ctl).hex(),
            "witnessScript": bytes(ms_ctl).hex(),
            "amount": utxo_ctl.nValue / COIN,
        }]
        ctl_a = node.signrawtransactionwithkey(unsigned_ctl.serialize().hex(), [wifC], prevtxs_ctl)
        ctl_b = node.signrawtransactionwithkey(ctl_a["hex"], [wifD], prevtxs_ctl)
        assert ctl_b["complete"], "legacy two-step multisig must work, as a control"

        self.log.info("Advance to one block below activation")
        edge_op, edge_utxo = self.make_p2pk_utxo(3 * COIN)
        self.mine(ACTIVATION_HEIGHT - node.getblockcount() - 2)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)

        # Pin the early side of the boundary. Everything above shows the fork
        # off well before activation and on from it, and none of it notices an
        # implementation that starts one block early. The block at
        # ACTIVATION_HEIGHT - 1 is the last that must still refuse an opt-in
        # signature, so build exactly that block and require the refusal.
        assert_equal(node.getdeploymentinfo()["hardfork"]["active"],
                     self.fork_active_for_next_block())
        assert not self.fork_active_for_next_block(), \
            "the block at ACTIVATION_HEIGHT - 1 must not enforce the fork"
        edge_tx = self.build_spend([edge_op], [edge_utxo])
        sign_input_unified(edge_tx, 0, edge_utxo.scriptPubKey, self.privkey, [edge_utxo])
        edge_peer = node.add_p2p_connection(P2PDataStore())
        edge_height = node.getblockcount() + 1
        assert_equal(edge_height, ACTIVATION_HEIGHT - 1)
        edge_block = create_block(int(node.getbestblockhash(), 16),
                                  create_coinbase(edge_height),
                                  node.getblock(node.getbestblockhash())["time"] + 1)
        edge_block.vtx.append(edge_tx)
        edge_block.hashMerkleRoot = edge_block.calc_merkle_root()
        edge_block.solve()
        edge_peer.send_blocks_and_test([edge_block], node, success=False,
                                       reject_reason="mandatory-script-verify-flag-failed")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)
        node.disconnect_p2ps()
        self.log.info("  the last pre-activation block still refuses an opt-in signature")

        op_x, utxo_x = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert self.fork_active_for_next_block(), "the next block should enforce the fork"
        # The RPC answers the same question as fork_active_for_next_block: does the
        # block built on this one enforce the fork. Pin them together rather than
        # asserting a constant, so the two cannot drift apart unnoticed.
        assert_equal(node.getdeploymentinfo()["hardfork"]["active"],
                     self.fork_active_for_next_block())
        assert_equal(node.getdeploymentinfo()["hardfork"]["active"], True)

        self.log.info("Mempool at the activation boundary")
        # The next block is the first one that enforces the fork, so the
        # mempool must already refuse legacy signatures here. Otherwise they
        # sit in the mempool, the block assembler picks them up, and block
        # production stops the moment the fork activates.
        boundary_tx = self.build_spend([op_x], [utxo_x])
        sign_input_legacy(boundary_tx, 0, utxo_x.scriptPubKey, self.privkey)
        # Legacy stays valid across activation, so this is simply accepted.
        assert_equal(self.submit(boundary_tx), None)

        # And a transaction that opts in is already acceptable here, since it is
        # valid in the block that is about to be built.
        boundary_hf = self.build_spend([op_x], [utxo_x])
        sign_input_unified(boundary_hf, 0, utxo_x.scriptPubKey, self.privkey, [utxo_x])
        assert_equal(self.submit(boundary_hf), None)
        boundary_txid = node.sendrawtransaction(boundary_hf.serialize().hex())
        assert boundary_txid in node.getrawmempool()
        # The rules apply to the block at ACTIVATION_HEIGHT, which is the next
        # one to be connected, so the mempool switches over once the tip is at
        # ACTIVATION_HEIGHT.
        boundary_block = self.mine(1)[0]
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        # Block production must not stall, and the fork-signed transaction is
        # mined into the first block that enforces the fork.
        assert boundary_txid in node.getblock(boundary_block)["tx"], \
            "the fork-signed transaction should have been mined"
        self.log.info("  block production continued across the boundary")

        assert_equal(node.getdeploymentinfo()["hardfork"]["active"], True)

        self.log.info("From activation: opting in works, and legacy still works")
        op_c, utxo_c = self.make_p2pk_utxo(9 * COIN)
        op_d, utxo_d = self.make_p2pk_utxo(6 * COIN)
        self.mine(1)

        stale_tx = self.build_spend([op_c, op_d], [utxo_c, utxo_d])
        sign_input_legacy(stale_tx, 0, utxo_c.scriptPubKey, self.privkey)
        sign_input_legacy(stale_tx, 1, utxo_d.scriptPubKey, self.privkey)
        assert_equal(self.submit(stale_tx), None)
        self.log.info("  legacy signatures still valid after activation")

        good_tx = self.build_spend([op_c, op_d], [utxo_c, utxo_d])
        sign_input_unified(good_tx, 0, utxo_c.scriptPubKey, self.privkey, [utxo_c, utxo_d])
        sign_input_unified(good_tx, 1, utxo_d.scriptPubKey, self.privkey, [utxo_c, utxo_d])
        assert_equal(self.submit(good_tx), None)

        self.log.info("The node's rules match the independent implementation: mine it")
        txid = node.sendrawtransaction(good_tx.serialize().hex())
        blockhash = self.mine(1)[0]
        assert txid in node.getblock(blockhash)["tx"]

        self.log.info("Every input's value is committed to (CVE-2020-14199)")
        op_e, utxo_e = self.make_p2pk_utxo(4 * COIN)
        op_f, utxo_f = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        lied = [utxo_e, CTxOut(utxo_f.nValue + 12345, utxo_f.scriptPubKey)]
        lie_tx = self.build_spend([op_e, op_f], [utxo_e, utxo_f])
        # Sign input 0 while being lied to about input 1's value.
        sign_input_unified(lie_tx, 0, utxo_e.scriptPubKey, self.privkey, lied)
        sign_input_unified(lie_tx, 1, utxo_f.scriptPubKey, self.privkey, [utxo_e, utxo_f])
        reason = self.submit(lie_tx)
        assert reason is not None, "a lie about another input's value must invalidate the signature"
        self.log.info(f"  rejected: {reason}")
        # Signing input 0 honestly makes the same transaction valid, which
        # proves the rejection was caused by the lie and nothing else.
        honest_tx = self.build_spend([op_e, op_f], [utxo_e, utxo_f])
        sign_input_unified(honest_tx, 0, utxo_e.scriptPubKey, self.privkey, [utxo_e, utxo_f])
        sign_input_unified(honest_tx, 1, utxo_f.scriptPubKey, self.privkey, [utxo_e, utxo_f])
        assert_equal(self.submit(honest_tx), None)

        self.log.info("ANYONECANPAY signatures survive being moved to another position")
        op_g, utxo_g = self.make_p2pk_utxo(5 * COIN)
        op_h, utxo_h = self.make_p2pk_utxo(5 * COIN)
        self.mine(1)
        # Sign op_g as the only input, then rebuild with op_h inserted first.
        solo = self.build_spend([op_g], [utxo_g])
        sig_hash_solo = UnifiedSignatureHash(utxo_g.scriptPubKey, solo, 0,
                                        SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED, [utxo_g], False)
        moved = CTransaction()
        moved.version = solo.version
        moved.vin = [CTxIn(op_h, b"", 0xfffffffe), CTxIn(op_g, b"", 0xfffffffe)]
        moved.vout = solo.vout
        sig_hash_moved = UnifiedSignatureHash(utxo_g.scriptPubKey, moved, 1,
                                         SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED, [utxo_h, utxo_g], False)
        assert_equal(sig_hash_solo, sig_hash_moved)

        self.log.info("SIGHASH_SINGLE with no matching output is not spendable")
        op_i, utxo_i = self.make_p2pk_utxo(4 * COIN)
        op_j, utxo_j = self.make_p2pk_utxo(4 * COIN)
        self.mine(1)
        single_tx = self.build_spend([op_i, op_j], [utxo_i, utxo_j], n_outputs=1)
        assert len(single_tx.vout) == 1
        # Input 1 has no output at index 1: the sighash cannot be computed.
        assert UnifiedSignatureHash(utxo_j.scriptPubKey, single_tx, 1, SIGHASH_SINGLE | SIGHASH_UNIFIED,
                               [utxo_i, utxo_j], False) is None
        # Signing it with the legacy sentinel hash of 1 must not be accepted.
        sign_input_unified(single_tx, 0, utxo_i.scriptPubKey, self.privkey, [utxo_i, utxo_j])
        der = self.privkey.sign_ecdsa((1).to_bytes(32, "big"))
        single_tx.vin[1].scriptSig = bytes(CScript([der + bytes([SIGHASH_SINGLE | SIGHASH_UNIFIED]), self.pubkey]))
        single_tx.rehash()
        reason = self.submit(single_tx)
        assert reason is not None, "the SIGHASH_SINGLE sentinel must not be spendable"
        self.log.info(f"  rejected: {reason}")

        self.log.info("Opting in with a non-canonical hash type is rejected")
        op_k, utxo_k = self.make_p2pk_utxo(4 * COIN)
        self.mine(1)
        # The opt-in bit with no output type, with a reserved output type, and
        # with an undefined bit set. Without the opt-in bit a byte is just a
        # legacy hash type, so it is not part of this.
        for bad_hashtype in (SIGHASH_UNIFIED, SIGHASH_UNIFIED | 0x04, SIGHASH_UNIFIED | 0x05,
                             SIGHASH_UNIFIED | 0x1f, SIGHASH_UNIFIED | 0x20):
            assert UnifiedSignatureHash(utxo_k.scriptPubKey, self.build_spend([op_k], [utxo_k]), 0,
                                   bad_hashtype, [utxo_k], False) is None, bad_hashtype
            bad_tx = self.build_spend([op_k], [utxo_k])
            # Sign the canonical message but claim a non-canonical type.
            good = UnifiedSignatureHash(utxo_k.scriptPubKey, bad_tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_k], False)
            der = self.privkey.sign_ecdsa(good)
            bad_tx.vin[0].scriptSig = bytes(CScript([der + bytes([bad_hashtype]), self.pubkey]))
            bad_tx.rehash()
            assert self.submit(bad_tx) is not None, f"hashtype {bad_hashtype:#x} must be rejected"

        self.log.info("Taproot opts in through the same algorithm as every other type")
        # The same output that was refused before activation is now spendable
        # with the identical signature, so the boundary is what changed.
        # Fund the other two cases first, so one block confirms all of them and
        # nothing is mined out from under a later assertion.
        op_d, utxo_d, info_d = self.make_taproot_utxo(2 * COIN)
        op_b, utxo_b_tr, info_b = self.make_taproot_utxo(2 * COIN)
        self.mine(1)

        tr_tx = self.build_taproot_spend(self.op_tr, self.utxo_tr)
        self.sign_taproot_keypath(tr_tx, [self.utxo_tr], self.info_tr, SIGHASH_ALL | SIGHASH_UNIFIED)
        assert_equal(self.submit(tr_tx), None)
        assert_equal(len(tr_tx.wit.vtxinwit[0].scriptWitness.stack[0]), 65)

        # Existing taproot spends are untouched: SIGHASH_DEFAULT still produces
        # a bare 64-byte signature and still validates.
        default_tx = self.build_taproot_spend(op_d, utxo_d)
        self.sign_taproot_keypath(default_tx, [utxo_d], info_d, 0)
        assert_equal(len(default_tx.wit.vtxinwit[0].scriptWitness.stack[0]), 64)
        assert_equal(self.submit(default_tx), None)

        # A byte carrying only the opt-in bit is not a second spelling of
        # SIGHASH_DEFAULT; it is undefined and stays that way. It cannot even be
        # signed for, so the test signs a valid one and rewrites the byte, which
        # also shows the byte cannot be tampered with after the fact.
        bare_tx = self.build_taproot_spend(op_b, utxo_b_tr)
        self.sign_taproot_keypath(bare_tx, [utxo_b_tr], info_b, SIGHASH_ALL | SIGHASH_UNIFIED)
        tampered = bare_tx.wit.vtxinwit[0].scriptWitness.stack[0][:-1] + bytes([SIGHASH_UNIFIED])
        bare_tx.wit.vtxinwit[0].scriptWitness.stack = [tampered]
        reason = self.submit(bare_tx)
        assert reason is not None, "a bare opt-in byte must not be accepted"

        # Tapscript through the independent implementation too, since the script
        # path commits to the leaf hash and codeseparator position that the key
        # path does not, and nothing else here would catch getting those wrong.
        op_ts, utxo_ts, info_ts = self.make_tapscript_utxo(2 * COIN)
        self.mine(1)
        ts_spend = self.build_taproot_spend(op_ts, utxo_ts)
        self.sign_tapscript(ts_spend, [utxo_ts], info_ts, SIGHASH_ALL | SIGHASH_UNIFIED)
        assert_equal(self.submit(ts_spend), None)
        self.nodes[0].sendrawtransaction(ts_spend.serialize().hex())
        self.log.info("  tapscript signed from the spec alone was accepted")

        # Relay them for real rather than only testing acceptance, so the path
        # from the wire through the mempool into a block is what gets checked.
        self.nodes[0].sendrawtransaction(tr_tx.serialize().hex())
        self.nodes[0].sendrawtransaction(default_tx.serialize().hex())
        blockhash = self.mine(1)[0]
        mined = self.nodes[0].getblock(blockhash)["tx"]
        assert tr_tx.rehash() in mined and default_tx.rehash() in mined
        self.log.info("  opt-in and SIGHASH_DEFAULT taproot spends both mined; "
                      f"bare opt-in byte rejected: {reason}")

        self.log.info("Segwit v0: P2WPKH follows the same rules")
        wpkh_spk = key_to_p2wpkh_script(self.pubkey)
        # BIP143 keeps the implicit P2PKH script as the scriptCode for P2WPKH.
        wpkh_script_code = key_to_p2pkh_script(self.pubkey)
        op_w, utxo_w = self.make_utxo(4 * COIN, wpkh_spk)
        self.mine(1)

        legacy_w = self.build_witness_spend([op_w], [utxo_w])
        sign_input_segwitv0(legacy_w, 0, wpkh_script_code, utxo_w.nValue, self.privkey)
        legacy_w.wit.vtxinwit[0].scriptWitness.stack.append(self.pubkey)
        legacy_w.rehash()
        # BIP143 signatures keep working; opting in is a choice, not a migration.
        assert_equal(self.submit(legacy_w), None)

        good_w = self.build_witness_spend([op_w], [utxo_w])
        sign_input_unified(good_w, 0, wpkh_script_code, self.privkey, [utxo_w], witness=True)
        good_w.wit.vtxinwit[0].scriptWitness.stack.append(self.pubkey)
        good_w.rehash()
        assert_equal(self.submit(good_w), None)

        self.log.info("A BASE signature is not valid for a WITNESS_V0 input")
        crossed = self.build_witness_spend([op_w], [utxo_w])
        sighash_base = UnifiedSignatureHash(wpkh_script_code, crossed, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_w], False)
        der = self.privkey.sign_ecdsa(sighash_base)
        crossed.wit.vtxinwit[0].scriptWitness.stack = [der + bytes([SIGHASH_ALL | SIGHASH_UNIFIED]), self.pubkey]
        crossed.rehash()
        assert self.submit(crossed) is not None, "BASE and WITNESS_V0 must be domain-separated"

        self.log.info("Segwit v0: P2WSH 2-of-2 exercises several signatures in one input")
        key2 = ECKey()
        key2.generate()
        pub2 = key2.get_pubkey().get_bytes()
        witness_script = CScript([OP_2, self.pubkey, pub2, OP_2, OP_CHECKMULTISIG])
        wsh_spk = script_to_p2wsh_script(witness_script)
        op_s, utxo_s = self.make_utxo(4 * COIN, wsh_spk)
        self.mine(1)

        multi = self.build_witness_spend([op_s], [utxo_s])
        sighash = UnifiedSignatureHash(witness_script, multi, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_s], True)
        sig1 = self.privkey.sign_ecdsa(sighash) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        sig2 = key2.sign_ecdsa(sighash) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        multi.wit.vtxinwit[0].scriptWitness.stack = [b"", sig1, sig2, bytes(witness_script)]
        multi.rehash()
        assert_equal(self.submit(multi), None)

        self.log.info("Mixed BASE and WITNESS_V0 inputs in one transaction")
        op_m1, utxo_m1 = self.make_p2pk_utxo(3 * COIN)
        op_m2, utxo_m2 = self.make_utxo(3 * COIN, wpkh_spk)
        self.mine(1)
        mixed = CTransaction()
        mixed.version = 2
        mixed.vin = [CTxIn(op_m1, bytes(CScript([self.pubkey])), 0xfffffffe),
                     CTxIn(op_m2, b"", 0xfffffffe)]
        mixed.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        mixed.vout = [CTxOut(utxo_m1.nValue + utxo_m2.nValue - 5000, self.sink_spk)]
        spent_mixed = [utxo_m1, utxo_m2]
        sign_input_unified(mixed, 0, utxo_m1.scriptPubKey, self.privkey, spent_mixed)
        sign_input_unified(mixed, 1, wpkh_script_code, self.privkey, spent_mixed, witness=True)
        mixed.wit.vtxinwit[1].scriptWitness.stack.append(self.pubkey)
        mixed.rehash()
        assert_equal(self.submit(mixed), None)

        self.log.info("P2SH: the redeemScript is the scriptCode")
        redeem = CScript([self.pubkey, OP_CHECKSIG])
        p2sh_spk = script_to_p2sh_script(redeem)
        op_p, utxo_p = self.make_utxo(3 * COIN, p2sh_spk)
        self.mine(1)

        p2sh_tx = self.build_spend([op_p], [utxo_p])
        p2sh_tx.vin[0].scriptSig = b""
        sighash = UnifiedSignatureHash(redeem, p2sh_tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_p], False)
        der = self.privkey.sign_ecdsa(sighash) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        p2sh_tx.vin[0].scriptSig = bytes(CScript([der, bytes(redeem)]))
        p2sh_tx.rehash()
        assert_equal(self.submit(p2sh_tx), None)

        # Signing the P2SH scriptPubKey instead of the redeemScript must fail:
        # the scriptCode is what is actually executed.
        wrong = self.build_spend([op_p], [utxo_p])
        wrong.vin[0].scriptSig = b""
        wrong_hash = UnifiedSignatureHash(p2sh_spk, wrong, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_p], False)
        der_w = self.privkey.sign_ecdsa(wrong_hash) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        wrong.vin[0].scriptSig = bytes(CScript([der_w, bytes(redeem)]))
        wrong.rehash()
        assert self.submit(wrong) is not None

        self.log.info("P2SH-wrapped P2WPKH")
        sh_wpkh_spk = key_to_p2sh_p2wpkh_script(self.pubkey)
        op_sw, utxo_sw = self.make_utxo(3 * COIN, sh_wpkh_spk)
        self.mine(1)
        sh_w = self.build_witness_spend([op_sw], [utxo_sw])
        # The scriptSig pushes the witness program; the witness carries the sig.
        sh_w.vin[0].scriptSig = bytes(CScript([bytes(key_to_p2wpkh_script(self.pubkey))]))
        sign_input_unified(sh_w, 0, key_to_p2pkh_script(self.pubkey), self.privkey, [utxo_sw], witness=True)
        sh_w.wit.vtxinwit[0].scriptWitness.stack.append(self.pubkey)
        sh_w.rehash()
        assert_equal(self.submit(sh_w), None)

        self.log.info("The node signs for the fork itself, with no external signing")
        # signrawtransactionwithkey must pick the rules for the next block.
        priv_wif = self.privkey_wif
        node_op, node_utxo = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        unsigned = self.build_spend([node_op], [node_utxo])
        unsigned.vin[0].scriptSig = b""
        prevtxs = [{
            "txid": f"{node_op.hash:064x}",
            "vout": node_op.n,
            "scriptPubKey": node_utxo.scriptPubKey.hex(),
            "amount": node_utxo.nValue / COIN,
        }]
        signed = node.signrawtransactionwithkey(unsigned.serialize().hex(), [priv_wif], prevtxs)
        assert signed["complete"], signed.get("errors")
        # The node's own signature is accepted under the fork rules.
        accepted = node.testmempoolaccept([signed["hex"]])[0]
        assert accepted["allowed"], accepted
        node.sendrawtransaction(signed["hex"])
        self.log.info("  signrawtransactionwithkey produced a valid fork signature")

        self.log.info("A partly signed multisig can be completed by a second signer")
        # combinerawtransaction has to recognise the opt-in signature already
        # present, or the second signer sees an empty input and the transaction
        # can never be completed.
        keyA, keyB = ECKey(), ECKey()
        keyA.generate()
        keyB.generate()
        pubA, pubB = keyA.get_pubkey().get_bytes(), keyB.get_pubkey().get_bytes()
        wifA = bytes_to_wif(keyA.get_bytes(), keyA.is_compressed)
        wifB = bytes_to_wif(keyB.get_bytes(), keyB.is_compressed)
        ms = CScript([OP_2, pubA, pubB, OP_2, OP_CHECKMULTISIG])
        ms_spk_sh = script_to_p2wsh_script(ms)
        op_c, utxo_c2 = self.make_utxo(3 * COIN, ms_spk_sh)
        self.mine(1)

        unsigned_ms = self.build_witness_spend([op_c], [utxo_c2])
        prevtxs = [{
            "txid": f"{op_c.hash:064x}", "vout": op_c.n,
            "scriptPubKey": ms_spk_sh.hex(),
            "witnessScript": bytes(ms).hex(),
            "amount": utxo_c2.nValue / COIN,
        }]
        half_a = node.signrawtransactionwithkey(unsigned_ms.serialize().hex(), [wifA], prevtxs)
        assert not half_a["complete"]
        half_b = node.signrawtransactionwithkey(half_a["hex"], [wifB], prevtxs)
        assert half_b["complete"], half_b.get("errors")
        accepted = node.testmempoolaccept([half_b["hex"]])[0]
        assert accepted["allowed"], accepted
        node.sendrawtransaction(half_b["hex"])
        self.log.info("  the second signer saw the first signature and completed it")

        self.log.info("An ordinary wallet spend opts in by itself")
        # The paths above are driven by raw RPCs. This is what a normal user
        # hits: the wallet builds, signs and broadcasts on its own, and must
        # choose the fork's rules without being told.
        node.createwallet(wallet_name="hfw")
        w = node.get_wallet_rpc("hfw")
        addr = w.getnewaddress(address_type="bech32")
        self.wallet.send_to(from_node=node, scriptPubKey=address_to_scriptpubkey(addr), amount=5 * COIN)
        self.mine(1)
        assert_equal(w.getbalances()["mine"]["trusted"], Decimal("5.00000000"))

        dest = w.getnewaddress(address_type="bech32")
        spend_txid = w.sendtoaddress(dest, 1, "", "", False, True)  # replaceable
        spent = tx_from_hex(w.gettransaction(spend_txid)["hex"])
        # Every input the wallet signed must carry the opt-in bit, or the wallet
        # is handing users transactions with no replay protection.
        assert spent.wit.vtxinwit, "expected a segwit spend"
        for wit in spent.wit.vtxinwit:
            sig = wit.scriptWitness.stack[0]
            assert_equal(sig[-1], SIGHASH_ALL | SIGHASH_UNIFIED)
        assert spend_txid in node.getrawmempool()
        self.log.info("  sendtoaddress produced opt-in signatures unprompted")

        bumped = w.bumpfee(spend_txid)
        bumped_tx = tx_from_hex(w.gettransaction(bumped["txid"])["hex"])
        for wit in bumped_tx.wit.vtxinwit:
            assert_equal(wit.scriptWitness.stack[0][-1], SIGHASH_ALL | SIGHASH_UNIFIED)
        assert bumped["txid"] in node.getrawmempool()
        blockhash = self.mine(1)[0]
        assert bumped["txid"] in node.getblock(blockhash)["tx"]
        self.log.info("  bumpfee re-signed with the fork's rules and was mined")

        self.log.info("All four script types opted in, in one transaction")
        # The realistic shape after activation, and the one place the four
        # message formats share a single PrecomputedTransactionData. Each input
        # commits to every other input's amount and script, so all four
        # signatures depend on the same aggregates while producing four
        # different messages.
        op_l4, utxo_l4 = self.make_p2pk_utxo(3 * COIN)
        wit_spk = key_to_p2wpkh_script(self.pubkey)
        op_w4, utxo_w4 = self.make_utxo(3 * COIN, wit_spk)
        op_t4, utxo_t4, info_t4 = self.make_taproot_utxo(3 * COIN)
        op_s4, utxo_s4, info_s4 = self.make_tapscript_utxo(3 * COIN)
        self.mine(1)

        spent4 = [utxo_l4, utxo_w4, utxo_t4, utxo_s4]
        mixed = CTransaction()
        mixed.version = 2
        for op in (op_l4, op_w4, op_t4, op_s4):
            mixed.vin.append(CTxIn(op, b"", 0xfffffffe))
        mixed.vout.append(CTxOut(sum(u.nValue for u in spent4) - 5000, self.sink_spk))
        for _ in range(4):
            mixed.wit.vtxinwit.append(CTxInWitness())
        # The signers prepend to what is already there, so the key each input
        # needs has to be in place first: in the scriptSig for the bare input,
        # on the witness stack for the segwit v0 one.
        mixed.vin[0].scriptSig = bytes(CScript([self.pubkey]))
        mixed.wit.vtxinwit[1].scriptWitness.stack = [self.pubkey]

        sign_input_unified(mixed, 0, utxo_l4.scriptPubKey, self.privkey, spent4)
        # BIP143 keeps the implicit P2PKH script as the scriptCode for P2WPKH.
        sign_input_unified(mixed, 1, key_to_p2pkh_script(self.pubkey), self.privkey, spent4, witness=True)
        self.sign_taproot_keypath(mixed, spent4, info_t4, SIGHASH_ALL | SIGHASH_UNIFIED, index=2)
        self.sign_tapscript(mixed, spent4, info_s4, SIGHASH_ALL | SIGHASH_UNIFIED, index=3)

        reason = self.submit(mixed)
        assert reason is None, f"four-type transaction rejected: {reason}"
        self.nodes[0].sendrawtransaction(mixed.serialize().hex())
        blockhash = self.mine(1)[0]
        assert mixed.rehash() in node.getblock(blockhash)["tx"]
        self.log.info("  legacy, segwit v0, taproot and tapscript signed and mined together")

        self.log.info("Every address type the wallet makes still spends after the fork")
        # Taproot included: an opted-in spend uses the same signature hash as
        # every other script type, not BIP341's. The cost is that
        # SIGHASH_DEFAULT can no longer be used, since it appends no byte to
        # carry the bit.
        # One transaction with an output of each type, so none of them can be
        # spent as change by the next send before the sweep sees it.
        outputs = [{w.getnewaddress(address_type=t): 1}
                   for t in ("legacy", "p2sh-segwit", "bech32", "bech32m")]
        w.send(outputs)
        self.mine(1)
        sweep_to = w.getnewaddress(address_type="bech32")
        sweep_txid = w.sendall([sweep_to])["txid"]
        sweep = tx_from_hex(w.gettransaction(sweep_txid)["hex"])
        assert len(sweep.vin) >= 4, "expected every address type to be spent"

        taproot_inputs = legacy_inputs = optin_inputs = 0
        for idx, vin in enumerate(sweep.vin):
            stack = sweep.wit.vtxinwit[idx].scriptWitness.stack
            if len(stack) == 1 and len(stack[0]) in (64, 65):
                # Taproot key path. Opting in costs the byte that
                # SIGHASH_DEFAULT saves, so an opted-in spend is 65 bytes.
                taproot_inputs += 1
                assert_equal(len(stack[0]), 65)
                assert_equal(stack[0][-1], SIGHASH_ALL | SIGHASH_UNIFIED)
            elif stack:
                optin_inputs += 1
                assert_equal(stack[0][-1], SIGHASH_ALL | SIGHASH_UNIFIED)
            else:
                # Bare legacy input: the signature lives in the scriptSig.
                legacy_inputs += 1
                sig = list(CScript(vin.scriptSig))[0]
                assert_equal(sig[-1], SIGHASH_ALL | SIGHASH_UNIFIED)

        assert taproot_inputs >= 1, "no taproot input was spent"
        assert legacy_inputs >= 1, "no bare legacy input was spent"
        assert optin_inputs >= 1, "no segwit v0 input was spent"
        blockhash = self.mine(1)[0]
        assert sweep_txid in node.getblock(blockhash)["tx"]
        self.log.info(f"  spent {legacy_inputs} legacy, {optin_inputs} segwit v0 and "
                      f"{taproot_inputs} taproot inputs in one transaction")
        w.unloadwallet()

        # BUILD_TX is a separate option from BUILD_UTIL, so bitcoin-tx can be
        # absent from an otherwise complete build. Guard just this section: the
        # checks after it are consensus coverage that does not need the tool.
        if not os.path.isfile(self.bitcoin_tx_path()):
            self.log.info("bitcoin-tx is not built, skipping the offline signing check")
        else:
            self.log.info("bitcoin-tx can sign for the fork when told to")
            # The offline tool has no chain access, so it has to be told with
            # -unifiedsighash. Without it the signature is legacy: still valid, but with
            # no replay protection, which is why the flag has to be explicit.
            op_bt, utxo_bt = self.make_utxo(3 * COIN, key_to_p2wpkh_script(self.pubkey))
            self.mine(1)
            bt_tx = self.build_witness_spend([op_bt], [utxo_bt])
            signed_hex = self.run_bitcoin_tx([
                "-unifiedsighash", bt_tx.serialize_without_witness().hex(),
                f"set=privatekeys:[\"{self.privkey_wif}\"]",
                f"set=prevtxs:[{{\"txid\":\"{op_bt.hash:064x}\",\"vout\":{op_bt.n},"
                f"\"scriptPubKey\":\"{utxo_bt.scriptPubKey.hex()}\","
                f"\"amount\":{utxo_bt.nValue / COIN:.8f}}}]",
                "sign=ALL",
            ])
            signed_tx = tx_from_hex(signed_hex)
            assert_equal(signed_tx.wit.vtxinwit[0].scriptWitness.stack[0][-1], SIGHASH_ALL | SIGHASH_UNIFIED)
            accepted = node.testmempoolaccept([signed_hex])[0]
            assert accepted["allowed"], accepted
            node.sendrawtransaction(signed_hex)
            self.log.info("  bitcoin-tx -unifiedsighash produced an accepted opt-in signature")

        self.log.info("combinerawtransaction merges opt-in signatures")
        # Each party signs the same transaction separately and the halves are
        # merged. If the merge cannot see an opt-in signature it drops it, and
        # the combined transaction is still incomplete.
        keyE, keyF = ECKey(), ECKey()
        keyE.generate()
        keyF.generate()
        pubE, pubF = keyE.get_pubkey().get_bytes(), keyF.get_pubkey().get_bytes()
        wifE = bytes_to_wif(keyE.get_bytes(), keyE.is_compressed)
        wifF = bytes_to_wif(keyF.get_bytes(), keyF.is_compressed)
        ms2 = CScript([OP_2, pubE, pubF, OP_2, OP_CHECKMULTISIG])
        ms2_spk = script_to_p2wsh_script(ms2)
        op_cr, utxo_cr = self.make_utxo(3 * COIN, ms2_spk)
        self.mine(1)
        unsigned_cr = self.build_witness_spend([op_cr], [utxo_cr])
        prevtxs_cr = [{
            "txid": f"{op_cr.hash:064x}", "vout": op_cr.n,
            "scriptPubKey": ms2_spk.hex(), "witnessScript": bytes(ms2).hex(),
            "amount": utxo_cr.nValue / COIN,
        }]
        part_e = node.signrawtransactionwithkey(unsigned_cr.serialize().hex(), [wifE], prevtxs_cr)
        part_f = node.signrawtransactionwithkey(unsigned_cr.serialize().hex(), [wifF], prevtxs_cr)
        assert not part_e["complete"] and not part_f["complete"]
        combined = node.combinerawtransaction([part_e["hex"], part_f["hex"]])
        accepted = node.testmempoolaccept([combined])[0]
        assert accepted["allowed"], accepted
        node.sendrawtransaction(combined)
        self.log.info("  two independently signed halves combined and were accepted")

        self.log.info("finalizepsbt completes an opt-in PSBT")
        op_fp, utxo_fp = self.make_utxo(3 * COIN, key_to_p2wpkh_script(self.pubkey))
        self.mine(1)
        fp_tx = self.build_witness_spend([op_fp], [utxo_fp])
        fp_psbt = node.utxoupdatepsbt(node.converttopsbt(fp_tx.serialize().hex()))
        fp_desc = descsum_create(f"wpkh({self.privkey_wif})")
        # finalize=false, so the input carries a partial signature and is not
        # yet complete; finalizepsbt is what has to verify and extract it.
        signed_psbt = node.descriptorprocesspsbt(fp_psbt, [fp_desc], "ALL", True, False)
        final = node.finalizepsbt(signed_psbt["psbt"])
        assert final["complete"], final
        accepted = node.testmempoolaccept([final["hex"]])[0]
        assert accepted["allowed"], accepted
        node.sendrawtransaction(final["hex"])
        self.log.info("  finalizepsbt verified the opt-in signature and extracted it")

        self.log.info("The opt-in bit cannot be flipped by a third party")
        # The bit is committed to by the signature it appears in, so neither
        # direction of tampering produces something that still verifies. If it
        # were not committed, a relayer could strip it and undo the replay
        # protection the spender asked for.
        op_fl, utxo_fl = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)

        opted = self.build_spend([op_fl], [utxo_fl])
        sign_input_unified(opted, 0, utxo_fl.scriptPubKey, self.privkey, [utxo_fl])
        assert_equal(self.submit(opted), None)
        # Strip the bit from the signature's hash type byte.
        stripped = self.build_spend([op_fl], [utxo_fl])
        sig = list(CScript(opted.vin[0].scriptSig))[0]
        assert sig[-1] == (SIGHASH_ALL | SIGHASH_UNIFIED)
        stripped.vin[0].scriptSig = bytes(CScript([sig[:-1] + bytes([SIGHASH_ALL]), self.pubkey]))
        stripped.rehash()
        assert self.submit(stripped) is not None, "stripping the opt-in bit must invalidate"

        # And the reverse: adding the bit to a legacy signature.
        legacy_one = self.build_spend([op_fl], [utxo_fl])
        sign_input_legacy(legacy_one, 0, utxo_fl.scriptPubKey, self.privkey)
        assert_equal(self.submit(legacy_one), None)
        forged = self.build_spend([op_fl], [utxo_fl])
        lsig = list(CScript(legacy_one.vin[0].scriptSig))[0]
        forged.vin[0].scriptSig = bytes(CScript([lsig[:-1] + bytes([SIGHASH_ALL | SIGHASH_UNIFIED]), self.pubkey]))
        forged.rehash()
        assert self.submit(forged) is not None, "adding the opt-in bit must invalidate"
        self.log.info("  both directions of tampering are rejected")

        self.log.info("Opting in is per signature, not per transaction")
        # A 2-of-2 where one signature opts in and the other does not. If the
        # choice were made per input or per transaction rather than per
        # signature, one of these two would fail.
        keym = ECKey()
        keym.generate()
        pubm = keym.get_pubkey().get_bytes()
        ms_script = CScript([OP_2, self.pubkey, pubm, OP_2, OP_CHECKMULTISIG])
        ms_spk = script_to_p2wsh_script(ms_script)
        op_ms, utxo_ms = self.make_utxo(3 * COIN, ms_spk)
        self.mine(1)
        mixed_sigs = self.build_witness_spend([op_ms], [utxo_ms])
        h_optin = UnifiedSignatureHash(ms_script, mixed_sigs, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_ms], True)
        h_legacy = SegwitV0SignatureHash(ms_script, mixed_sigs, 0, SIGHASH_ALL, utxo_ms.nValue)
        s_optin = self.privkey.sign_ecdsa(h_optin) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        s_legacy = keym.sign_ecdsa(h_legacy) + bytes([SIGHASH_ALL])
        mixed_sigs.wit.vtxinwit[0].scriptWitness.stack = [b"", s_optin, s_legacy, bytes(ms_script)]
        mixed_sigs.rehash()
        assert_equal(self.submit(mixed_sigs), None)
        self.log.info("  one opted-in and one legacy signature verify in the same input")

        self.log.info("Opt-in and legacy inputs mix within one transaction")
        op_i1, utxo_i1 = self.make_p2pk_utxo(2 * COIN)
        op_i2, utxo_i2 = self.make_p2pk_utxo(2 * COIN)
        self.mine(1)
        mix_tx = self.build_spend([op_i1, op_i2], [utxo_i1, utxo_i2])
        sign_input_unified(mix_tx, 0, utxo_i1.scriptPubKey, self.privkey, [utxo_i1, utxo_i2])
        sign_input_legacy(mix_tx, 1, utxo_i2.scriptPubKey, self.privkey)
        assert_equal(self.submit(mix_tx), None)
        self.log.info("  a transaction may opt in for some inputs and not others")

        self.log.info("OP_CODESEPARATOR: signer and validator agree on the scriptCode")
        # Two signatures in one script, separated by OP_CODESEPARATOR. The first
        # commits to the whole script, the second only to the part after the
        # separator. If the node derived either differently from the signer, one
        # of the two signatures would fail.
        key2b = ECKey()
        key2b.generate()
        pub2b = key2b.get_pubkey().get_bytes()
        cs_script = CScript([self.pubkey, OP_CHECKSIGVERIFY, OP_CODESEPARATOR, pub2b, OP_CHECKSIG])
        cs_spk = script_to_p2wsh_script(cs_script)
        op_cs, utxo_cs = self.make_utxo(3 * COIN, cs_spk)
        self.mine(1)

        cs_tx = self.build_witness_spend([op_cs], [utxo_cs])
        raw = bytes(cs_script)
        # Build the tail structurally. Searching raw bytes for the opcode is
        # wrong: a pubkey push can contain that byte value.
        tail = CScript([pub2b, OP_CHECKSIG])
        assert raw.endswith(bytes(tail))
        # First signature: scriptCode is the whole script, separator included,
        # since the hardfork sighash does not strip separators the way the
        # legacy one does.
        h_full = UnifiedSignatureHash(cs_script, cs_tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_cs], True)
        # Second: only what follows the separator that has executed.
        h_tail = UnifiedSignatureHash(tail, cs_tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_cs], True)
        assert h_full != h_tail, "the separator must actually change the scriptCode"
        sig_full = self.privkey.sign_ecdsa(h_full) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        sig_tail = key2b.sign_ecdsa(h_tail) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        cs_tx.wit.vtxinwit[0].scriptWitness.stack = [sig_tail, sig_full, raw]
        cs_tx.rehash()
        assert_equal(self.submit(cs_tx), None)

        # Signing the second one over the whole script instead is rejected,
        # which is what proves the separator is being honoured rather than
        # ignored by both sides in the same way.
        bad_cs = self.build_witness_spend([op_cs], [utxo_cs])
        h_full2 = UnifiedSignatureHash(cs_script, bad_cs, 0, SIGHASH_ALL | SIGHASH_UNIFIED, [utxo_cs], True)
        bad_tail = key2b.sign_ecdsa(h_full2) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        bad_full = self.privkey.sign_ecdsa(h_full2) + bytes([SIGHASH_ALL | SIGHASH_UNIFIED])
        bad_cs.wit.vtxinwit[0].scriptWitness.stack = [bad_tail, bad_full, raw]
        bad_cs.rehash()
        assert self.submit(bad_cs) is not None, "the separator must change the second scriptCode"
        self.log.info("  both signatures verify with the separator honoured")

        self.log.info("PSBT signing produces fork signatures too")
        # A hardware wallet or multi-party flow goes through PSBT, not
        # signrawtransactionwithkey, so it needs the same rules or it signs
        # something the network will reject.
        # A segwit input, so utxoupdatepsbt can supply witness_utxo; a legacy
        # input would need the whole previous transaction attached instead.
        psbt_op, psbt_utxo = self.make_utxo(3 * COIN, key_to_p2wpkh_script(self.pubkey))
        self.mine(1)
        psbt_tx = self.build_witness_spend([psbt_op], [psbt_utxo])
        psbt = node.converttopsbt(psbt_tx.serialize().hex())
        # Supply the input's utxo so the signer can commit to its value.
        psbt = node.utxoupdatepsbt(psbt)
        desc = descsum_create(f"wpkh({self.privkey_wif})")
        processed = node.descriptorprocesspsbt(psbt, [desc], "ALL", True, True)
        assert processed["complete"], processed
        accepted = node.testmempoolaccept([processed["hex"]])[0]
        assert accepted["allowed"], accepted
        node.sendrawtransaction(processed["hex"])
        self.log.info("  descriptorprocesspsbt produced a valid fork signature")

        self.log.info("A tapscript spend signed through the wallet's satisfier")
        # Script path rather than key path: the internal key is a NUMS point
        # nobody holds, so the only way to spend is through the leaf, which
        # reaches the signature creator by a different route than a key path
        # spend does.
        ts_desc = descsum_create(f"tr({NUMS_INTERNAL_KEY},pk({self.privkey_wif}))")
        ts_spk = address_to_scriptpubkey(node.deriveaddresses(ts_desc)[0])
        ts_funding = self.wallet.send_to(from_node=node, scriptPubKey=ts_spk, amount=3 * COIN)
        self.mine(1)
        ts_tx = CTransaction()
        ts_tx.version = 2
        ts_tx.vin.append(CTxIn(COutPoint(int(ts_funding["txid"], 16), ts_funding["sent_vout"]), b"", 0xfffffffe))
        ts_tx.vout.append(CTxOut(3 * COIN - 5000, self.sink_spk))
        ts_psbt = node.utxoupdatepsbt(node.converttopsbt(ts_tx.serialize().hex()))
        ts_processed = node.descriptorprocesspsbt(ts_psbt, [ts_desc], "ALL", True, True)
        assert ts_processed["complete"], ts_processed
        ts_final = tx_from_hex(ts_processed["hex"])
        ts_stack = ts_final.wit.vtxinwit[0].scriptWitness.stack
        # Signature, leaf script, control block.
        assert_equal(len(ts_stack), 3)
        assert_equal(len(ts_stack[0]), 65)
        assert_equal(ts_stack[0][-1], SIGHASH_ALL | SIGHASH_UNIFIED)
        node.sendrawtransaction(ts_processed["hex"])
        self.log.info("  the script path opted in through miniscript satisfaction")

        self.log.info("Reorg back across the activation height")
        # A fork-signed transaction mined above the activation height, then the
        # chain is rolled back below it. The transaction returns to the mempool
        # but is no longer valid for the block that would be built next, so the
        # node must not stall trying to mine it.
        op_r, utxo_r = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        reorg_tx = self.build_spend([op_r], [utxo_r])
        sign_input_unified(reorg_tx, 0, utxo_r.scriptPubKey, self.privkey, [utxo_r])
        reorg_txid = node.sendrawtransaction(reorg_tx.serialize().hex())
        reorg_block = self.mine(1)[0]
        assert reorg_txid in node.getblock(reorg_block)["tx"]

        # Roll back to below the activation height: the next block would be
        # ACTIVATION_HEIGHT - 1, which does not enforce the fork.
        rollback_to = node.getblockhash(ACTIVATION_HEIGHT - 1)
        node.invalidateblock(rollback_to)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)
        assert reorg_txid not in node.getrawmempool(), \
            "a fork-signed transaction must not survive a reorg below activation"
        # Block production must not stall.
        self.mine(1)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        node.reconsiderblock(rollback_to)
        # The reorg invalidated the wallet's cached utxo set.
        self.wallet.rescan_utxos()
        self.log.info("  reorg handled, block production continued")

        self.log.info("An unconfirmed opt-in transaction is evicted by a reorg below activation")
        # The previous case came back through the disconnect pool and failed
        # re-acceptance. This one never reaches a block, so nothing re-validates
        # it: only the reorg filter can drop it, and if it survives the block
        # assembler will pick it up and block production stops.
        op_u, utxo_u = self.op_reserved, self.utxo_reserved
        unconf = self.build_spend([op_u], [utxo_u])
        sign_input_unified(unconf, 0, utxo_u.scriptPubKey, self.privkey, [utxo_u])
        unconf_txid = node.sendrawtransaction(unconf.serialize().hex())
        assert unconf_txid in node.getrawmempool()
        accepted_height = node.getblockcount()

        # Two blocks exist at ACTIVATION_HEIGHT - 1 after the earlier reorg, so
        # roll back past both to be sure the next block is below activation.
        rollback2 = node.getblockhash(ACTIVATION_HEIGHT - 2)
        node.invalidateblock(rollback2)
        assert node.getblockcount() < accepted_height
        assert not self.fork_active_for_next_block()
        assert unconf_txid not in node.getrawmempool(), \
            "an unconfirmed opt-in transaction must not survive a reorg below activation"
        self.mine(1)
        node.reconsiderblock(rollback2)
        self.wallet.rescan_utxos()
        self.log.info("  evicted, and block production continued")

        self.log.info("An opt-in entry is evicted when a rollback drops below activation")
        # The entry records whether the fork applied when it was accepted, and
        # the filter compares that against the tip the node actually has. A
        # rollback is the shape reachable here; a reorg onto a shorter chain
        # with more work is the other, and the predicate reads the new tip
        # either way rather than reasoning about relative heights.
        assert self.fork_active_for_next_block()
        roll_tx = self.build_spend([self.op_branch], [self.utxo_branch])
        sign_input_unified(roll_tx, 0, self.utxo_branch.scriptPubKey, self.privkey,
                           [self.utxo_branch])
        roll_txid = node.sendrawtransaction(roll_tx.serialize().hex())
        # Control: same shape, same funding depth, signed under the legacy rules.
        # It goes too, because the entry records that the fork was active when it
        # was accepted rather than that it opted in. Asserted so the
        # over-eviction stays visible.
        ctl_tx = self.build_spend([self.op_branch_ctl], [self.utxo_branch_ctl])
        sign_input_legacy(ctl_tx, 0, self.utxo_branch_ctl.scriptPubKey, self.privkey)
        ctl_txid = node.sendrawtransaction(ctl_tx.serialize().hex())
        assert roll_txid in node.getrawmempool()
        assert ctl_txid in node.getrawmempool()

        roll_to = node.getblockhash(ACTIVATION_HEIGHT - 2)
        node.invalidateblock(roll_to)
        assert not self.fork_active_for_next_block()
        mempool_after = node.getrawmempool()
        assert roll_txid not in mempool_after, \
            "an opt-in entry survived a rollback below activation"
        assert ctl_txid not in mempool_after, \
            "entries accepted while the fork was active are dropped together"
        # The assembler throws rather than skipping an entry it cannot validate,
        # so a surviving entry stops block production outright.
        node.getblocktemplate({"rules": ["segwit"]})
        node.reconsiderblock(roll_to)
        assert self.fork_active_for_next_block()
        self.wallet.rescan_utxos()
        self.log.info("  evicted, and the template still builds")

        self.log.info("A block containing a bad opt-in signature is rejected outright")
        # Fresh outputs: the earlier stale_tx spent inputs that good_tx has
        # since consumed, so a block with it would fail as a double spend
        # before any script is run.
        op_l, utxo_l = self.make_p2pk_utxo(4 * COIN)
        self.mine(1)
        # An opt-in signature made over the wrong message: the mempool refuses
        # it, and so must block connection, or the rules would only be policy.
        block_tx = self.build_spend([op_l], [utxo_l])
        lied_utxo = CTxOut(utxo_l.nValue + 1, utxo_l.scriptPubKey)
        sign_input_unified(block_tx, 0, utxo_l.scriptPubKey, self.privkey, [lied_utxo])
        assert self.submit(block_tx) is not None

        peer = node.add_p2p_connection(P2PDataStore())
        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block_time = node.getblock(node.getbestblockhash())["time"] + 1
        block = create_block(tip, create_coinbase(height), block_time)
        block.vtx.append(block_tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        peer.send_blocks_and_test([block], node, success=False,
                                  reject_reason="mandatory-script-verify-flag-failed")
        assert_equal(node.getblockcount(), height - 1)

        self.log.info("A reindex reaches the same tip")
        # Reindexing revalidates every block from disk, on a different path from
        # the one that accepted them, so the rules must be reconstructed the
        # same way. Heights come from the rebuilt block index here, which is
        # exactly what activation is keyed to.
        final_tip = node.getbestblockhash()
        final_height = node.getblockcount()
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        assert_equal(node.getbestblockhash(), final_tip)
        assert_equal(node.getblockcount(), final_height)

        self.log.info("A second node syncing from scratch agrees")
        # If activation were derived differently during initial sync than during
        # normal operation, this is where the two would part company.
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=120)
        assert_equal(self.nodes[1].getbestblockhash(), final_tip)
        assert_equal(self.nodes[1].getblockcount(), final_height)
        assert_equal(self.nodes[1].getdeploymentinfo()["hardfork"]["active"], True)
        self.log.info("  reindex and a fresh peer both reach the same chain")

        self.log.info("An opt-in transaction relays to a peer and is accepted there")
        # Block sync only proves the second node accepts opt-in transactions
        # inside a block. Relay goes through a different path, with policy rules
        # rather than consensus ones, so a transaction that is valid but treated
        # as non-standard would simply never propagate.
        op_rl, utxo_rl = self.make_p2pk_utxo(3 * COIN)
        self.mine(1)
        self.sync_blocks(timeout=120)
        relay_tx = self.build_spend([op_rl], [utxo_rl])
        sign_input_unified(relay_tx, 0, utxo_rl.scriptPubKey, self.privkey, [utxo_rl])
        # Deliver it to the second node over p2p and confirm it validates and
        # accepts independently. Relaying it out of node 0 instead would depend
        # on announcement timers, which are driven by the mocked clock here and
        # are not what this is checking.
        relay_txid = node.sendrawtransaction(relay_tx.serialize().hex())
        peer1 = self.nodes[1].add_p2p_connection(P2PInterface())
        peer1.send_and_ping(msg_tx(relay_tx))
        self.wait_until(lambda: relay_txid in self.nodes[1].getrawmempool(), timeout=30)
        assert relay_txid in self.nodes[1].getrawmempool(), \
            "an opt-in transaction must be accepted by a peer receiving it over the wire"
        self.log.info("  the peer accepted it from the wire, not just in a block")

        self.log.info("Signing refuses an input whose amount was not supplied")
        # The unified message commits to the amount of every input, not just
        # witness ones. Omitting it for a bare input was legitimate before,
        # because the legacy message never covered it, so signing anyway would
        # report success for a transaction the network rejects.
        op_amt, utxo_amt = self.make_p2pk_utxo(2 * COIN)
        self.mine(1)
        funding_txid = f"{op_amt.hash:064x}"
        spend = self.build_spend([op_amt], [utxo_amt])
        unsigned = spend.serialize().hex()
        prevtx = {"txid": funding_txid, "vout": op_amt.n,
                  "scriptPubKey": utxo_amt.scriptPubKey.hex()}
        assert_raises_rpc_error(-3, "Missing amount",
                                node.signrawtransactionwithkey, unsigned, [self.privkey_wif], [prevtx])
        prevtx["amount"] = Decimal(utxo_amt.nValue) / COIN
        signed = node.signrawtransactionwithkey(unsigned, [self.privkey_wif], [prevtx])
        assert signed["complete"], signed
        self.log.info("  refused without the amount, signs with it")


if __name__ == "__main__":
    UnifiedSighashTest(__file__).main()
