#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native opt-in sharepool validation, reorgs, expiry, and persisted replay.

Only disposable regtest nodes are used. Neither physical miners nor public
networks are accessed. The second node intentionally has enforcement disabled.
"""

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import (StateEntry, apply_to_coinbase, candidate,
    monetary_outputs, parse_coinbase, payouts_root, solve_share, winner_share)
from native_mining_gate import JobOmission, NativeMiningGate
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error, write_config


class SharePoolEnforcementTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"],
                           ["-testactivationheight=blake2b@1", "-disablewallet"]]

    def setup_network(self):
        # Relay explicitly while testing intentional validity disagreement.
        self.setup_nodes()

    def make(self, parent=None, *, owner=0, payout_script=None, shares=(), seconds=1, fees=0, transactions=(), witness=False):
        parent = self.nodes[0].getbestblockhash() if parent is None else parent
        info = self.nodes[0].getblockheader(parent)
        previous = self.manifests.get(parent)
        block, manifest = candidate(genesis=self.genesis, native_parent=int(parent, 16),
            height=info["height"] + 1, ntime=info["time"] + seconds, pool=self.pool,
            secret=self.keys[owner], payout_script=self.scripts[owner] if payout_script is None else payout_script, shares=shares,
            parent_manifest=previous, fees=fees, transactions=transactions, witness=witness)
        return block, manifest

    def finalize(self, block):
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        return block

    def accept(self, block, manifest, *, active=True):
        self.finalize(block)
        for node in self.nodes:
            result = node.submitblock(block.serialize().hex())
            if active:
                assert_equal(result, None)
            else:
                # A shorter valid branch is stored but ConnectBlock validation
                # is deferred until it can become the best-work chain.
                assert result in (None, "inconclusive"), result
                assert_equal(node.getblockheader(block.hash)["height"], block.m_height)
            if active:
                assert_equal(node.getbestblockhash(), block.hash)
        self.manifests[block.hash] = manifest
        self.blocks[block.hash] = block
        return block.hash

    def reject(self, block, *, reason="bad-sharepool-", disabled_accepts=False):
        self.finalize(block)
        tip = self.nodes[0].getbestblockhash()
        result = self.nodes[0].submitblock(block.serialize().hex())
        assert isinstance(result, str) and result.startswith(reason), (result, reason)
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        if disabled_accepts:
            disabled_tip = self.nodes[1].getbestblockhash()
            assert_equal(self.nodes[1].submitblock(block.serialize().hex()), None)
            assert_equal(self.nodes[1].getbestblockhash(), block.hash)
            self.nodes[1].invalidateblock(block.hash)
            assert_equal(self.nodes[1].getbestblockhash(), disabled_tip)

    def install(self, block, manifest, outputs=None):
        if outputs is None:
            outputs = monetary_outputs(manifest.shares, reward=5000000000,
                                       fallback_script=manifest.envelope.payout_script)
        apply_to_coinbase(block, manifest, outputs)
        return block

    def run_test(self):
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.pool = 0xabc123
        self.keys = tuple(value.to_bytes(32, "big") for value in (1, 2, 3))
        # A's exact standard P2WSH is later spent with OP_TRUE to test real fees.
        self.scripts = (b"\x00\x20" + hashlib.sha256(bytes(CScript([OP_TRUE]))).digest(),
                        b"\x00\x14" + b"B" * 20, b"\x51\x20" + b"C" * 32)
        self.manifests, self.blocks = {}, {}

        self.log.info("Activate with a self-contained owner-authorized empty snapshot")
        first, first_manifest = self.make()
        self.log.info("Activated consensus requires a manifest even when stock native rules accept its omission")
        missing_manifest = copy.deepcopy(first)
        missing_manifest.vtx[0].vout = missing_manifest.vtx[0].vout[:1]
        missing_manifest.m_mm_rhs = 0
        self.reject(missing_manifest, disabled_accepts=True)
        self.accept(first, first_manifest)
        assert_equal(parse_coinbase(first.vtx[0])[0], first_manifest)

        origin_a, manifest_a = self.make()
        origin_a_other, manifest_a_other = self.make(owner=2, payout_script=self.scripts[0])
        origin_a_other.m_nonce3 = 9
        origin_a_other.m_time_offset = 6
        origin_a_other.m_extranonce = 666
        origin_b, manifest_b = self.make(owner=1)
        a = solve_share(origin_a, manifest_a)
        a2 = solve_share(origin_a_other, manifest_a_other, start_nonce=11 << 32)
        a_late = solve_share(origin_a, manifest_a, start_nonce=a.header.nNonce + 1)
        a_expired = solve_share(origin_a, manifest_a, start_nonce=a_late.header.nNonce + 1)
        b = solve_share(origin_b, manifest_b)
        tail = solve_share(origin_b, manifest_b, start_nonce=b.header.nNonce + 1)
        settlement, manifest = self.make(shares=(a, a2, b))

        self.log.info("Native share RPC verifies owner/header binding before durable pool admission")
        checked = self.nodes[0].validatesharepoolshare(a.serialize().hex())
        assert_equal(checked["valid"], True)
        assert_equal(checked["proof_id"], f"{a.proof_id:064x}")
        assert_equal(checked["payout_script"], self.scripts[0].hex())
        assert_equal(checked["pool"], f"{self.pool:064x}")
        checked_physical = self.nodes[0].validatesharepoolshare(a2.serialize().hex())
        assert_equal(checked_physical["valid"], True)
        assert a.envelope.public_key != a2.envelope.public_key
        assert_equal(a.envelope.payout_script, a2.envelope.payout_script)
        assert_raises_rpc_error(-8, "not active", self.nodes[1].validatesharepoolshare, a.serialize().hex())
        malformed = [replace(a, owner_signature=bytes(64)),
                     replace(a, envelope=replace(a.envelope, public_key=bytes(32)))]
        changed_header = a.header
        changed_header.m_mm_rhs ^= 1
        malformed.append(replace(a, header_bytes=changed_header.serialize()))
        for share in malformed:
            assert_raises_rpc_error(-26, "", self.nodes[0].validatesharepoolshare, share.serialize().hex())

        self.log.info("Miner gate verifies complete jobs natively and independently detects omitted local work")
        with NativeMiningGate(Path(self.options.tmpdir) / "native-gate.sqlite",
                rpc=lambda method, *args: getattr(self.nodes[0], method)(*args), pool=self.pool,
                public_key=manifest.envelope.public_key, payout_script=self.scripts[0]) as gate:
            assert_equal(gate.base_template()["sharepool"]["requires_completion"], True)
            gate.register_template(origin_a.serialize())
            try:
                gate.authorize(settlement.serialize())
            except ValueError as error:
                assert "origin template has not been validated locally" in str(error), str(error)
            else:
                raise AssertionError("Miner gate authorized snapshot work with unknown origin bodies")
            gate.register_template(origin_a_other.serialize())
            gate.register_template(origin_b.serialize())
            invalid_transaction = CTransaction()
            invalid_transaction.vin = [CTxIn(COutPoint(0xdeadbeef, 0), CScript(), 0xffffffff)]
            invalid_transaction.vout = [CTxOut(1, CScript(self.scripts[0]))]
            invalid_transaction.rehash()
            invalid_body, unused = self.make(transactions=(invalid_transaction,))
            try:
                gate.register_template(invalid_body.serialize())
            except ValueError as error:
                assert "native node rejected" in str(error), str(error)
            else:
                raise AssertionError("Miner gate registered a template spending nonexistent inputs")
            assert_equal(gate.receive(a.serialize()), True)
            assert_equal(gate.receive(a.serialize()), False)
            assert_equal(self.nodes[0].getblocktemplate({"mode": "proposal", "data": origin_a.serialize().hex(),
                "rules": ["segwit", "blake2b", "sharepool"]}), None)
            try:
                gate.authorize(origin_a.serialize())
            except JobOmission as omission:
                assert_equal(omission.proof_ids, (f"{a.proof_id:064x}",))
            else:
                raise AssertionError("Miner gate authorized a job omitting received eligible work")
            authorization = gate.authorize(settlement.serialize())
            immutable = authorization.block_bytes
            assert_equal(gate.needs_refresh(authorization), False)
            assert_equal(gate.receive(tail.serialize()), True)
            assert_equal(gate.needs_refresh(authorization), True)
            assert_equal(authorization.block_bytes, immutable)
            changed = copy.deepcopy(settlement)
            changed.vtx[0].vout[0].nValue -= 1
            self.finalize(changed)
            try:
                gate.authorize(changed.serialize())
            except ValueError as error:
                assert "native node rejected" in str(error), str(error)
            else:
                raise AssertionError("Miner gate authorized a changed native coinbase")

        self.log.info("Reject evidence/root/owner/proof/output/carrier substitutions natively")
        wrong = copy.deepcopy(settlement)
        wrong.m_mm_rhs ^= 1
        self.reject(wrong)
        wrong = replace(manifest, owner_signature=bytes(64))
        self.reject(self.install(copy.deepcopy(settlement), wrong))
        wrong_share = replace(a, owner_signature=bytes(64))
        bad_proof, unused = self.make(shares=(wrong_share,))
        self.reject(bad_proof)
        insufficient = solve_share(origin_a, manifest_a, valid=False)
        bad_proof, unused = self.make(shares=(insufficient,))
        self.reject(bad_proof)
        wrong = replace(manifest, envelope=replace(manifest.envelope, state_root=0))
        self.reject(self.install(copy.deepcopy(settlement), wrong))
        wrong = replace(manifest, envelope=replace(manifest.envelope, shares_root=0))
        self.reject(self.install(copy.deepcopy(settlement), wrong))
        duplicate, unused = self.make(shares=(a, a))
        self.reject(duplicate)
        correct_money = monetary_outputs(manifest.shares, reward=5000000000,
                                         fallback_script=self.scripts[0])
        wrong_money = copy.deepcopy(correct_money)
        wrong_money[0].scriptPubKey = CScript(self.scripts[2])
        wrong_money.sort(key=lambda output: bytes(output.scriptPubKey))
        wrong_manifest = replace(manifest, envelope=replace(manifest.envelope, payouts_root=payouts_root(wrong_money)))
        self.reject(self.install(copy.deepcopy(settlement), wrong_manifest, wrong_money), disabled_accepts=True)
        wrong_money = copy.deepcopy(correct_money)
        wrong_money[0].nValue -= 1
        wrong_manifest = replace(manifest, envelope=replace(manifest.envelope, payouts_root=payouts_root(wrong_money)))
        self.reject(self.install(copy.deepcopy(settlement), wrong_manifest, wrong_money), disabled_accepts=True)
        wrong_money = copy.deepcopy(correct_money)
        wrong_money[0].nValue += 1
        wrong_money[1].nValue -= 1
        wrong_manifest = replace(manifest, envelope=replace(manifest.envelope, payouts_root=payouts_root(wrong_money)))
        self.reject(self.install(copy.deepcopy(settlement), wrong_manifest, wrong_money), disabled_accepts=True)
        wrong = copy.deepcopy(settlement)
        wrong.vtx[0].vout[-1], wrong.vtx[0].vout[-2] = wrong.vtx[0].vout[-2], wrong.vtx[0].vout[-1]
        self.reject(wrong)
        wrong = copy.deepcopy(settlement)
        wrong.vtx[0].vout.pop()
        self.reject(wrong)
        wrong = copy.deepcopy(settlement)
        wrong.vtx[0].vout[2].nValue = 1
        wrong.vtx[0].vout[0].nValue -= 1
        self.reject(wrong)
        # A forged parent-state payload cannot turn already anchored IDs into an
        # externally supplied local registry; it must match the real parent root.
        wrong = replace(manifest, parent_state=(StateEntry(1, 42),))
        self.reject(self.install(copy.deepcopy(settlement), wrong))

        self.log.info("Aggregate two owner keys sharing A's payout and one paying B in exact integer payouts")
        second_hash = self.accept(settlement, manifest)
        expected = monetary_outputs((a, a2, b), reward=5000000000, fallback_script=self.scripts[0])
        assert_equal([(bytes(o.scriptPubKey), o.nValue) for o in parse_coinbase(settlement.vtx[0])[1]],
                     [(bytes(o.scriptPubKey), o.nValue) for o in expected])
        winning_second = winner_share(settlement, manifest)

        self.log.info("Carry later work and the winning proof into a subsequent native block")
        third, third_manifest = self.make(shares=(tail, winning_second))
        third_hash = self.accept(third, third_manifest)
        replay, unused = self.make(shares=(a,))
        self.reject(replay)
        fourth, fourth_manifest = self.make()
        self.accept(fourth, fourth_manifest)
        # All a* proofs originated at j=2: j+3=5 is inclusive.
        replay, unused = self.make(shares=(a,))
        self.reject(replay)
        fifth, fifth_manifest = self.make(shares=(a_late,))
        self.accept(fifth, fifth_manifest)
        expired, unused = self.make(shares=(a_expired,))
        self.reject(expired)
        expired, unused = self.make(shares=(a_late,))
        self.reject(expired)
        sixth, sixth_manifest = self.make()
        self.accept(sixth, sixth_manifest)

        self.log.info("A stronger native branch rolls back orphan payouts and permits its own tail settlement")
        branch_parent = second_hash
        # Tail was paid only on the soon-orphaned branch, so this actual sibling
        # can pay it; the common ancestor's already paid a/b proofs still cannot.
        fork, fork_manifest = self.make(branch_parent, owner=2, shares=(tail,), seconds=2)
        branch_parent = self.accept(fork, fork_manifest, active=False)
        for height in range(4, 8):
            fork, fork_manifest = self.make(branch_parent, owner=2,
                shares=(winning_second,) if height == 4 else ())
            branch_parent = self.accept(fork, fork_manifest, active=height == 7)
        assert_equal(self.nodes[0].getblockheader(third_hash)["confirmations"], -1)
        assert_equal(self.nodes[0].getbestblockhash(), branch_parent)

        fresh_origin, fresh_manifest = self.make()
        fresh = solve_share(fresh_origin, fresh_manifest)
        eighth, eighth_manifest = self.make(shares=(fresh,))
        eighth_hash = self.accept(eighth, eighth_manifest)
        self.log.info("Restart and reindex-chainstate preserve duplicate protection and exact native tip")
        self.restart_node(0, self.extra_args[0])
        assert_equal(self.nodes[0].getbestblockhash(), eighth_hash)
        replay, unused = self.make(shares=(fresh,))
        self.reject(replay)
        self.restart_node(0, self.extra_args[0] + ["-reindex-chainstate"])
        assert_equal(self.nodes[0].getbestblockhash(), eighth_hash)
        replay, unused = self.make(shares=(fresh,), seconds=2)
        self.reject(replay)

        self.log.info("Validate actual transaction fees against exact coinbase allocation in ConnectBlock")
        while self.nodes[0].getblockcount() < 101:
            block, current_manifest = self.make()
            self.accept(block, current_manifest)
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(int(first.vtx[0].rehash(), 16), 0), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(5000000000 - 12345, CScript(self.scripts[0]))]
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(CScript([OP_TRUE]))]
        transaction.rehash()
        underpaid, unused = self.make(transactions=(transaction,), witness=True)
        self.reject(underpaid, disabled_accepts=True)
        correct, correct_manifest = self.make(fees=12345, transactions=(transaction,), witness=True)
        final_hash = self.accept(correct, correct_manifest)
        assert_equal(sum(o.nValue for o in parse_coinbase(correct.vtx[0])[1]), 5000012345)
        self.restart_node(0, self.extra_args[0] + ["-reindex-chainstate"])
        assert_equal(self.nodes[0].getbestblockhash(), final_hash)

        self.log.info("Reindex must invalidate a formerly accepted wrong payout when enforcement is enabled")
        bad_history, bad_manifest = self.make()
        bad_outputs = [CTxOut(5000000000, CScript(self.scripts[1]))]
        bad_manifest = replace(bad_manifest, envelope=replace(bad_manifest.envelope,
            payouts_root=payouts_root(bad_outputs)))
        self.install(bad_history, bad_manifest, bad_outputs)
        self.reject(bad_history)
        assert_equal(self.nodes[1].submitblock(bad_history.serialize().hex()), None)
        assert_equal(self.nodes[1].getbestblockhash(), bad_history.hash)
        # Do not administratively invalidate this block. Its existing native
        # index marks it valid under the old rules; reindex must catch it itself.
        self.restart_node(1, self.extra_args[0] + ["-reindex-chainstate"])
        assert_equal(self.nodes[1].getbestblockhash(), final_hash)
        assert_equal(self.nodes[1].getblockcount(), 102)
        assert_equal(self.nodes[1].getblockheader(bad_history.hash)["confirmations"], -1)
        assert any(tip["hash"] == bad_history.hash and tip["status"] == "invalid"
                   for tip in self.nodes[1].getchaintips())
        self.log.info("The reindexed node rejected historical block 103 and retained valid height 102")

        self.log.info("Two enforcing replicas agree using block evidence despite different local pool histories")
        shared_origin, shared_origin_manifest = self.make(owner=1)
        shared_proof = solve_share(shared_origin, shared_origin_manifest)
        shared_block, shared_manifest = self.make(shares=(shared_proof,))
        final_hash = self.accept(shared_block, shared_manifest)
        for node in self.nodes:
            assert_equal(node.getblockcount(), 103)
            assert_equal(node.getbestblockhash(), final_hash)
            assert_equal(node.getblock(final_hash, 0), shared_block.serialize().hex())
        assert_equal(self.nodes[0].getblockheader(final_hash)["mm_rhs"],
                     self.nodes[1].getblockheader(final_hash)["mm_rhs"])
        assert shared_proof.proof_id in {entry.proof_id for entry in shared_manifest.post_state}
        replay, unused = self.make(shares=(shared_proof,))
        self.finalize(replay)
        for node in self.nodes:
            assert_equal(node.submitblock(replay.serialize().hex()), "bad-sharepool-shares")
            assert_equal(node.getbestblockhash(), final_hash)
            assert_equal(node.getblockcount(), 103)
        self.log.info("Both enforcing replicas accepted height 103 and independently rejected paid-proof replay at 104")

        self.log.info("Test activation cannot be enabled on mainnet or public test networks")
        self.stop_node(1)
        config_path = self.nodes[1].datadir_path / "bitcoin.conf"
        for chain in ("main", "testnet4", "signet"):
            write_config(config_path, n=1, chain=chain)
            self.nodes[1].assert_start_raises_init_error(
                extra_args=["-sharepoolheight=1", "-listen=0", "-networkactive=0"],
                expected_msg="sharepoolheight.*regtest|regtest.*sharepoolheight", match=ErrorMatch.PARTIAL_REGEX)
        write_config(config_path, n=1, chain="regtest")
        self.start_node(1, self.extra_args[0])
        assert_equal(self.nodes[1].getbestblockhash(), final_hash)


if __name__ == "__main__":
    SharePoolEnforcementTest(__file__).main()
