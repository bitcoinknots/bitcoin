#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Explicit v7 compact jobs, native payouts, missing data, forks and local index recovery.

This is an isolated native regtest correctness test. The separate capacity
harness selects --profile-version=7 for its unchanged 100-miner workload.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from native_mining_gate import template_id
from hash_snapshot import (COMPACT_TIDES_RULES_HASH, HashSigner, Snapshot, TemplateRecord,
                           apply_tides_state, solve_share)
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.messages import CTxOut
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashCompactTest(SharePoolHashTidesTest):
    PROFILE_VERSION = 7

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=1, choices=(1,))

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = ["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
                  "-testactivationheight=blake2b@1", "-disablewallet"]
        self.extra_args = [common + ["-sharepoolcompacttides=1"] for _ in range(2)] + [common]

    def wait_tip(self, block):
        self.wait_until(lambda: all(node.getbestblockhash() == block.hash for node in self.nodes[:2]), timeout=120)
        for node in self.nodes[:2]:
            assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

    def check_resources(self, node, snapshot):
        measured = super().check_resources(node, snapshot)
        usage = measured["usage"]
        assert_equal(usage["state_bytes"], 0)
        assert_equal(usage["certificate_bytes"], 0)
        assert_equal(usage["jobs"], len({template_id(proof.header) for proof in snapshot.shares}))
        assert_equal(measured["limits"]["compact_shares"], 32768)
        assert_equal(measured["limits"]["dependency_shares"], 131072)
        return measured

    def check_guards(self, final):
        node, legacy = self.nodes[1:]
        self.stop_node(1)
        marker = Path(node.chain_path) / "sharepool-profile-v7"
        before = marker.read_bytes()
        manifest = self.disk_manifest(Path(node.chain_path) / "blocks")
        for arguments in (self.extra_args[2], ["-testactivationheight=blake2b@1", "-disablewallet", "-reindex"]):
            node.assert_start_raises_init_error(arguments, "TIDES datadir profile", match=ErrorMatch.PARTIAL_REGEX)
            assert_equal(marker.read_bytes(), before)
            assert_equal(self.disk_manifest(Path(node.chain_path) / "blocks"), manifest)
        for value in ("0", "-1", "nan"):
            node.assert_start_raises_init_error(self.extra_args[1] + [f"-sharepooltidesindexmib={value}"],
                "must be a positive whole MiB", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(1)
        assert_equal(node.getbestblockhash(), final.hash)
        self.stop_node(2)
        legacy_marker = Path(legacy.chain_path) / "sharepool-profile-v6"
        legacy_before = legacy_marker.read_bytes()
        legacy.assert_start_raises_init_error(self.extra_args[0], "TIDES datadir profile", match=ErrorMatch.PARTIAL_REGEX)
        assert_equal(legacy_marker.read_bytes(), legacy_before)
        self.start_node(2)

    def run_test(self):
        node, follower, legacy = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        for current in self.nodes[:2]:
            status = current.getsharepoolhashstatus()
            assert_equal(status["mode"], "hash-only-v7-compact-tides")
            assert_equal(status["rules"], f"{COMPACT_TIDES_RULES_HASH:064x}")
        assert_equal(legacy.getsharepoolhashstatus()["mode"], "hash-only-v6-tides")
        directory = Path(self.options.tmpdir)
        keys, gates = [], []
        report = {"network": "isolated native regtest", "profile": "hash-only-v7-compact-tides",
                  "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
                  "signer_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
                  "rules": f"{COMPACT_TIDES_RULES_HASH:064x}", "physical_miners": 0}
        try:
            signers = []
            for index in range(4):
                key = directory / f"compact-owner-{index}.key"
                keys.append(key)
                signers.append(HashSigner.create(self.signer_binary, key, pool=101 if index < 3 else 202,
                    payout_script=b"\x00\x14" + (index + 1).to_bytes(20, "big")))
            self.log.info("Four exact signed jobs, 128 independent proofs, two independent payout pools")
            origins = [self.origin(0, signer) for signer in signers]
            gate = HashMiningGate(directory / "compact-gate.sqlite", rpc=lambda method, *args: getattr(node, method)(*args),
                pool=signers[0].pool, public_key=signers[0].public_key, payout_script=signers[0].payout_script,
                profile_version=7)
            gates.append(gate)
            proofs = []
            for origin, opening, first_proof in origins:
                gate.register_snapshot(opening.serialize())
                gate.register_template(origin.serialize())
                next_nonce = 0
                for _ in range(32):
                    proof = solve_share(origin, opening, start_nonce=next_nonce)
                    next_nonce = proof.header.nNonce + 1
                    gate.receive(proof)
                    proofs.append(proof)
            assert_equal(len({proof.proof_id for proof in proofs}), 128)
            first, first_state = gate.make_native(sign_owner=signers[0].sign_owner)
            authorization = gate.authorize(first.serialize(), first_state.serialize())
            assert gate.ready_for_dispatch(authorization)
            assert_equal([proof.serialize() for proof in first_state.shares],
                         [proof.serialize() for proof in sorted(proofs, key=lambda proof: proof.proof_id)])
            assert_equal((first_state.post_state, first_state.certificates), ((), ()))
            derived = apply_tides_state(first_state, None)
            assert_equal(len(derived.post_state), 128)
            assert_equal(len(derived.certificates), 4)
            assert_equal(derived.history_head, first_state.history_head)
            resources = self.check_resources(node, first_state)
            assert_equal(resources["usage"]["jobs"], 4)
            assert_equal(resources["usage"]["share_bytes"], 1 + 128 * 33)
            report["first_settlement_resources"] = resources
            report["full_standalone_share_bytes"] = sum(len(proof.serialize()) for proof in proofs)
            assert resources["usage"]["share_bytes"] + resources["usage"]["job_table_bytes"] < report["full_standalone_share_bytes"] // 4
            # Keep the shared descriptor internally consistent, but substitute
            # its origin authorization. Native validation must still reject it.
            changed_shares = tuple(replace(proof, owner_signature=b"x" * 64)
                if proof.envelope == origins[0][1].envelope else proof for proof in first_state.shares)
            self.reject_snapshot(signers[0], {"template": first.serialize().hex()},
                replace(first_state, shares=changed_shares), "share-authorization")
            expected = {signer.payout_script: 1_666_666_666 for signer in signers[:3]}
            assert_equal(self.payouts(first), expected)
            self.publish(0, first, first_state)
            self.connect_nodes(0, 1)
            self.wait_tip(first)
            assert_equal(gate.batch_status()["selected_proofs"], ())
            statuses = gate.receipt_status(limit=256)["receipts"]
            assert_equal({receipt["status"] for receipt in statuses}, {"confirmed_admitted"})
            assert_equal(len(statuses), 128)
            assert_equal(follower.getsharepoolhashsnapshot(first_state.hash_hex)["data"], first_state.serialize().hex())

            second, second_state, prepared = self.construct(0, signers[1])
            assert_equal(self.payouts(second), expected)
            self.reject_snapshot(signers[1], prepared, replace(second_state, history_head=second_state.history_head ^ 1), "history")
            self.reject_snapshot(signers[1], prepared, replace(second_state, payouts=(CTxOut(1, signers[0].payout_script),)), "payout")
            # A signed snapshot cannot re-admit a previously confirmed proof.
            with_duplicate = self.proposal(0, signers[0], templates=(origins[0][0],), shares=(proofs[0],))
            assert_raises_rpc_error(-26, "", node.preparesharepoolhashjob, with_duplicate.serialize().hex())
            self.publish(0, second, second_state)
            self.wait_tip(second)
            third, third_state, _ = self.construct(0, signers[3])
            assert_equal(self.payouts(third), {signers[3].payout_script: 5_000_000_000})

            self.log.info("Missing compact ancestry remains pending through restart and recovers over native P2P")
            self.disconnect_nodes(0, 1)
            self.stop_node(1)
            shutil.rmtree(Path(follower.chain_path) / "sharepool-snapshots-v7")
            shutil.rmtree(Path(follower.chain_path) / "sharepool-tides-index-v7")
            self.start_node(1)
            self.store(1, second_state)
            self.store(1, third_state)
            third.solve()
            assert_equal(follower.submitblock(third.serialize().hex()), "sharepool-hash-data-missing")
            assert_equal(follower.getbestblockhash(), second.hash)
            self.restart_node(1)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.publish(0, third, third_state)
            self.connect_nodes(0, 1)
            self.wait_tip(third)

            # A current tip can use authenticated recent certificates without
            # reopening every old origin. Offline reindex also needs those
            # original openings, so wait for full P2P evidence recovery first.
            def original_openings_recovered():
                available = set(follower.getsharepoolhashstatus()["inventory"])
                return all(opening.hash_hex in available for _, opening, _ in origins)
            self.wait_until(original_openings_recovered, timeout=120)
            for _, opening, _ in origins:
                assert_equal(follower.getsharepoolhashsnapshot(opening.hash_hex)["data"], opening.serialize().hex())

            self.log.info("Competing branches derive their own omitted state and history")
            self.disconnect_nodes(0, 1)
            a = self.origin(0, signers[0])
            left, left_state = self.mine(0, signers[0], templates=(a[0],), shares=(a[2],))
            b = self.origin(1, signers[1])
            right, right_state = self.mine(1, signers[1], templates=(b[0],), shares=(b[2],))
            assert self.payouts(left) != self.payouts(right)
            right, right_state = self.mine(1, signers[1])
            self.connect_nodes(0, 1)
            self.wait_tip(right)
            assert_equal(node.getblockheader(left.hash)["confirmations"], -1)

            self.log.info("Persistent local history survives restart and falls back when its local seal is unavailable")
            node.getsharepoolhashtidesbudget(f"{signers[0].pool:064x}", signers[0].payout_script.hex())
            before = node.getsharepoolhashstatus()["history_index"]
            assert before["available"] and before["covered_blocks"] > 0
            self.disconnect_nodes(0, 1)
            self.restart_node(0)
            assert_equal(node.getsharepoolhashstatus()["history_index"], before)
            normal, normal_state, _ = self.construct(0, signers[0])
            self.stop_node(0)
            seal = Path(node.chain_path) / "sharepool-tides-index-v7" / "seal.key"
            saved = seal.with_name("seal.saved")
            seal.rename(saved)
            try:
                self.start_node(0)
                status = node.getsharepoolhashstatus()["history_index"]
                assert not status["available"] and status["error"]
                fallback, fallback_state, _ = self.construct(0, signers[0])
                assert_equal(self.payouts(fallback), self.payouts(normal))
                assert_equal(fallback_state.history_head, normal_state.history_head)
                self.stop_node(0)
            finally:
                saved.rename(seal)
            self.start_node(0)
            for flags in (["-reindex-chainstate"], ["-reindex"]):
                self.restart_node(1, extra_args=self.extra_args[1] + flags)
                assert_equal(follower.getbestblockhash(), right.hash)
                assert follower.verifychain(4, 0)
            self.check_guards(right)
            report.update(result="passed", admitted_proofs=128, jobs=4, final_height=node.getblockcount(),
                          checks=["exact_python_native_wire", "native_payouts", "independent_pools", "replay_rejected",
                                  "history_payout_mutation_rejected", "shared_descriptor_authorization_rejected", "p2p", "pending_restart", "fork_reorg",
                                  "persistent_history_restart", "missing_seal_fallback", "reindex", "profile_isolation"])
            (directory / "compact-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            for gate in gates:
                gate.close()
            for key in keys:
                key.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashCompactTest(__file__).main()
