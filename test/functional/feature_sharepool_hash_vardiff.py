#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent miner targets, native work-weighted payouts and v8 history replay.

Synthetic, isolated regtest work. Neither share cadence nor independent template
construction is inferred from these deterministic correctness fixtures.
"""
from collections import defaultdict
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, Share, TemplateRecord, rules_hash, share_target, solve_share
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.messages import CBlockHeader, CTxOut
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashVardiffTest(SharePoolHashTidesTest):
    PROFILE_VERSION = 8

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=1, choices=(1,))
        parser.add_argument("--miners", type=int, default=100)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = ["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
                  "-sharepoolcompacttides=1", "-testactivationheight=blake2b@1", "-disablewallet"]
        self.extra_args = [common + ["-sharepoolvardiff=1"] for _ in range(2)] + [common]
        self.assignments = {}

    def proposal(self, index, signer, *, share_work_bits=None, **kwargs):
        proposal = super().proposal(index, signer, **kwargs)
        bits = self.assignments.get(signer.public_key, 0) if share_work_bits is None else share_work_bits
        return replace(proposal, envelope=replace(proposal.envelope, share_work_bits=bits))

    def wait_tip(self, block):
        self.wait_until(lambda: all(node.getbestblockhash() == block.hash for node in self.nodes[:2]), timeout=120)
        for node in self.nodes[:2]:
            assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

    def expected_payouts(self, proofs, reward=5_000_000_000):
        # Independent integer oracle: all selected proofs enter at one height,
        # so proportional TIDES boundary sharing preserves these work ratios.
        work = defaultdict(int)
        for proof in proofs:
            work[proof.envelope.payout_script] += 1 << proof.envelope.share_work_bits
        total = sum(work.values())
        return {script: reward * amount // total for script, amount in work.items() if reward * amount // total}

    def run_test(self):
        node, follower, legacy = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        assert 3 <= self.options.miners <= 100, "bounded 3..100 miner fixture required"
        directory = Path(self.options.tmpdir)
        paths, gates = [], []
        report = {"network": "isolated native regtest", "profile": "hash-only-v8-vardiff-tides",
                  "miners": self.options.miners, "hardware_used": False,
                  "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
                  "rules": f"{rules_hash(8):064x}", "checks": []}
        try:
            for current in self.nodes[:2]:
                status = current.getsharepoolhashstatus()
                assert_equal(status["mode"], report["profile"])
                assert_equal(status["rules"], report["rules"])
            assert_equal(legacy.getsharepoolhashstatus()["mode"], "hash-only-v7-compact-tides")
            self.log.info("Independent miners commit three different assigned targets at the same native difficulty")
            signers, origins = [], []
            for index in range(self.options.miners):
                path = directory / f"vardiff-owner-{index}.key"
                paths.append(path)
                signer = HashSigner.create(self.signer_binary, path, pool=101,
                    payout_script=b"\x00\x14" + (index + 1).to_bytes(20, "big"))
                signers.append(signer)
                self.assignments[signer.public_key] = (2, 4, 6)[index % 3]
                origins.append(self.origin(0, signer))
            assert_equal(len({TemplateRecord.from_block(item[0]).template_id for item in origins}), self.options.miners)
            assert_equal(len({item[0].nBits for item in origins}), 1)
            assert_equal({item[1].envelope.share_work_bits for item in origins}, {2, 4, 6})
            proofs = [item[2] for item in origins]

            self.log.info("Assignment changes, another miner's authorization and insufficient work are rejected")
            proof = proofs[0]
            altered = replace(proof, envelope=replace(proof.envelope, share_work_bits=6))
            assert_raises_rpc_error(-26, "bad-sharepool", node.validatesharepoolhashshare, altered.serialize().hex())
            relabeled = replace(proof, envelope=proofs[1].envelope, owner_signature=proofs[1].owner_signature)
            assert_raises_rpc_error(-26, "bad-sharepool", node.validatesharepoolhashshare, relabeled.serialize().hex())
            header = CBlockHeader(origins[2][0])
            target = share_target(header.nBits, 8, share_work_bits=6)
            while header.rehash() <= target:
                header.nNonce += 1
            insufficient = Share(header.serialize(), proofs[2].envelope, proofs[2].owner_signature)
            assert_raises_rpc_error(-26, "bad-sharepool", node.validatesharepoolhashshare, insufficient.serialize().hex())
            report["checks"] += ["assigned_target_bound_before_work", "miner_relabel_rejected", "insufficient_share_work_rejected"]

            gate = HashMiningGate(directory / "vardiff-gate.sqlite", rpc=lambda method, *args: getattr(node, method)(*args),
                pool=101, public_key=signers[0].public_key, payout_script=signers[0].payout_script,
                profile_version=8, share_work_bits=2)
            gates.append(gate)
            for block, snapshot, proof in origins:
                gate.register_snapshot(snapshot.serialize())
                gate.register_template(block.serialize())
                assert gate.receive(proof)
            first, first_snapshot = gate.make_native(sign_owner=signers[0].sign_owner)
            authorization = gate.authorize(first.serialize(), first_snapshot.serialize())
            assert gate.ready_for_dispatch(authorization)
            assert_equal(len(first_snapshot.shares), self.options.miners)
            assert_equal(self.payouts(first), self.expected_payouts(proofs))
            assert_equal(len(self.payouts(first)), self.options.miners)
            frozen = authorization.block_bytes, authorization.snapshot_bytes
            gate.set_share_work_bits(6)
            assert gate.ready_for_continued_work(authorization)
            assert_equal((authorization.block_bytes, authorization.snapshot_bytes), frozen)
            changed, changed_snapshot = gate.make_native(sign_owner=signers[0].sign_owner)
            assert_equal(changed_snapshot.envelope.share_work_bits, 6)
            assert first.m_mm_rhs != changed.m_mm_rhs
            report["checks"] += ["exact_weighted_payouts", "retarget_only_future_jobs", "old_authorization_keeps_assigned_target"]
            report["first_settlement"] = {"shares": len(first_snapshot.shares),
                "recipients": len(self.payouts(first)), "snapshot_bytes": len(first_snapshot.serialize()),
                "assigned_work": sum(1 << proof.envelope.share_work_bits for proof in proofs),
                "paid_satoshis": sum(self.payouts(first).values())}
            self.publish(0, first, first_snapshot)
            self.connect_nodes(0, 1)
            self.wait_tip(first)

            self.log.info("A late old-target proof keeps its original credit alongside a new harder job")
            late = solve_share(origins[0][0], origins[0][1], start_nonce=proofs[0].header.nNonce + 1)
            other = solve_share(origins[1][0], origins[1][1], start_nonce=proofs[1].header.nNonce + 1)
            self.assignments[signers[0].public_key] = 6
            fresh_origin = self.origin(0, signers[0])
            current = [late, other, fresh_origin[2]]
            second, second_snapshot, prepared = self.construct(0, signers[0],
                templates=(origins[0][0], origins[1][0], fresh_origin[0]), shares=current)
            assert_equal(self.payouts(second), self.expected_payouts(current))
            assert_equal(late.envelope.share_work_bits, 2)
            assert_equal(fresh_origin[2].envelope.share_work_bits, 6)
            # The block's actual coinbase must still equal the native computed outputs.
            altered_outputs = list(second_snapshot.payouts)
            altered_outputs[0] = CTxOut(altered_outputs[0].nValue - 1, altered_outputs[0].scriptPubKey)
            self.reject_snapshot(signers[0], prepared, replace(second_snapshot, payouts=tuple(altered_outputs)), "payout")
            self.publish(0, second, second_snapshot)
            self.wait_tip(second)
            report["checks"] += ["late_proof_original_weight", "actual_coinbase_payout_mutation_rejected", "p2p_peer_validation"]

            self.log.info("Persistent history, restart and competing branches preserve assigned work weights")
            self.restart_node(1)
            replay, _, _ = self.construct(1, signers[1])
            assert_equal(self.payouts(replay), self.payouts(second))
            assert follower.verifychain(4, 0)
            self.connect_nodes(0, 1)
            self.disconnect_nodes(0, 1)
            left_origin = self.origin(0, signers[0])
            left, _ = self.mine(0, signers[0], templates=(left_origin[0],), shares=(left_origin[2],))
            assert_equal(self.payouts(left), {signers[0].payout_script: 5_000_000_000})
            self.assignments[signers[1].public_key] = 6
            right_origin = self.origin(1, signers[1])
            right, _ = self.mine(1, signers[1], templates=(right_origin[0],), shares=(right_origin[2],))
            right, _ = self.mine(1, signers[1])
            assert_equal(self.payouts(right), {signers[1].payout_script: 5_000_000_000})
            self.connect_nodes(0, 1)
            self.wait_tip(right)
            assert_equal(node.getblockheader(left.hash)["confirmations"], -1)
            report["checks"] += ["persistent_history_restart", "competing_fork_reorg_weights"]

            self.stop_node(1)
            marker = Path(follower.chain_path) / "sharepool-profile-v8"
            before = marker.read_bytes()
            follower.assert_start_raises_init_error(self.extra_args[2], "TIDES datadir profile", match=ErrorMatch.PARTIAL_REGEX)
            assert_equal(marker.read_bytes(), before)
            self.start_node(1, self.extra_args[1] + ["-reindex"])
            assert_equal(follower.getbestblockhash(), right.hash)
            assert follower.verifychain(4, 0)
            reindexed, _, _ = self.construct(1, signers[0])
            assert_equal(self.payouts(reindexed), self.payouts(right))
            report["checks"] += ["v7_v8_datadir_separation", "offline_reindex_weight_recovery"]
            (directory / "vardiff-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            for gate in gates:
                gate.close()
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashVardiffTest(__file__).main()
