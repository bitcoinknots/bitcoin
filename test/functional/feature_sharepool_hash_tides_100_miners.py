#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""100 v6 gates build, attest, dispatch and admit distinct native mining jobs.

Two disposable native nodes exchange the complete flat-hash openings over P2P.
The 100 logical miners each have their own signer and durable gate. One gate
collects all proofs; this does not simulate 100 native nodes or WAN performance.
The boundary native-height cohort is clipped proportionally, so all 100 miners
in the initial admission cohort remain eligible even at easy regtest difficulty.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from fractions import Fraction
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, TemplateRecord, TIDES_VERSION, share_work, solve_share, winner_share
from native_mining_gate import parse_block
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex, uint256_from_compact
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal, assert_raises, assert_raises_rpc_error


class SharePoolHashTides100MinersTest(SharePoolHashTidesTest):
    MINERS = 100
    FEE = 1_000

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=102", "-sharepoolhashonly=1", "-sharepooltides=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(2)]

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=102, choices=(102,))
        parser.add_argument("--results", type=Path, help="Public isolated-regtest evidence JSON")

    @staticmethod
    def spend(previous, index, value, redeem, script, fee):
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(previous, index), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(value - fee, CScript(script))]
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(redeem)]
        transaction.rehash()
        return transaction

    def open_gate(self, index, signer):
        return HashMiningGate(self.directory / f"miner-{index:03d}.sqlite",
            rpc=lambda method, *args: getattr(self.nodes[0], method)(*args),
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=TIDES_VERSION, activation_height=102)

    def admitted_job(self, gate, signer):
        block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        assert gate.ready_for_dispatch(authorization)
        assert_equal(authorization.block_bytes, block.serialize())
        assert_equal(authorization.snapshot_bytes, snapshot.serialize())
        gate.register_snapshot(snapshot.serialize())
        return block, snapshot, authorization

    def check_payouts(self, block, snapshot, history, *, reward):
        """Independent Fraction oracle for the exact native-height cohort window.

        Entries explicitly retain their admission height, distinct from a proof's
        origin height. Every member of the boundary cohort receives the same
        proportional clipping fraction. Proof ID never determines entitlement.
        """
        remaining = Fraction(8 << 256, uint256_from_compact(block.nBits) + 1)
        weights, selected = {}, []
        cohorts = {}
        for admitted_height, proof in history:
            if proof.envelope.pool != snapshot.envelope.pool:
                continue
            cohorts.setdefault(admitted_height, []).append(proof)
        for admitted_height in sorted(cohorts, reverse=True):
            if remaining == 0:
                break
            cohort = cohorts[admitted_height]
            total_work = sum(share_work(proof.header.nBits, TIDES_VERSION) for proof in cohort)
            included = min(remaining, Fraction(total_work))
            fraction = included / total_work
            for proof in cohort:
                script = proof.envelope.payout_script
                contribution = share_work(proof.header.nBits, TIDES_VERSION) * fraction
                weights[script] = weights.get(script, Fraction(0)) + contribution
                selected.append(proof.proof_id)
            remaining -= included
        assert weights  # Bootstrap is tested separately, never hidden here.
        total = sum(weights.values())
        expected = {script: int(reward * work / total) for script, work in weights.items()
                    if int(reward * work / total)}
        assert_equal(self.payouts(block), expected)
        assert_equal({bytes(output.scriptPubKey): output.nValue for output in snapshot.payouts}, expected)
        assert_equal([output.serialize() for output in block.vtx[0].vout[:len(snapshot.payouts)]],
                     [output.serialize() for output in snapshot.payouts])
        # The only non-payout output is the ordinary BIP141 witness commitment.
        assert len(block.vtx[0].vout) - len(snapshot.payouts) in (0, 1)
        for output in block.vtx[0].vout[len(snapshot.payouts):]:
            assert_equal(output.nValue, 0)
            assert bytes(output.scriptPubKey).startswith(bytes.fromhex("6a24aa21a9ed"))
        assert_equal(block.m_mm_rhs, snapshot.hash)
        assert_equal((snapshot.pending, snapshot.settled), ((), ()))
        record = {"height": block.m_height, "commitment": snapshot.hash_hex,
                  "new_admissions": len(snapshot.shares), "eligible_proofs": len(selected),
                  "payout_scripts": len(expected), "reward_satoshis": reward,
                  "unclaimed_rounding_satoshis": reward - sum(expected.values()),
                  "whole_admission_height_cohorts_verified": True,
                  "exact_rational_window_and_coinbase_verified": True}
        self.report["rewards"].append(record)
        return selected

    def save_report(self):
        if self.options.results:
            self.options.results.parent.mkdir(parents=True, exist_ok=True)
            self.options.results.write_text(json.dumps(self.report, indent=2) + "\n")

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        self.pool = 0x60100
        self.directory = Path(self.options.tmpdir) / "tides-logical-miners"
        self.directory.mkdir(mode=0o700)
        self.gates, keys = [], []
        self.report = {"schema": 2, "profile": "hash-only-v6-tides", "rules_revision": 2, "result": "running",
            "started_utc": datetime.now(timezone.utc).isoformat(), "network": "isolated native regtest",
            "logical_miners": self.MINERS, "native_nodes": 2, "physical_miners_used": 0,
            "transport": "v2" if self.options.v2transport else "v1", "rewards": [],
            "native_binary_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
            "limitations": ["100 logical gates use one validating node; a second node validates through P2P",
                "The coordinator collects all proofs; full 100-by-100 gate replication is not simulated",
                "Regtest proves protocol behavior, not mainnet capacity, sampling variance or WAN performance",
                "Proof target is deliberately easy; approximately 16 units of work are proportionally drawn from complete admission-height cohorts",
                "Only acknowledged work admitted into canonical history becomes recurring reward-eligible"]}
        started = time.monotonic()
        try:
            self.connect_nodes(0, 1)
            redeem = CScript([OP_TRUE])
            funded = self.generatetoaddress(node, 100, script_to_p2wsh(redeem))
            coinbase = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
            coinbase.rehash()
            funding_script = b"\x00\x20" + hashlib.sha256(bytes(redeem)).digest()
            funding_value = 49_999_900
            funding = self.spend(coinbase.sha256, 0, coinbase.vout[0].nValue, redeem, funding_script, 10_000)
            funding.vout = [CTxOut(funding_value, CScript(funding_script)) for _ in range(self.MINERS)]
            funding.rehash()
            node.sendrawtransaction(funding.serialize().hex())
            self.generatetoaddress(node, 1, script_to_p2wsh(redeem))
            self.sync_blocks()
            assert_equal(node.getblockcount(), 101)
            assert_equal(node.getrawmempool(), [])

            self.log.info("100 separate native builders/signers/gates validate and dispatch distinct transaction sets")
            scripts = [b"\x00\x14" + index.to_bytes(20, "big") for index in range(1, self.MINERS + 1)]
            signers, origins, proofs, transactions = [], [], [], []
            for index, script in enumerate(scripts):
                path = self.directory / f"owner-{index:03d}.key"
                keys.append(path)
                signer = HashSigner.create(self.signer_binary, path, pool=self.pool, payout_script=script)
                signers.append(signer)
                gate = self.open_gate(index, signer)
                self.gates.append(gate)
                transaction = self.spend(funding.sha256, index, funding_value, redeem, script, self.FEE)
                node.sendrawtransaction(transaction.serialize().hex())
                transactions.append(transaction)
                block, snapshot, authorization = self.admitted_job(gate, signer)
                assert_equal(len(block.vtx), index + 2)
                assert_equal({tx.rehash() for tx in block.vtx[1:]}, {tx.rehash() for tx in transactions})
                assert_equal(self.payouts(block), {script: 5_000_000_000 + (index + 1) * self.FEE})
                assert gate.ready_for_dispatch(authorization)
                # Simulated work consumes the exact bytes approved for dispatch.
                proof = solve_share(parse_block(authorization.block_bytes), snapshot)
                worked = parse_block(authorization.block_for_header(proof.header_bytes))
                assert_equal(CBlockHeader(worked).serialize(), proof.header_bytes)
                assert_equal([tx.serialize_with_witness() for tx in worked.vtx],
                             [tx.serialize_with_witness() for tx in block.vtx])
                gate.receive(proof)
                assert_equal(gate.archive_head()["receipt_revision"], 1)
                origins.append((block, snapshot))
                proofs.append(proof)
                if index % 20 == 19:
                    self.log.info("%d/100 distinct native jobs dispatched and shares durably acknowledged", index + 1)
            assert_equal(len({signer.public_key for signer in signers}), self.MINERS)
            assert_equal(len({TemplateRecord.from_block(block).template_id for block, _ in origins}), self.MINERS)
            assert_equal(len({block.hashMerkleRoot for block, _ in origins}), self.MINERS)
            assert_equal(len({proof.proof_id for proof in proofs}), self.MINERS)

            self.log.info("Reject altered payout/pool proof bindings before acknowledgement")
            collector, signer = self.gates[0], signers[0]
            before = collector.archive_head()
            for envelope in (replace(proofs[0].envelope, payout_script=scripts[1]),
                             replace(proofs[0].envelope, pool=self.pool + 1)):
                bad = replace(proofs[0], envelope=envelope)
                assert_raises(ValueError, collector.receive, bad)
                assert_raises_rpc_error(-26, "", node.validatesharepoolhashshare, bad.serialize().hex())
                assert_equal(collector.archive_head(), before)

            self.log.info("Collect and admit all 100 proofs with full origins; apply the exact rolling window")
            for (block, snapshot), proof in zip(origins[1:], proofs[1:]):
                collector.register_snapshot(snapshot.serialize())
                collector.register_template(block.serialize())
                collector.receive(proof)
            assert_equal(collector.archive_head()["receipt_revision"], self.MINERS)
            batch = collector.batch_status()
            assert_equal((batch["eligible_count"], batch["deferred_count"]), (self.MINERS, 0))
            assert_equal(len(batch["selected_proofs"]), self.MINERS)
            first, first_state, authorization = self.admitted_job(collector, signer)
            assert_equal(len(first_state.templates), self.MINERS)
            assert_equal(len(first_state.shares), self.MINERS)
            assert_equal(len(first_state.certificates), self.MINERS)
            history = [(first.m_height, proof) for proof in proofs]
            selected = self.check_payouts(first, first_state, history,
                                         reward=5_000_000_000 + self.MINERS * self.FEE)
            assert_equal(len(selected), self.MINERS)
            assert_equal(len(first_state.payouts), self.MINERS)
            assert_equal(len(first.vtx) - 1, self.MINERS)
            assert collector.ready_for_dispatch(authorization)

            self.log.info("A forged payout is refused; late work cannot rewrite a dispatched snapshot")
            wrong = replace(first_state, payouts=(CTxOut(1, CScript(scripts[0])),))
            wrong = replace(wrong, owner_signature=signer.sign_owner(wrong))
            assert_raises_rpc_error(-26, "payout", node.finalizesharepoolhashjob,
                                    first.serialize().hex(), wrong.serialize().hex())
            frozen = authorization.block_bytes, authorization.snapshot_bytes
            first.solve()  # The valid frozen job was dispatched before the next ACK.
            assert_equal(authorization.block_for_header(CBlockHeader(first).serialize()), first.serialize())
            late = solve_share(origins[0][0], origins[0][1], start_nonce=proofs[0].header.nNonce + 1)
            collector.receive(late)
            assert not collector.ready_for_dispatch(authorization)
            assert_equal((authorization.block_bytes, authorization.snapshot_bytes), frozen)
            assert late.proof_id not in {proof.proof_id for proof in first_state.shares}
            assert_equal(node.submitblock(first.serialize().hex()), None)
            self.wait_tip(first)
            for _, opening in origins:
                assert_equal(follower.getsharepoolhashsnapshot(opening.hash_hex)["data"], opening.serialize().hex())
            assert_equal(follower.getblock(first.hash, 0), first.serialize().hex())
            winner = winner_share(first, first_state)
            assert winner.proof_id not in {proof.proof_id for proof in first_state.shares}
            collector.receive(winner)
            receipts = collector.receipt_status()["receipts"]
            assert_equal(sum(receipt["status"] == "confirmed_admitted" for receipt in receipts), self.MINERS)
            assert_equal(sum(receipt["status"] == "provisional" for receipt in receipts), 2)

            self.log.info("The next native job carries late/winning work and rewards the rolling history again")
            batch = collector.batch_status()
            assert_equal((batch["eligible_count"], batch["deferred_count"]), (2, 0))
            second, second_state, next_authorization = self.admitted_job(collector, signer)
            assert_equal({proof.proof_id for proof in second_state.shares}, {late.proof_id, winner.proof_id})
            history.extend((second.m_height, proof) for proof in (late, winner))
            assert all(admitted_height > proof.envelope.height for admitted_height, proof in history[-2:])
            self.check_payouts(second, second_state, history, reward=5_000_000_000)
            assert collector.ready_for_dispatch(next_authorization)
            second.solve()
            assert_equal(node.submitblock(second.serialize().hex()), None)
            self.wait_tip(second)
            assert_equal(len(collector.eligible_shares()), 0)
            assert all(receipt["status"] == "confirmed_admitted" for receipt in collector.receipt_status()["receipts"])

            self.log.info("The same recipient may join a different pool; previous pool work is not borrowed")
            other_path = self.directory / "other-pool.key"
            keys.append(other_path)
            other = HashSigner.create(self.signer_binary, other_path, pool=self.pool + 1, payout_script=scripts[0])
            other_job, other_state, _ = self.construct(0, other)
            assert_equal(self.payouts(other_job), {scripts[0]: 5_000_000_000})
            assert_equal(other_state.shares, ())
            assert other.public_key != signer.public_key
            assert_equal(other_state.envelope.payout_script, first_state.envelope.payout_script)

            self.log.info("Native and gate restarts preserve recurring history and invalidate old dispatch capabilities")
            collector.close()
            collector = self.open_gate(0, signer)
            self.gates[0] = collector
            assert not collector.ready_for_dispatch(next_authorization)
            assert_equal(collector.archive_head()["receipt_revision"], self.MINERS + 2)
            repeat, repeat_state, repeat_auth = self.admitted_job(collector, signer)
            assert_equal(repeat_state.shares, ())
            self.check_payouts(repeat, repeat_state, history, reward=5_000_000_000)
            assert collector.ready_for_dispatch(repeat_auth)
            self.restart_node(1)
            assert_equal(follower.getbestblockhash(), second.hash)
            self.connect_nodes(0, 1)
            repeat.solve()
            assert_equal(node.submitblock(repeat.serialize().hex()), None)
            self.wait_tip(repeat)
            assert_equal(follower.getblock(repeat.hash, 0), repeat.serialize().hex())
            self.report.update(result="passed", distinct_valid_native_templates=self.MINERS,
                independent_valid_transactions=self.MINERS, authorized_initial_jobs=self.MINERS,
                initial_shares_admitted=self.MINERS, carried_late_and_winning_shares=2,
                proof_binding_rejections=2, invalid_payout_rejections=1,
                frozen_late_work_verified=True, same_address_separate_pool_accepted=True,
                native_and_gate_restart_verified=True, full_snapshot_p2p_follower_verified=True,
                seconds=round(time.monotonic() - started, 3))
        except BaseException:
            self.report.update(result="failed", seconds=round(time.monotonic() - started, 3))
            raise
        finally:
            for gate in self.gates:
                gate.close()
            for path in keys:
                path.unlink(missing_ok=True)
            self.save_report()


if __name__ == "__main__":
    SharePoolHashTides100MinersTest(__file__).main()
