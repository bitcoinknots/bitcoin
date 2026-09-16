#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native DATUM-style refresh cadence, frozen jobs and immediate chain changes.

An injected monotonic clock advances refresh deadlines without sleeping. Native
transaction, signature, proof, block, payout and reorg validation remain real.
This small isolated regtest fixture is not a throughput or hardware benchmark.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_job_scheduler import HashJobScheduler
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, Snapshot, job_hash
from native_mining_gate import parse_block
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class SharePoolHashDatumCadenceTest(SharePoolHashTidesTest):
    PROFILE_VERSION = 7

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=102, choices=(102,))

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=102", "-sharepoolhashonly=1", "-sharepooltides=1",
                            "-sharepoolcompacttides=1", "-testactivationheight=blake2b@1",
                            "-disablewallet", "-networkactive=0"]]

    @staticmethod
    def unpack(authorization):
        block = parse_block(authorization.block_bytes)
        snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
        assert_equal(block.m_mm_rhs, snapshot.hash)
        assert_equal(job_hash(block), snapshot.job_commitment)
        return block, snapshot

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        directory = Path(self.options.tmpdir)
        keys = [directory / f"cadence-owner-{index}.key" for index in range(2)]
        gate, scheduler = None, None
        report = {
            "network": "isolated native regtest", "profile": "hash-only-v7-compact-tides",
            "scope": "Injected refresh clock; actual native transactions, signatures, proofs, payouts and reorgs",
            "work_update_seconds": 40, "activation_height": 102,
            "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
            "signer_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
            "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                for name in ("contrib/sharepool/hash_job_scheduler.py", "contrib/sharepool/hash_mining_gate.py",
                             "test/functional/feature_sharepool_hash_datum_cadence.py")},
        }
        try:
            redeem = CScript([OP_TRUE])
            funded = self.generatetoaddress(node, 101, script_to_p2wsh(redeem))
            signers = [HashSigner.create(self.signer_binary, key, pool=101,
                payout_script=b"\x00\x14" + bytes([index + 1]) * 20) for index, key in enumerate(keys)]
            gate = HashMiningGate(directory / "cadence-gate.sqlite",
                rpc=lambda method, *args: getattr(node, method)(*args), profile_version=7,
                activation_height=102, pool=101, public_key=signers[0].public_key,
                payout_script=signers[0].payout_script)
            origins = [self.origin(0, signer) for signer in signers]
            for block, opening, _ in origins:
                gate.register_snapshot(opening.serialize())
                gate.register_template(block.serialize())
            assert gate.receive(origins[0][2])
            clock = Clock()
            published, withdrawn = [], []
            signing = {"mode": "normal"}

            def sign_owner(snapshot):
                if signing["mode"] == "invalid":
                    return bytes(64)
                if signing["mode"] == "tip-race":
                    signing["mode"] = "normal"
                    node.invalidateblock(signing["block"])
                return signers[0].sign_owner(snapshot)

            def publish(authorization):
                # authorize validates with an overlay and retains local bytes;
                # the transport must separately make the opening available.
                gate.register_snapshot(authorization.snapshot_bytes)
                published.append(authorization)
                return True

            def withdraw():
                withdrawn.append(clock.now)

            scheduler = HashJobScheduler(gate, sign_owner=sign_owner, publish=publish,
                                         withdraw=withdraw, clock=clock)
            self.log.info("The first job freezes its exact snapshot and one-recipient coinbase")
            original = scheduler.poll()
            assert original is scheduler.active
            assert_equal(len(published), 1)
            assert_equal(scheduler.next_refresh_at, 40.0)
            original_block, original_snapshot = self.unpack(original)
            assert_equal({share.proof_id for share in original_snapshot.shares}, {origins[0][2].proof_id})
            assert_equal(self.payouts(original_block), {signers[0].payout_script: 5_000_000_000})
            frozen = (original.block_bytes, original.snapshot_bytes)

            self.log.info("A real mempool transaction and late ACK do not rewrite or repeatedly rebuild active work")
            funding = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
            funding.rehash()
            transaction = CTransaction()
            transaction.vin = [CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff)]
            transaction.vout = [CTxOut(funding.vout[0].nValue - 10_000, CScript(signers[0].payout_script))]
            witness = CTxInWitness()
            witness.scriptWitness.stack = [bytes(redeem)]
            transaction.wit.vtxinwit = [witness]
            transaction.rehash()
            clock.now = 5.0
            assert_equal(node.sendrawtransaction(transaction.serialize().hex()), transaction.hash)
            assert_equal(node.getrawmempool(), [transaction.hash])
            assert gate.receive(origins[1][2])
            assert_equal(gate.ready_for_dispatch(original), False)
            assert_equal(gate.ready_for_continued_work(original), True)
            for moment in (5.0, 10.0, 20.0, 39.999):
                clock.now = moment
                assert_equal(scheduler.poll(), None)
                assert scheduler.active is original
                assert_equal(scheduler.next_refresh_at, 40.0)
                assert_equal((original.block_bytes, original.snapshot_bytes), frozen)
            assert_equal(len(published), 1)
            report["coalesced_updates"] = {
                "mempool_transaction": transaction.hash, "late_receipt_retained": True,
                "poll_times": [5.0, 10.0, 20.0, 39.999], "publications_before_deadline": 1,
                "strict_redispatch_refused": True, "already_issued_work_continues": True,
                "original_bytes_unchanged": True,
            }

            self.log.info("At the 40-second deadline the next native job includes the transaction and both ACKs")
            clock.now = 40.0
            refreshed = scheduler.poll()
            assert refreshed is scheduler.active
            assert_equal(len(published), 2)
            assert_equal(scheduler.next_refresh_at, 80.0)
            refreshed_block, refreshed_snapshot = self.unpack(refreshed)
            assert_equal(refreshed_block.hashPrevBlock, original_block.hashPrevBlock)
            assert_equal([tx.serialize_with_witness() for tx in refreshed_block.vtx[1:]],
                         [transaction.serialize_with_witness()])
            expected_proofs = {origin[2].proof_id for origin in origins}
            assert_equal({share.proof_id for share in refreshed_snapshot.shares}, expected_proofs)
            assert_equal(self.payouts(refreshed_block), {signer.payout_script: 2_500_005_000 for signer in signers})
            report["normal_refresh"] = {
                "clock": 40.0, "next_refresh_at": 80.0, "transaction_included": True,
                "acknowledged_proofs_included": 2,
                "payouts": {script.hex(): amount for script, amount in self.payouts(refreshed_block).items()},
            }

            self.log.info("A solved older job remains valid with its original commitment and original payout")
            assert_equal((original.block_bytes, original.snapshot_bytes), frozen)
            original_block.solve()
            assert_equal(node.submitblock(original_block.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), original_block.hash)
            accepted = from_hex(CBlock(), node.getblock(original_block.hash, 0))
            assert_equal(accepted.m_mm_rhs, original_snapshot.hash)
            assert_equal(self.payouts(accepted), {signers[0].payout_script: 5_000_000_000})
            assert transaction.hash in node.getrawmempool()
            report["older_job_solution"] = {
                "accepted_block": original_block.hash, "snapshot_hash": original_snapshot.hash_hex,
                "original_payout_preserved": True, "late_receipt_deferred": True,
            }

            self.log.info("A new native block bypasses the interval and retains the late work for the next block")
            clock.now = 41.0
            after_block = scheduler.poll()
            child, child_snapshot = self.unpack(after_block)
            assert_equal(child.hashPrevBlock, int(original_block.hash, 16))
            assert_equal(scheduler.next_refresh_at, 81.0)
            assert_equal({share.proof_id for share in child_snapshot.shares}, {origins[1][2].proof_id})
            assert_equal([tx.serialize_with_witness() for tx in child.vtx[1:]], [transaction.serialize_with_witness()])
            assert_equal(self.payouts(child), {signer.payout_script: 2_500_005_000 for signer in signers})
            child.solve()
            assert_equal(node.submitblock(child.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), child.hash)
            assert_equal(node.getrawmempool(), [])
            clock.now = 42.0
            descendant = scheduler.poll()
            assert_equal(descendant.native_parent, child.hash)
            assert_equal(scheduler.next_refresh_at, 82.0)
            report["new_block_refresh"] = {
                "clock": 41.0, "previous_deadline": 80.0, "parent": original_block.hash,
                "late_proof_included": True, "settled_child": child.hash,
            }

            self.log.info("Actual native rollback and restoration each replace stale work immediately")
            node.invalidateblock(child.hash)
            assert_equal(node.getbestblockhash(), original_block.hash)
            clock.now = 43.0
            rollback = scheduler.poll()
            assert_equal(rollback.native_parent, original_block.hash)
            assert_equal(rollback.native_height, 102)
            assert_equal(scheduler.next_refresh_at, 83.0)
            rollback_block, rollback_snapshot = self.unpack(rollback)
            assert_equal({share.proof_id for share in rollback_snapshot.shares}, {origins[1][2].proof_id})
            assert_equal(self.payouts(rollback_block), self.payouts(child))
            node.reconsiderblock(child.hash)
            assert_equal(node.getbestblockhash(), child.hash)
            clock.now = 44.0
            restored = scheduler.poll()
            assert_equal(restored.native_parent, child.hash)
            assert_equal(scheduler.next_refresh_at, 84.0)
            report["reorg_refresh"] = {
                "rollback_clock": 43.0, "rollback_parent": original_block.hash,
                "restoration_clock": 44.0, "restoration_parent": child.hash,
                "deferred_work_and_payout_recomputed": True,
            }

            self.log.info("Invalid signing and a real tip change during signing never publish replacement work")
            clock.now = 84.0
            signing["mode"] = "invalid"
            before_published, before_withdrawn = len(published), len(withdrawn)
            try:
                scheduler.poll()
            except ValueError as error:
                assert "invalid job attestation" in str(error)
            else:
                raise AssertionError("invalid signer response was dispatched")
            assert_equal(len(published), before_published)
            assert_equal(len(withdrawn), before_withdrawn + 1)
            assert_equal(scheduler.active, None)
            signing["mode"] = "normal"
            recovered = scheduler.poll()
            assert_equal(recovered.native_parent, child.hash)
            assert_equal(scheduler.next_refresh_at, 124.0)

            clock.now = 124.0
            signing.update(mode="tip-race", block=child.hash)
            before_published, before_withdrawn = len(published), len(withdrawn)
            try:
                scheduler.poll()
            except ValueError as error:
                assert "native tip changed" in str(error)
            else:
                raise AssertionError("a job prepared across a native tip race was dispatched")
            assert_equal(len(published), before_published)
            assert_equal(len(withdrawn), before_withdrawn + 1)
            assert_equal(scheduler.active, None)
            node.reconsiderblock(child.hash)
            final = scheduler.poll()
            assert_equal(final.native_parent, child.hash)
            assert gate.ready_for_dispatch(final)
            assert node.verifychain(4, 0)
            statuses = gate.receipt_status(limit=16)["receipts"]
            assert_equal(len(statuses), 2)
            assert_equal({item["status"] for item in statuses}, {"confirmed_admitted"})
            report.update(result="passed", final_height=node.getblockcount(),
                          failure_fences={"invalid_signer_refused": True, "native_tip_race_refused": True,
                                          "withdrawal_before_retry": True},
                          acknowledged_and_confirmed_receipts=2, publications=len(published),
                          withdrawals=len(withdrawn), final_native_parent=final.native_parent)
            (directory / "datum-cadence-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            if scheduler is not None:
                scheduler.close()
            if gate is not None:
                gate.close()
            for key in keys:
                key.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashDatumCadenceTest(__file__).main()
