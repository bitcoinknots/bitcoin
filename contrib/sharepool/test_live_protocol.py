#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial tests for authenticated reward jobs and delayed work settlement."""
from dataclasses import replace
import copy
import json
from pathlib import Path
import random
import tempfile
import unittest

from live_protocol import (Engine, MissingData, Rules, append_receipt,
                           canonical, decode_coinbase, decode_header, issue_job,
                           mine)
from signed_registry import (private_key, public_key, register, sign, update)
from work_accounting import expected_work
from precommit_demo import uint256_from_compact
from settlement_sim import inclusion_proof, merkle_root, verify_inclusion


class Fixture:
    def __init__(self, **rules):
        self.coordinator = private_key(901)
        self.keys = (private_key(902), private_key(903))
        self.rules = Rules(public_key(self.coordinator), **rules)
        self.engine = Engine(self.rules)
        self.registry_root = self.engine.genesis_registry
        self.ids, self.scripts = [], []
        for index, key in enumerate(self.keys):
            script = b"\x00\x20" + bytes([index + 1]) * 32
            change = register(self.engine.registry(self.registry_root), key,
                              f"miner-{index}".encode(), script)
            self.registry_root = self.engine.add_change(change)
            self.ids.append(change.entry.miner_id)
            self.scripts.append(script)

    def job(self, index=0, root=None, **kwargs):
        return issue_job(self.engine, self.keys[index], self.coordinator,
                         self.registry_root, root or self.engine.empty_ledger, **kwargs)

    def receipt(self, root, proof):
        return append_receipt(self.engine, self.coordinator, root, proof=proof)

    def seal(self, root, winner):
        return append_receipt(self.engine, self.coordinator, root, winner=winner)

    def resign(self, job, **changes):
        changed = replace(job, **changes)
        key = self.keys[self.ids.index(changed.manifest.miner_id)]
        return replace(changed, miner_signature=sign(key, changed.payload),
                       coordinator_signature=sign(self.coordinator, changed.payload))


class LiveProtocolTests(unittest.TestCase):
    def test_authenticated_jobs_are_full_reward_templates_with_distinct_tags(self):
        f = Fixture()
        first, second = f.job(), f.job(1)
        self.assertNotEqual(first.header, second.header)
        self.assertNotEqual(first.coinbase, second.coinbase)
        for index, job in enumerate((first, second)):
            self.assertTrue(f.engine.validate_job(job))
            tx = decode_coinbase(job.coinbase)
            self.assertEqual(sum(output.nValue for output in tx.vout), f.rules.reward)
            self.assertEqual(bytes(tx.vout[0].scriptPubKey), f.scripts[index])
            self.assertIn(f"miner-{index}".encode(), tx.vin[0].scriptSig)
            self.assertEqual(decode_header(job.header).hashMerkleRoot, tx.sha256)
            self.assertEqual(decode_header(job.header).m_mm_rhs,
                             int.from_bytes(job.manifest.root, "little"))
        # A single registered miner is sufficient: the removed percentage rule
        # must not reappear as a minimum participant or template count.
        winner = mine(first, full_block=True)
        block = f.engine.add_block(winner)
        self.assertEqual(dict(f.engine.state(block).balances), {f.scripts[0]: f.rules.reward})

    def test_new_verified_prefix_updates_sidechain_commitment_and_keeps_old_job(self):
        f = Fixture()
        old = f.job()
        share = mine(old, extranonce=1)
        receipt = f.receipt(f.engine.empty_ledger, share)
        refreshed = f.job(root=receipt.root, serial=1)
        self.assertNotEqual(old.manifest.ledger_root, refreshed.manifest.ledger_root)
        self.assertNotEqual(old.manifest.root, refreshed.manifest.root)
        self.assertNotEqual(decode_header(old.header).m_mm_rhs,
                            decode_header(refreshed.header).m_mm_rhs)
        self.assertTrue(f.engine.validate_job(old))
        self.assertTrue(f.engine.validate_job(refreshed))
        forged = replace(share, header=replace_header(share.header,
                            m_mm_rhs=decode_header(refreshed.header).m_mm_rhs))
        with self.assertRaisesRegex(ValueError, "committed job"):
            f.engine.claim(forged)

    def test_live_snapshot_inclusions_bind_every_receipt_context_and_leaf_count(self):
        f = Fixture()
        job = f.job()
        first = f.receipt(f.engine.empty_ledger, mine(job, extranonce=1))
        second = f.receipt(first.root, mine(job, extranonce=2))
        block = f.engine.add_block(mine(job, extranonce=3, full_block=True))
        seal = f.seal(second.root, block)
        roots = (f.engine.empty_ledger, first.root, second.root, seal.root)
        self.assertEqual(len({f.engine.snapshot_root(root) for root in roots}), 4)
        for receipt_count, root in enumerate(roots):
            leaves = f.engine.snapshot_leaves(root)
            snapshot_root = f.engine.snapshot_root(root)
            self.assertEqual(snapshot_root, merkle_root(leaves))
            self.assertEqual(len(leaves), receipt_count + 1)
            context = json.loads(leaves[0])
            self.assertEqual(context["receipt_count"], receipt_count)
            self.assertEqual(context["ledger_root"], root.hex())
            self.assertEqual(context["rules_root"], f.rules.root.hex())
            expected_receipts = (first.payload, second.payload, seal.payload)[:receipt_count]
            self.assertEqual(leaves[1:], expected_receipts)
            for index, leaf in enumerate(leaves):
                with self.subTest(receipt_count=receipt_count, index=index):
                    proof = inclusion_proof(leaves, index)
                    self.assertTrue(verify_inclusion(leaf, index, len(leaves), proof, snapshot_root))
                    self.assertFalse(verify_inclusion(leaf + b"tampered", index,
                                                      len(leaves), proof, snapshot_root))
                    self.assertFalse(verify_inclusion(leaf, index, len(leaves) + 1,
                                                      proof, snapshot_root))
                    self.assertFalse(verify_inclusion(leaf, index, len(leaves) - 1,
                                                      proof, snapshot_root))
                    if proof:
                        changed = (bytes([proof[0][0] ^ 1]) + proof[0][1:], *proof[1:])
                        self.assertFalse(verify_inclusion(leaf, index, len(leaves),
                                                          changed, snapshot_root))
        refreshed = f.job(root=seal.root)
        self.assertEqual(refreshed.manifest.share_snapshot_root, f.engine.snapshot_root(seal.root))

    def test_resigned_job_with_wrong_snapshot_merkle_root_is_rejected(self):
        f = Fixture()
        old = f.job()
        receipt = f.receipt(f.engine.empty_ledger, mine(old))
        job = f.job(root=receipt.root)
        manifest = replace(job.manifest, share_snapshot_root=bytes(32))
        header = replace_header(job.header, m_mm_rhs=int.from_bytes(manifest.root, "little"))
        # Both signers authorize the forged root and the header commits it;
        # replaying the actual receipt prefix must still reject this job.
        bad = f.resign(job, manifest=manifest, header=header)
        with self.assertRaisesRegex(ValueError, "snapshot Merkle root"):
            f.engine.add_job(bad)
        self.assertNotIn(bad.job_id, f.engine.jobs)

    def test_distinct_proofs_from_one_job_are_credited_once_each(self):
        f = Fixture()
        job = f.job()
        first, second = mine(job, extranonce=10), mine(job, extranonce=11)
        self.assertNotEqual(first.proof_id, second.proof_id)
        one = f.receipt(f.engine.empty_ledger, first)
        two = f.receipt(one.root, second)
        self.assertEqual(len(f.engine.ledger(two.root).claims), 2)
        self.assertEqual({c.work for c in f.engine.ledger(two.root).claims},
                         {expected_work(uint256_from_compact(f.rules.share_bits))})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            f.receipt(two.root, first)

    def test_wrong_job_signatures_never_enter_job_cache(self):
        f = Fixture()
        job = f.job()
        for field, message in (("miner_signature", "miner job"),
                               ("coordinator_signature", "coordinator job")):
            bad = replace(job, **{field: b"invalid-signature"})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                f.engine.add_job(bad)
        self.assertEqual(f.engine.jobs, {job.job_id: job})

    def test_authenticated_unapproved_target_and_wrong_commitments_rejected(self):
        f = Fixture()
        job = f.job()
        variants = [
            (f.resign(job, manifest=replace(job.manifest, share_bits=f.rules.block_bits)), "target"),
            (f.resign(job, manifest=replace(job.manifest, payout_root=bytes(32))), "payout"),
            (f.resign(job, header=replace_header(job.header, m_mm_rhs=123)), "approved template"),
            (f.resign(job, manifest=replace(job.manifest, registry_root=bytes(32))), "registry"),
        ]
        for bad, message in variants:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                f.engine.add_job(bad)
            self.assertNotIn(bad.job_id, f.engine.jobs)

    def test_coordinator_and_miner_cannot_authorize_redirected_coinbase(self):
        f = Fixture()
        job = f.job()
        cb = decode_coinbase(job.coinbase)
        cb.vout[0].scriptPubKey = f.scripts[1]
        bad = f.resign(job, coinbase=cb.serialize())
        with self.assertRaisesRegex(ValueError, "registered payout"):
            f.engine.add_job(bad)
        cb = decode_coinbase(job.coinbase)
        cb.vout[0].nValue += 1
        with self.assertRaisesRegex(ValueError, "registered payout"):
            f.engine.add_job(f.resign(job, coinbase=cb.serialize()))

    def test_receipt_authorization_and_predecessor_are_verified(self):
        f = Fixture()
        proof = mine(f.job())
        receipt = f.receipt(f.engine.empty_ledger, proof)
        with self.assertRaisesRegex(ValueError, "authorization"):
            f.engine.add_receipt(replace(receipt, signature=b"bad"))
        changed = replace(receipt, sequence=2)
        changed = replace(changed, signature=sign(f.coordinator, changed.payload))
        with self.assertRaisesRegex(ValueError, "sequence"):
            f.engine.add_receipt(changed)
        missing = replace(receipt, previous_root=bytes(32))
        missing = replace(missing, signature=sign(f.coordinator, missing.payload))
        with self.assertRaises(MissingData):
            f.engine.add_receipt(missing)

    def test_shares_cannot_change_target_coinbase_or_authenticated_job(self):
        f = Fixture()
        job, other = f.job(), f.job(1)
        proof = mine(job)
        mutations = (
            replace(proof, job_id=other.job_id),
            replace(proof, header=replace_header(proof.header, nBits=f.rules.share_bits)),
            replace(proof, header=replace_header(proof.header, hashMerkleRoot=123)),
            replace(proof, header=replace_header(proof.header, m_mm_rhs=123)),
        )
        for changed in mutations:
            with self.subTest(proof=changed), self.assertRaisesRegex(ValueError, "committed job"):
                f.engine.claim(changed)

    def test_insufficient_share_pow_is_not_credited(self):
        f = Fixture()
        proof = mine(f.job())
        header = decode_header(proof.header)
        for nonce in range(1000):
            header.nNonce = nonce
            if header.rehash() > uint256_from_compact(f.rules.share_bits):
                break
        else:
            self.fail("fixture could not produce an insufficient proof")
        bad = replace(proof, header=header.serialize())
        with self.assertRaisesRegex(ValueError, "insufficient share"):
            f.receipt(f.engine.empty_ledger, bad)
        self.assertEqual(f.engine.ledger(f.engine.empty_ledger).claims, ())

    def test_old_job_winner_carries_tail_and_itself_into_next_payout_once(self):
        f = Fixture()
        old = f.job()
        tail = mine(old, extranonce=10)
        receipt = f.receipt(f.engine.empty_ledger, tail)
        refreshed = f.job(1, root=receipt.root, serial=1)
        old_winner = mine(old, extranonce=20, full_block=True)
        first = f.engine.add_block(old_winner)
        self.assertEqual(f.engine.state(first).ledger_root, f.engine.empty_ledger)
        self.assertIn(refreshed.job_id, f.engine.jobs)
        with self.assertRaisesRegex(ValueError, "seal"):
            f.job(1, root=receipt.root)
        seal = f.seal(receipt.root, first)
        self.assertEqual(set(f.engine.pending(seal.root)), {tail.proof_id, old_winner.proof_id})
        next_job = f.job(1, root=seal.root)
        self.assertEqual([(bytes(o.scriptPubKey), o.nValue)
                          for o in decode_coinbase(next_job.coinbase).vout],
                         [(f.scripts[0], f.rules.reward)])
        next_winner = mine(next_job, extranonce=30, full_block=True)
        second = f.engine.add_block(next_winner)
        self.assertEqual(f.engine.state(second).paid, frozenset((tail.proof_id, old_winner.proof_id)))
        self.assertEqual(set(f.engine.pending(seal.root)), {next_winner.proof_id})
        seal2 = f.seal(seal.root, second)
        third_job = f.job(root=seal2.root)
        self.assertEqual([(bytes(o.scriptPubKey), o.nValue)
                          for o in decode_coinbase(third_job.coinbase).vout],
                         [(f.scripts[1], f.rules.reward)])
        third = f.engine.add_block(mine(third_job, extranonce=40, full_block=True))
        self.assertEqual(dict(f.engine.state(third).balances),
                         {f.scripts[0]: 2 * f.rules.reward, f.scripts[1]: f.rules.reward})
        before = f.engine.state(third)
        f.engine.add_block(next_winner)
        self.assertEqual(f.engine.state(third), before)
        self.assertEqual(f.engine.tip, third)

    def test_winner_that_also_has_receipt_is_deduplicated(self):
        f = Fixture()
        proof = mine(f.job(), full_block=True)
        receipt = f.receipt(f.engine.empty_ledger, proof)
        winner = f.engine.add_block(proof)
        seal = f.seal(receipt.root, winner)
        self.assertEqual(set(f.engine.pending(seal.root)), {proof.proof_id})
        job = f.job(1, root=seal.root)
        second = f.engine.add_block(mine(job, full_block=True))
        self.assertEqual(f.engine.state(second).paid, frozenset((proof.proof_id,)))

    def test_late_share_after_parent_seal_is_rejected(self):
        f = Fixture()
        job = f.job()
        block = f.engine.add_block(mine(job, full_block=True))
        seal = f.seal(f.engine.empty_ledger, block)
        with self.assertRaisesRegex(ValueError, "after parent seal"):
            f.receipt(seal.root, mine(job, extranonce=999))
        with self.assertRaisesRegex(ValueError, "sealed parent|another base branch"):
            f.job(root=seal.root, parent=f.engine.anchor)

    def test_registry_update_cannot_redirect_preexisting_claims(self):
        f = Fixture()
        old_job = f.job()
        old_proof = mine(old_job, extranonce=1)
        receipt = f.receipt(f.engine.empty_ledger, old_proof)
        replacement_script = b"\x00\x20" + b"\x77" * 32
        change = update(f.engine.registry(f.registry_root), f.ids[0],
                        f.keys[0], f.keys[0], replacement_script)
        f.registry_root = f.engine.add_change(change)
        job = f.job(1, root=receipt.root)
        self.assertEqual(f.engine.claim(old_proof).payout_script, f.scripts[0])
        self.assertEqual([(bytes(o.scriptPubKey), o.nValue)
                          for o in decode_coinbase(job.coinbase).vout],
                         [(f.scripts[0], f.rules.reward)])
        newer_proof = mine(f.job(), extranonce=2)
        self.assertEqual(f.engine.claim(newer_proof).payout_script, replacement_script)

    def test_sibling_registry_histories_cannot_mix_claims_and_payouts(self):
        f = Fixture()
        common = f.engine.registry(f.registry_root)
        left_change = update(common, f.ids[0], f.keys[0], f.keys[0], b"\x00\x20" + b"\x81" * 32)
        right_change = update(common, f.ids[0], f.keys[0], f.keys[0], b"\x00\x20" + b"\x82" * 32)
        left, right = f.engine.add_change(left_change), f.engine.add_change(right_change)
        left_job = issue_job(f.engine, f.keys[0], f.coordinator, left, f.engine.empty_ledger)
        receipt = f.receipt(f.engine.empty_ledger, mine(left_job))
        with self.assertRaisesRegex(ValueError, "registry"):
            issue_job(f.engine, f.keys[1], f.coordinator, right, receipt.root)
        # The exact history which authorized the old claim still settles it.
        accepted = issue_job(f.engine, f.keys[1], f.coordinator, left, receipt.root)
        self.assertEqual(bytes(decode_coinbase(accepted.coinbase).vout[0].scriptPubKey),
                         left_change.entry.payout_script)

    def test_seal_cannot_attach_a_conflicting_registry_tail_to_winner(self):
        f = Fixture()
        common = f.engine.registry(f.registry_root)
        roots = [f.engine.add_change(update(common, f.ids[0], f.keys[0], f.keys[0],
                                           b"\x00\x20" + bytes([value]) * 32))
                 for value in (0x91, 0x92)]
        jobs = [issue_job(f.engine, f.keys[0], f.coordinator, root, f.engine.empty_ledger)
                for root in roots]
        receipt = f.receipt(f.engine.empty_ledger, mine(jobs[0], extranonce=1))
        with self.assertRaisesRegex(ValueError, "conflicting registry"):
            f.receipt(receipt.root, mine(jobs[1], extranonce=2))
        wrong_winner = f.engine.add_block(mine(jobs[1], extranonce=3, full_block=True))
        with self.assertRaisesRegex(ValueError, "conflicting registry"):
            f.seal(receipt.root, wrong_winner)
        right_winner = f.engine.add_block(mine(jobs[0], extranonce=4, full_block=True))
        seal = f.seal(receipt.root, right_winner)
        self.assertEqual(len(f.engine.pending(seal.root, parent=right_winner)), 2)

    def test_share_origin_on_orphaned_branch_is_rejected(self):
        f = Fixture()
        job = f.job()
        left = f.engine.add_block(mine(job, extranonce=1, full_block=True))
        right = f.engine.add_block(mine(job, extranonce=2, full_block=True))
        left_seal = f.seal(f.engine.empty_ledger, left)
        left_job = f.job(root=left_seal.root, parent=left)
        left_receipt = f.receipt(left_seal.root, mine(left_job, extranonce=3))
        with self.assertRaisesRegex(ValueError, "another base branch"):
            f.engine.claims_for(right, left_receipt.root)
        with self.assertRaisesRegex(ValueError, "another base branch"):
            f.job(root=left_receipt.root, parent=right)

    def test_out_of_order_export_import_and_restore_revalidate_all_objects(self):
        f = Fixture()
        original = f.job()
        receipt = f.receipt(f.engine.empty_ledger, mine(original, extranonce=1))
        first = f.engine.add_block(mine(original, extranonce=2, full_block=True))
        seal = f.seal(receipt.root, first)
        child = f.job(1, root=seal.root)
        second = f.engine.add_block(mine(child, extranonce=3, full_block=True))
        exported = f.engine.export()
        for seed in range(5):
            shuffled = copy.deepcopy(exported)
            rng = random.Random(seed)
            for field in ("changes", "jobs", "receipts", "blocks"):
                rng.shuffle(shuffled[field])
            replica = Engine(f.rules)
            self.assertEqual(replica.import_objects(shuffled), 0)
            self.assertEqual(replica.tip, second)
            self.assertEqual(replica.state(second), f.engine.state(second))
            self.assertEqual(replica.pending(seal.root), f.engine.pending(seal.root))
            self.assertEqual(replica.import_objects(shuffled), 0)
            self.assertEqual(replica.state(second), f.engine.state(second))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            f.engine.save(path)
            restored = Engine.restore(path, f.rules)
            self.assertEqual(restored.tip, f.engine.tip)
            self.assertEqual(restored.state(second), f.engine.state(second))
            tampered = json.loads(path.read_text())
            tampered["jobs"][0]["coordinator_signature"] = "00" * 8
            path.write_bytes(canonical(tampered))
            with self.assertRaisesRegex(ValueError, "authorization"):
                Engine.restore(path, f.rules)

    def test_missing_transport_dependencies_remain_uncredited(self):
        f = Fixture()
        f.receipt(f.engine.empty_ledger, mine(f.job()))
        payload = f.engine.export()
        payload["jobs"] = []
        replica = Engine(f.rules)
        self.assertEqual(replica.import_objects(payload), 1)
        self.assertEqual(replica.receipts, {})
        self.assertEqual(replica.pending(replica.empty_ledger), {})

    def test_job_refresh_cannot_reset_aggregated_group_work_budget(self):
        f = Fixture(window_seconds=1, cap_hashes_per_second=4)
        initial = f.job()
        first = f.receipt(f.engine.empty_ledger, mine(initial, extranonce=1))
        refreshed = f.job(root=first.root, serial=1)
        second = f.receipt(first.root, mine(refreshed, extranonce=2))
        with self.assertRaisesRegex(ValueError, "budget"):
            f.job(root=second.root, serial=2)
        # Another miner retains its own allowance; there is no percentage cap.
        self.assertTrue(f.engine.validate_job(f.job(1, root=second.root)))

    def test_inflight_overbudget_work_is_retained_and_stops_new_group_jobs(self):
        f = Fixture(window_seconds=1, cap_hashes_per_second=4)
        initial = f.job()
        first = f.receipt(f.engine.empty_ledger, mine(initial, extranonce=1))
        second = f.receipt(first.root, mine(initial, extranonce=2))
        third = f.receipt(second.root, mine(initial, extranonce=3))
        self.assertEqual(len(f.engine.ledger(third.root).claims), 3)
        self.assertEqual(sum(c.work for c in f.engine.ledger(third.root).claims), 6)
        self.assertEqual(f.engine.budget_violations(third.root), {(0, b"miner-0"): 6})
        self.assertEqual(f.engine.rules.budget, 4)
        with self.assertRaisesRegex(ValueError, "budget"):
            f.job(root=third.root)
        self.assertTrue(f.engine.validate_job(f.job(1, root=third.root)))
        # A previously issued job may still win; settlement retains its work
        # and all valid in-flight receipts instead of resetting the allowance.
        winner = f.engine.add_block(mine(initial, extranonce=4, full_block=True))
        seal = f.seal(third.root, winner)
        self.assertEqual(f.engine.budget_violations(seal.root), {(0, b"miner-0"): 8})
        self.assertEqual(len(f.engine.pending(seal.root)), 4)
        with self.assertRaisesRegex(ValueError, "budget"):
            f.job(root=seal.root)
        self.assertTrue(f.engine.validate_job(f.job(1, root=seal.root)))

    def test_paid_work_and_winner_keep_origin_epoch_budget(self):
        f = Fixture(window_seconds=1, cap_hashes_per_second=4, epoch_blocks=8)
        initial = f.job()
        first = f.receipt(f.engine.empty_ledger, mine(initial, extranonce=1))
        refreshed = f.job(root=first.root, serial=1)
        block = f.engine.add_block(mine(refreshed, extranonce=2, full_block=True))
        seal = f.seal(first.root, block)
        self.assertEqual(len(f.engine.state(block).paid), 1)
        with self.assertRaisesRegex(ValueError, "budget"):
            f.job(root=seal.root)
        self.assertTrue(f.engine.validate_job(f.job(1, root=seal.root)))

    def test_new_origin_epoch_gets_new_budget_without_relabeling_old_claims(self):
        f = Fixture(window_seconds=1, cap_hashes_per_second=4, epoch_blocks=1)
        initial = f.job()
        first = f.receipt(f.engine.empty_ledger, mine(initial, extranonce=1))
        refreshed = f.job(root=first.root, serial=1)
        winner = mine(refreshed, extranonce=2, full_block=True)
        block = f.engine.add_block(winner)
        seal = f.seal(first.root, block)
        child = f.job(root=seal.root)
        self.assertEqual(child.manifest.epoch, 1)
        self.assertEqual(f.engine.claim(winner).epoch, 0)
        self.assertEqual({c.epoch for c in f.engine.claims_for(block, seal.root).values()}, {0})
        self.assertEqual(f.engine.claim(mine(child, extranonce=3)).epoch, 1)


def replace_header(raw, **changes):
    header = decode_header(raw)
    for field, value in changes.items():
        setattr(header, field, value)
    return header.serialize()


if __name__ == "__main__":
    unittest.main()
