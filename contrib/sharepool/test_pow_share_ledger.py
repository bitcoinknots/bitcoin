#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial checks for the experimental PoW-selected accounting ledger.

These exercise a permissionless reference state machine, not Bitcoin block
validity, native Knots fork choice, or a physical hashrate limit.
"""

import copy
from dataclasses import replace
import json
from pathlib import Path
import random
import tempfile
import unittest

from live_protocol import canonical, decode_coinbase, decode_header, mine
from pow_share_ledger import (Checkpoint, PowLedger, PowRules, make_job,
                              mine_checkpoint, proof_action, register_action)
from precommit_demo import uint256_from_compact
from signed_registry import private_key, register, sign, update
from work_accounting import expected_work


class Fixture:
    def __init__(self, payout_scripts=None, **rules):
        self.scripts = tuple(payout_scripts or (
            b"\x00\x20" + b"\x31" * 32,
            b"\x00\x20" + b"\x32" * 32,
        ))
        self.keys = tuple(private_key(2801 + index)
                          for index in range(len(self.scripts)))
        self.rules = PowRules(**rules)
        self.ledger = PowLedger(self.rules)
        self.ids = []
        for index, (key, script) in enumerate(zip(self.keys, self.scripts)):
            change = register(self.ledger.state().registry, key,
                              f"miner-{index}".encode(), script)
            self.add(register_action(change))
            self.ids.append(change.entry.miner_id)

    def add(self, *actions, parent=None, start_nonce=0):
        checkpoint = mine_checkpoint(self.ledger, actions, parent=parent,
                                     start_nonce=start_nonce)
        self.ledger.add(checkpoint)
        return checkpoint

    def job(self, index=0, checkpoint=None, serial=0):
        return make_job(self.ledger, self.keys[index], checkpoint=checkpoint,
                        serial=serial)


def outputs(job):
    return {bytes(output.scriptPubKey): output.nValue
            for output in decode_coinbase(job.coinbase).vout}


def resign(job, key, **changes):
    changed = replace(job, **changes)
    return replace(changed, miner_signature=sign(key, changed.payload))


def altered_header(raw, **changes):
    header = decode_header(raw)
    for name, value in changes.items():
        setattr(header, name, value)
    return header.serialize()


def solve_checkpoint(checkpoint, rules, *, valid=True):
    """Give a deliberately altered public checkpoint a real easy-target proof."""
    target = uint256_from_compact(rules.checkpoint_bits)
    for nonce in range(100000):
        candidate = replace(checkpoint, nonce=nonce)
        if (int.from_bytes(candidate.checkpoint_id, "big") <= target) == valid:
            return candidate
    raise AssertionError("failed to construct checkpoint proof fixture")


class PowShareLedgerTests(unittest.TestCase):
    def assert_rejected_unchanged(self, ledger, actions, parent=None):
        before = ledger.export()
        tip, state = ledger.tip, ledger.state()
        with self.assertRaises(ValueError) as proposal_error:
            mine_checkpoint(ledger, actions, parent=parent)
        # Bypass the honest proposal helper and give the malicious actions an
        # actual proof. Import must reject the action itself, not merely a bad
        # post-state root or an inability to mine through the public helper.
        parent = ledger.tip if parent is None else parent
        forged = Checkpoint(ledger.rules.root, parent, ledger.state(parent).height + 1,
                            canonical(list(actions)), bytes(32), 0)
        forged = solve_checkpoint(forged, ledger.rules)
        with self.assertRaises(ValueError) as import_error:
            ledger.add(forged)
        self.assertEqual(str(import_error.exception), str(proposal_error.exception))
        self.assertEqual(ledger.tip, tip)
        self.assertEqual(ledger.state(), state)
        self.assertEqual(ledger.export(), before)

    def test_empty_permissionless_heartbeat_adds_work_and_no_reward_credit(self):
        rules = PowRules(epoch_checkpoints=2)
        ledger = PowLedger(rules)
        original = ledger.state()
        # No registered miner, signing key, or coordinator is involved.
        for height in (1, 2):
            checkpoint = mine_checkpoint(ledger)
            ledger.add(checkpoint)
            view = ledger.state()
            self.assertEqual(view.height, height)
            self.assertEqual(view.chainwork, height * expected_work(
                uint256_from_compact(rules.checkpoint_bits)))
            self.assertEqual(view.registry.entries, ())
            self.assertEqual(view.claims, ())
            self.assertEqual(view.paid, frozenset())
            self.assertEqual(view.balances, ())
            self.assertEqual(view.reward_tip, original.reward_tip)
            self.assertEqual(view.reward_height, 0)
        self.assertNotEqual(ledger.state().root, original.root)

    def test_jobs_bind_checkpoint_snapshot_tag_and_exact_coinbase_payout(self):
        f = Fixture()
        first, second = f.job(), f.job(1)
        self.assertNotEqual(first.header, second.header)
        self.assertNotEqual(first.coinbase, second.coinbase)
        for index, job in enumerate((first, second)):
            self.assertEqual(job.manifest.ledger_root, f.ledger.tip)
            self.assertEqual(job.manifest.share_snapshot_root, f.ledger.state().root)
            self.assertEqual(outputs(job), {f.scripts[index]: f.rules.reward})
            header = decode_header(job.header)
            self.assertEqual(header.m_mm_rhs, int.from_bytes(job.manifest.root, "little"))
            self.assertIn(f"miner-{index}".encode(),
                          decode_coinbase(job.coinbase).vin[0].scriptSig)
        f.add(proof_action(first, mine(first)))
        refreshed = f.job(serial=1)
        self.assertNotEqual(refreshed.manifest.root, first.manifest.root)
        self.assertNotEqual(refreshed.manifest.share_snapshot_root,
                            first.manifest.share_snapshot_root)

    def test_all_scripts_exactly_capped_resume_after_empty_epoch_heartbeat(self):
        work = expected_work(uint256_from_compact(PowRules().share_bits))
        f = Fixture(epoch_checkpoints=4, window_seconds=1,
                    cap_hashes_per_second=work)
        jobs = (f.job(), f.job(1))
        proofs = tuple(mine(job, extranonce=index) for index, job in enumerate(jobs))
        f.add(*(proof_action(job, proof) for job, proof in zip(jobs, proofs)))
        exhausted = f.ledger.state()
        self.assertEqual(exhausted.height, 3)
        self.assertEqual(f.ledger.budget_violations(), {})
        for index in range(2):
            with self.subTest(index=index), self.assertRaises(ValueError):
                f.job(index)
        f.add()
        for index in range(2):
            refreshed = f.job(index)
            self.assertEqual(refreshed.manifest.epoch, jobs[index].manifest.epoch + 1)
        self.assertEqual(f.ledger.state().reward_height, 0)
        self.assertEqual(f.ledger.state().reward_tip, exhausted.reward_tip)
        self.assertEqual(f.ledger.state().claims, exhausted.claims)
        self.assertEqual(set(f.ledger.pending()), {proof.proof_id for proof in proofs})

    def test_same_script_tags_share_budget_and_inflight_overrun_remains_credit(self):
        script, other = b"\x51", b"\x52"
        work = expected_work(uint256_from_compact(PowRules().share_bits))
        f = Fixture((script, script, other), epoch_checkpoints=100,
                    window_seconds=1, cap_hashes_per_second=work)
        jobs = (f.job(), f.job(1))
        proofs = tuple(mine(job) for job in jobs)
        f.add(*(proof_action(job, proof) for job, proof in zip(jobs, proofs)))
        self.assertEqual(len(f.ledger.pending()), 2)
        self.assertEqual(f.ledger.budget_violations(), {(0, script): 2 * work})
        self.assertEqual({claim.tag for claim in f.ledger.state().claims},
                         {b"miner-0", b"miner-1"})
        for index in (0, 1):
            with self.assertRaises(ValueError):
                f.job(index)
        self.assertEqual(f.job(2).manifest.miner_id, f.ids[2])

    def test_insufficient_share_pow_and_mutated_committed_header_are_rejected(self):
        f = Fixture()
        job = f.job()
        proof = mine(job)
        header = decode_header(proof.header)
        for nonce in range(1000):
            header.nNonce = nonce
            if header.rehash() > uint256_from_compact(f.rules.share_bits):
                break
        else:
            self.fail("failed to construct insufficient proof")
        variants = (
            replace(proof, header=header.serialize()),
            replace(proof, header=altered_header(proof.header, m_mm_rhs=123)),
            replace(proof, header=altered_header(proof.header, hashMerkleRoot=123)),
            replace(proof, header=altered_header(proof.header, nBits=f.rules.share_bits)),
        )
        for variant in variants:
            with self.subTest(header=variant.header.hex()):
                self.assert_rejected_unchanged(f.ledger, (proof_action(job, variant),))
        self.assertEqual(f.ledger.state().claims, ())

    def test_job_signature_registry_target_and_snapshot_forgery_are_rejected(self):
        f = Fixture()
        job = f.job()
        manifests = (
            replace(job.manifest, registry_root=bytes(32)),
            replace(job.manifest, share_snapshot_root=bytes(32)),
            replace(job.manifest, share_bits=f.rules.block_bits),
        )
        variants = [replace(job, miner_signature=b"invalid-signature")]
        for manifest in manifests:
            variants.append(resign(job, f.keys[0], manifest=manifest,
                header=altered_header(job.header,
                    m_mm_rhs=int.from_bytes(manifest.root, "little"))))
        for variant in variants:
            with self.subTest(manifest=variant.manifest):
                self.assert_rejected_unchanged(f.ledger,
                    (proof_action(variant, mine(variant)),))
        good = f.add(proof_action(job, mine(job)))
        self.assertEqual(len(f.ledger.state(good.checkpoint_id).claims), 1)

    def test_old_winner_pays_its_snapshot_and_tail_and_winner_are_paid_once(self):
        f = Fixture()
        first = f.job()
        first_share = mine(first, extranonce=1)
        f.add(proof_action(first, first_share))
        old = f.job(1)
        self.assertEqual(outputs(old), {f.scripts[0]: f.rules.reward})
        tail = mine(old, extranonce=2)
        f.add(proof_action(old, tail))
        winner = mine(old, extranonce=3, full_block=True)
        f.add(proof_action(old, winner, winner=True))
        view = f.ledger.state()
        self.assertEqual(view.paid, frozenset((first_share.proof_id,)))
        self.assertEqual(set(f.ledger.pending()), {tail.proof_id, winner.proof_id})
        self.assertEqual(dict(view.balances), {f.scripts[0]: f.rules.reward})
        second = f.job()
        self.assertEqual(outputs(second), {f.scripts[1]: f.rules.reward})
        second_winner = mine(second, extranonce=4, full_block=True)
        f.add(proof_action(second, second_winner, winner=True))
        self.assertEqual(set(f.ledger.pending()), {second_winner.proof_id})
        self.assertEqual(f.ledger.state().paid,
                         frozenset((first_share.proof_id, tail.proof_id, winner.proof_id)))
        third = f.job(1)
        self.assertEqual(outputs(third), {f.scripts[0]: f.rules.reward})
        f.add(proof_action(third, mine(third, extranonce=5, full_block=True), winner=True))
        self.assertEqual(dict(f.ledger.state().balances),
                         {f.scripts[0]: 2 * f.rules.reward, f.scripts[1]: f.rules.reward})

    def test_winning_proof_promotes_existing_share_once_and_cannot_win_twice(self):
        f = Fixture()
        job = f.job()
        winner = mine(job, full_block=True)
        f.add(proof_action(job, winner))
        f.add(proof_action(job, winner, winner=True))
        self.assertEqual(len(f.ledger.state().claims), 1)
        self.assertEqual(set(f.ledger.pending()), {winner.proof_id})
        self.assertEqual(f.ledger.state().reward_height, 1)
        self.assert_rejected_unchanged(f.ledger, (proof_action(job, winner, winner=True),))

    def test_checkpoint_action_duplicates_and_winner_order_are_rejected(self):
        f = Fixture()
        job = f.job()
        share = proof_action(job, mine(job, extranonce=11))
        winner = proof_action(job, mine(job, extranonce=12, full_block=True), winner=True)
        another = proof_action(job, mine(job, extranonce=13, full_block=True), winner=True)
        for actions in ((share, share), (winner, share), (winner, another)):
            with self.subTest(actions=actions):
                self.assert_rejected_unchanged(f.ledger, actions)
        # Promotion is distinct from duplicate ordinary share credit.
        proof = mine(job, extranonce=14, full_block=True)
        f.add(proof_action(job, proof), proof_action(job, proof, winner=True))
        self.assertEqual(len(f.ledger.state().claims), 1)
        self.assertEqual(f.ledger.state().reward_height, 1)

    def test_job_age_exact_boundary_uses_event_parent_and_then_expires(self):
        work = expected_work(uint256_from_compact(PowRules().share_bits))
        f = Fixture((b"\x51",), max_job_age=3, epoch_checkpoints=100,
                    window_seconds=1, cap_hashes_per_second=work)
        job = f.job()
        origin = f.ledger.tip
        origin_height = f.ledger.state().height
        f.add(proof_action(job, mine(job, extranonce=19)))
        with self.assertRaises(ValueError):
            f.job()
        # Signing a NEW job from an old under-budget checkpoint cannot reveal
        # its physical creation time. The reference explicitly permits this
        # within the ancestry-based lag, then cuts it off on this branch.
        newly_signed_old_prefix = f.job(checkpoint=origin, serial=91)
        self.assertEqual(newly_signed_old_prefix.manifest.epoch, job.manifest.epoch)
        for _ in range(f.rules.max_job_age - 1):
            f.add()
        self.assertEqual(f.ledger.state().height - origin_height, f.rules.max_job_age)
        f.add(proof_action(newly_signed_old_prefix,
                           mine(newly_signed_old_prefix, extranonce=20)))
        self.assertEqual(f.ledger.budget_violations(), {(0, f.scripts[0]): 2 * work})
        for winner in (False, True):
            proof = mine(newly_signed_old_prefix, extranonce=21 + winner,
                         full_block=winner)
            with self.subTest(winner=winner):
                self.assert_rejected_unchanged(f.ledger,
                    (proof_action(newly_signed_old_prefix, proof, winner=winner),))

    def test_job_checkpoint_must_be_event_ancestor_even_if_signature_is_valid(self):
        f = Fixture()
        base = f.ledger.tip
        left = f.add(parent=base)
        job = f.job(checkpoint=left.checkpoint_id)
        right = f.add(parent=base, start_nonce=left.nonce + 1)
        action = proof_action(job, mine(job))
        self.assert_rejected_unchanged(f.ledger, (action,), parent=right.checkpoint_id)
        accepted = f.add(action, parent=left.checkpoint_id)
        self.assertEqual(f.ledger.tip, accepted.checkpoint_id)
        self.assertEqual(len(f.ledger.state().claims), 1)

    def test_ordinary_old_parent_share_can_arrive_after_a_reward_winner(self):
        f = Fixture()
        job = f.job()
        late = mine(job, extranonce=30)
        winner = mine(job, extranonce=31, full_block=True)
        f.add(proof_action(job, winner, winner=True))
        f.add(proof_action(job, late))
        claims = {claim.proof_id: claim for claim in f.ledger.state().claims}
        self.assertEqual(set(claims), {late.proof_id, winner.proof_id})
        self.assertEqual(claims[late.proof_id].origin_parent, job.manifest.parent)
        self.assertEqual(claims[late.proof_id].epoch, job.manifest.epoch)

    def test_legitimate_checkpoint_reorg_can_orphan_then_reinclude_a_share(self):
        f = Fixture()
        base = f.ledger.tip
        job = f.job()
        proof = mine(job)
        left = f.add(proof_action(job, proof), parent=base)
        right = f.add(parent=base)
        right_child = f.add(parent=right.checkpoint_id)
        self.assertEqual(f.ledger.tip, right_child.checkpoint_id)
        self.assertEqual(f.ledger.state().claims, ())
        self.assertEqual(len(f.ledger.state(left.checkpoint_id).claims), 1)
        # Re-inclusion is an explicit action on the chosen branch, not a union
        # of local observations or an automatic payment of orphaned work.
        f.add(proof_action(job, proof), parent=right_child.checkpoint_id)
        self.assertEqual(set(f.ledger.pending()), {proof.proof_id})
        self.assertEqual(len(f.ledger.state().claims), 1)

    def test_branch_work_counts_ancestors_once_and_never_sums_siblings(self):
        f = Fixture()
        base = f.ledger.tip
        siblings = [f.add(parent=base, start_nonce=index * 100)
                    for index in range(4)]
        self.assertEqual(len({node.checkpoint_id for node in siblings}), 4)
        best = min(node.checkpoint_id for node in siblings)
        self.assertEqual(f.ledger.tip, best)
        work = expected_work(uint256_from_compact(f.rules.checkpoint_bits))
        self.assertEqual(f.ledger.state().chainwork, 3 * work)
        child = f.add(parent=siblings[-1].checkpoint_id)
        self.assertEqual(f.ledger.tip, child.checkpoint_id)
        self.assertEqual(f.ledger.state().chainwork, 4 * work)

    def test_paid_work_still_consumes_original_script_and_epoch_budget(self):
        work = expected_work(uint256_from_compact(PowRules().share_bits))
        f = Fixture((b"\x51",), epoch_checkpoints=100, window_seconds=1,
                    cap_hashes_per_second=2 * work)
        job = f.job()
        share = mine(job)
        f.add(proof_action(job, share))
        paying_job = f.job(serial=1)
        winner = mine(paying_job, full_block=True)
        f.add(proof_action(paying_job, winner, winner=True))
        self.assertEqual(f.ledger.state().paid, frozenset((share.proof_id,)))
        self.assertEqual(set(f.ledger.pending()), {winner.proof_id})
        self.assertEqual(f.ledger.budget_violations(), {})
        with self.assertRaises(ValueError):
            f.job()

    def test_authorized_payout_update_does_not_redirect_old_work(self):
        f = Fixture()
        job = f.job()
        old = mine(job, extranonce=40)
        f.add(proof_action(job, old))
        new_script = b"\x53"
        change = update(f.ledger.state().registry, f.ids[0], f.keys[0],
                        f.keys[0], new_script)
        f.add(register_action(change))
        refreshed = f.job()
        late = mine(job, extranonce=41)
        fresh = mine(refreshed, extranonce=42)
        f.add(proof_action(job, late), proof_action(refreshed, fresh))
        claims = {claim.proof_id: claim for claim in f.ledger.state().claims}
        for proof in (old, late):
            self.assertEqual(claims[proof.proof_id].payout_script, f.scripts[0])
            self.assertEqual(claims[proof.proof_id].registry_root, job.manifest.registry_root)
        self.assertEqual(claims[fresh.proof_id].payout_script, new_script)
        self.assertEqual(claims[fresh.proof_id].registry_root,
                         refreshed.manifest.registry_root)

    def test_fork_reorg_rolls_back_reward_balances_and_paid_claims(self):
        f = Fixture()
        share_job = f.job()
        share = mine(share_job)
        base = f.add(proof_action(share_job, share)).checkpoint_id
        job = f.job(1)
        winner = mine(job, full_block=True)
        paid = f.add(proof_action(job, winner, winner=True), parent=base)
        self.assertEqual(f.ledger.state(paid.checkpoint_id).paid,
                         frozenset((share.proof_id,)))
        right = f.add(parent=base)
        child = f.add(parent=right.checkpoint_id)
        self.assertEqual(f.ledger.tip, child.checkpoint_id)
        self.assertEqual(f.ledger.state().reward_height, 0)
        self.assertEqual(f.ledger.state().balances, ())
        self.assertEqual(f.ledger.state().paid, frozenset())
        self.assertEqual(set(f.ledger.pending()), {share.proof_id})
        restored = f.add(proof_action(job, winner, winner=True), parent=child.checkpoint_id)
        self.assertEqual(f.ledger.tip, restored.checkpoint_id)
        self.assertEqual(f.ledger.state().reward_height, 1)
        self.assertEqual(dict(f.ledger.state().balances), {f.scripts[0]: f.rules.reward})

    def test_checkpoint_pow_payload_state_and_rules_forgery_never_poison_retry(self):
        f = Fixture()
        job = f.job()
        action = proof_action(job, mine(job))
        good = mine_checkpoint(f.ledger, (action,))
        invalid_actions = [action, {"kind": "unknown-action"}]
        variants = (
            solve_checkpoint(good, f.rules, valid=False),
            solve_checkpoint(replace(good, state_root=bytes(32)), f.rules),
            solve_checkpoint(replace(good, rules_root=bytes(32)), f.rules),
            solve_checkpoint(replace(good, height=good.height + 1), f.rules),
            solve_checkpoint(replace(good, payload=canonical(invalid_actions)), f.rules),
        )
        original = f.ledger.export()
        for checkpoint in variants:
            with self.subTest(checkpoint=checkpoint), self.assertRaises(ValueError):
                f.ledger.add(checkpoint)
            self.assertEqual(f.ledger.export(), original)
        # A valid first action followed by invalid data must not leave a partial
        # registry/claim state behind or prevent the original checkpoint retry.
        f.ledger.add(Checkpoint.from_object(good.to_object()))
        self.assertEqual(f.ledger.tip, good.checkpoint_id)
        self.assertEqual(len(f.ledger.state().claims), 1)
        after = f.ledger.export()
        f.ledger.add(good)
        self.assertEqual(f.ledger.export(), after)

    def test_missing_dependencies_and_reordered_forks_converge_only_after_validation(self):
        f = Fixture()
        base = f.ledger.tip
        job = f.job()
        left = f.add(proof_action(job, mine(job, extranonce=50)), parent=base)
        right = f.add(parent=base)
        child = f.add(parent=right.checkpoint_id)
        bundle = f.ledger.export()
        isolated = PowLedger(f.rules)
        only_child = copy.deepcopy(bundle)
        only_child["checkpoints"] = [child.to_object()]
        self.assertEqual(isolated.import_objects(only_child), 1)
        self.assertEqual(isolated.tip, isolated.genesis)
        self.assertEqual(isolated.state().chainwork, 0)
        self.assertEqual(isolated.state().claims, ())
        self.assertEqual(isolated.import_objects(bundle), 0)
        self.assertEqual(isolated.tip, child.checkpoint_id)
        self.assertEqual(isolated.state(), f.ledger.state())
        self.assertEqual(len(isolated.state(left.checkpoint_id).claims), 1)
        for seed in range(8):
            reordered = copy.deepcopy(bundle)
            random.Random(seed).shuffle(reordered["checkpoints"])
            replica = PowLedger(f.rules)
            with self.subTest(seed=seed):
                self.assertEqual(replica.import_objects(reordered), 0)
                self.assertEqual(replica.tip, child.checkpoint_id)
                self.assertEqual(replica.state(), f.ledger.state())
                self.assertEqual(replica.pending(), {})
                before = replica.export()
                self.assertEqual(replica.import_objects(reordered), 0)
                self.assertEqual(replica.export(), before)
        # Equal work also has an objective tie break, independent of arrival.
        tied = copy.deepcopy(bundle)
        tied["checkpoints"] = [obj for obj in tied["checkpoints"]
                               if Checkpoint.from_object(obj).checkpoint_id != child.checkpoint_id]
        for ordered in (tied["checkpoints"], list(reversed(tied["checkpoints"]))):
            replica = PowLedger(f.rules)
            self.assertEqual(replica.import_objects({**tied, "checkpoints": ordered}), 0)
            self.assertEqual(replica.tip, min(left.checkpoint_id, right.checkpoint_id))

    def test_restart_replays_branches_and_rejects_legacy_or_mismatched_rules(self):
        f = Fixture()
        old = f.job()
        share = mine(old)
        f.add(proof_action(old, share))
        paying = f.job(1)
        fork_parent = f.ledger.tip
        f.add(proof_action(paying, mine(paying, full_block=True), winner=True))
        fork = f.add(parent=fork_parent)
        f.add(parent=fork.checkpoint_id)
        with tempfile.TemporaryDirectory(prefix="sharepool-pow-ledger-test-") as directory:
            path = Path(directory) / "ledger.json"
            f.ledger.save(path)
            restored = PowLedger.restore(path, f.rules)
            self.assertEqual(restored.tip, f.ledger.tip)
            self.assertEqual(restored.state(), f.ledger.state())
            self.assertEqual(restored.pending(), f.ledger.pending())
            self.assertEqual(restored.export(), f.ledger.export())
            with self.assertRaises(ValueError):
                PowLedger.restore(path, replace(f.rules, max_job_age=f.rules.max_job_age + 1))
            stored = json.loads(path.read_text())
            self.assertNotIn("private", json.dumps(stored).lower())
        for changed in (
            {**f.ledger.export(), "format": 0},
            {**f.ledger.export(), "rules": replace(f.rules, pool_id=b"other-pool").to_object()},
            {"format": 1, "rules": f.rules.to_object(), "receipts": []},
        ):
            replica = PowLedger(f.rules)
            with self.subTest(bundle=changed), self.assertRaises(ValueError):
                replica.import_objects(changed)
            self.assertEqual(replica.tip, replica.genesis)

    def test_registration_that_cannot_fit_one_job_payout_is_rejected(self):
        ledger = PowLedger(PowRules())
        key = private_key(2901)
        change = register(ledger.state().registry, key, b"oversized-payout",
                          b"\x51" + b"\x00" * 4999)
        self.assert_rejected_unchanged(ledger, (register_action(change),))
        self.assertEqual(ledger.state().registry.entries, ())
        self.assertEqual(ledger.tip, ledger.genesis)

    def test_registry_aggregate_payout_capacity_is_reserved_before_work_arrives(self):
        scripts = tuple(bytes([0x51 + index]) + b"\x00" * 1899 for index in range(3))
        f = Fixture(scripts[:2])
        jobs = (f.job(), f.job(1))
        for job in jobs:
            self.assertLessEqual(len(job.coinbase), 4096)
        newcomer = private_key(2902)
        change = register(f.ledger.state().registry, newcomer, b"third-payout", scripts[2])
        # Each destination fits by itself; accepting the third would promise a
        # future payout combination that cannot fit the public WorkJob limit.
        self.assert_rejected_unchanged(f.ledger, (register_action(change),))
        f.add(*(proof_action(job, mine(job)) for job in jobs))
        actual = f.job()
        self.assertEqual(set(outputs(actual)), set(scripts[:2]))
        self.assertEqual(sum(outputs(actual).values()), f.rules.reward)
        self.assertLessEqual(len(actual.coinbase), 4096)
        self.assertEqual(len(f.ledger.state().registry.entries), 2)

    def test_rotation_reserves_eligible_old_destinations_and_releases_unused_ones(self):
        scripts = tuple(bytes([0x51 + index]) + b"\x00" * 1899 for index in range(3))
        f = Fixture(scripts[:1], max_job_age=2)
        old_job = f.job()
        late = mine(old_job)
        first_change = update(f.ledger.state().registry, f.ids[0], f.keys[0],
                              f.keys[0], scripts[1])
        f.add(register_action(first_change))
        second_change = update(f.ledger.state().registry, f.ids[0], f.keys[0],
                               f.keys[0], scripts[2])
        self.assert_rejected_unchanged(f.ledger, (register_action(second_change),))
        f.add()
        # The origin is exactly max_job_age behind this event's parent. An
        # included late proof preserves its payout claim even though that
        # registry will be too old for future events after this checkpoint.
        self.assertEqual(f.ledger.state().height -
                         f.ledger.state(old_job.manifest.ledger_root).height, 2)
        self.assert_rejected_unchanged(f.ledger, (
            register_action(second_change), proof_action(old_job, late)))
        f.add(register_action(second_change))
        new_job = f.job()
        self.assertEqual(outputs(new_job), {scripts[2]: f.rules.reward})
        self.assertLessEqual(len(new_job.coinbase), 4096)
        self.assertEqual(f.ledger.pending(), {})

    def test_pending_claim_reserves_expired_script_until_actual_settlement(self):
        scripts = tuple(bytes([0x51 + index]) + b"\x00" * 1899 for index in range(3))
        f = Fixture(scripts[:1], max_job_age=2)
        old_job = f.job()
        old_proof = mine(old_job)
        f.add(proof_action(old_job, old_proof))
        first_change = update(f.ledger.state().registry, f.ids[0], f.keys[0],
                              f.keys[0], scripts[1])
        f.add(register_action(first_change))
        f.add()
        f.add()
        second_change = update(f.ledger.state().registry, f.ids[0], f.keys[0],
                               f.keys[0], scripts[2])
        self.assert_rejected_unchanged(f.ledger, (register_action(second_change),))
        self.assertEqual(set(f.ledger.pending()), {old_proof.proof_id})
        paying_job = f.job()
        self.assertEqual(outputs(paying_job), {scripts[0]: f.rules.reward})
        self.assertLessEqual(len(paying_job.coinbase), 4096)
        winner = mine(paying_job, full_block=True)
        f.add(proof_action(paying_job, winner, winner=True))
        self.assertEqual(f.ledger.state().paid, frozenset((old_proof.proof_id,)))
        self.assertEqual(dict(f.ledger.state().balances), {scripts[0]: f.rules.reward})
        f.add(register_action(second_change))
        next_job = f.job()
        self.assertEqual(outputs(next_job), {scripts[1]: f.rules.reward})
        self.assertLessEqual(len(next_job.coinbase), 4096)
        self.assertEqual(set(f.ledger.pending()), {winner.proof_id})

    def test_rules_reject_malformed_and_unbounded_resource_parameters(self):
        malformed = (
            {"max_actions": 0}, {"max_actions": 129},
            {"max_checkpoints": 4097}, {"max_job_age": 4097},
            {"max_payload_bytes": 1024 * 1024 + 1},
            {"epoch_checkpoints": 0}, {"cap_hashes_per_second": True},
            {"window_seconds": 1.5}, {"checkpoint_bits": 0x208fffff},
            {"renewal_basis": "local-receipt-time"},
        )
        for kwargs in malformed:
            with self.subTest(rules=kwargs), self.assertRaises((ValueError, TypeError)):
                PowRules(**kwargs)


if __name__ == "__main__":
    unittest.main()
