#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Three-replica permissionless checkpoint accounting scenarios.

Uses direct object delivery and public fixture keys. The ledger-selected reward
history is LAB ACCOUNTING, not Bitcoin fork choice or activated Knots consensus.
"""

import argparse
import json
from pathlib import Path
import tempfile

from live_protocol import MissingData, mine
from pow_share_ledger import (Checkpoint, PowLedger, PowRules, make_job,
                              mine_checkpoint, proof_action, register_action)
from signed_registry import apply_change, private_key, register


def summary(ledger):
    state = ledger.state()
    return {"checkpoint": ledger.tip.hex(), "checkpoint_height": state.height,
            "chainwork": state.chainwork, "state_root": state.root.hex(),
            "reward_tip": f"{state.reward_tip:064x}", "reward_height": state.reward_height,
            "claim_count": len(state.claims), "paid_count": len(state.paid),
            "pending_count": len(ledger.pending()),
            "balances": {script.hex(): amount for script, amount in state.balances}}


def setup(rules=None, scripts=(b"\x51", b"\x52", b"\x53")):
    rules = PowRules() if rules is None else rules
    replicas = [PowLedger(rules) for _ in range(3)]
    keys = tuple(private_key(1701 + index) for index in range(len(scripts)))
    registry, actions = replicas[0].state().registry, []
    for index, (key, script) in enumerate(zip(keys, scripts)):
        change = register(registry, key, f"pow-miner-{index}".encode(), script)
        actions.append(register_action(change))
        registry = apply_change(registry, change)
    registration = mine_checkpoint(replicas[0], actions=tuple(actions))
    replicas[0].add(registration)
    synchronize(replicas[0], replicas[1:])
    return replicas, keys, registration


def synchronize(source, targets):
    for target in targets:
        assert target.import_objects(source.export()) == 0


def append(ledger, actions=(), *, parent=None, start_nonce=0):
    checkpoint = mine_checkpoint(ledger, actions=tuple(actions), parent=parent,
                                 start_nonce=start_nonce)
    ledger.add(checkpoint)
    return checkpoint


def expect_error(callback, contains):
    try:
        callback()
    except ValueError as error:
        assert contains in str(error).lower(), str(error)
        return str(error)
    raise AssertionError("invalid action was accepted")


def assert_converged(replicas):
    snapshots = [summary(replica) for replica in replicas]
    assert snapshots[1:] == [snapshots[0]] * (len(snapshots) - 1)
    return snapshots


def run():
    cases = []

    def record(name, behavior, **details):
        cases.append({"name": name, "passed": True, "behavior": behavior, **details})

    replicas, keys, _ = setup(PowRules(cap_hashes_per_second=1, window_seconds=4),
                               scripts=(b"\x51", b"\x51", b"\x52"))
    primary = replicas[0]
    first_job = make_job(primary, keys[0])
    first_proof = mine(first_job, extranonce=1)
    append(primary, (proof_action(first_job, first_proof),))
    second_job = make_job(primary, keys[1])
    second_proof = mine(second_job, extranonce=2)
    append(primary, (proof_action(second_job, second_proof),))
    assert first_job.manifest.miner_id != second_job.manifest.miner_id
    claims = primary.state().claims
    assert len({claim.tag for claim in claims}) == 2
    assert {claim.payout_script for claim in claims} == {b"\x51"}
    assert sum(claim.work for claim in claims) == 4
    errors = [expect_error(lambda key=key: make_job(primary, key), "budget") for key in keys[:2]]
    assert make_job(primary, keys[2]).manifest.miner_id not in {
        first_job.manifest.miner_id, second_job.manifest.miner_id}
    synchronize(primary, replicas[1:])
    record("shared_payout_budget", "Different registered miner IDs and tags share one payout-script allowance.",
           budget=4, work=4, rejected_refreshes=errors, distinct_payout_still_available=True,
           replicas=assert_converged(replicas))

    replicas, keys, _ = setup(PowRules(cap_hashes_per_second=1, window_seconds=2,
                                      epoch_checkpoints=3))
    primary = replicas[0]
    job = make_job(primary, keys[0])
    append(primary, (proof_action(job, mine(job, extranonce=3)),))
    expect_error(lambda: make_job(primary, keys[0]), "budget")
    before = summary(primary)
    append(primary)  # No share, reward candidate, registry change, or coordinator signature.
    renewed = make_job(primary, keys[0])
    assert renewed.manifest.epoch > job.manifest.epoch
    assert primary.state().reward_height == 0
    assert len(primary.state().claims) == 1
    synchronize(primary, replicas[1:])
    record("heartbeat_progress_without_reward_block", "An empty proof-of-work checkpoint advances the accounting epoch and permits fresh work.",
           before=before, renewed_epoch=renewed.manifest.epoch, coordinator_required=False,
           replicas=assert_converged(replicas))

    replicas, keys, _ = setup()
    primary = replicas[0]
    old_job = make_job(primary, keys[0])
    other_job = make_job(primary, keys[1])
    tail = mine(other_job, extranonce=4)
    append(primary, (proof_action(other_job, tail),))
    old_winner = mine(old_job, full_block=True, extranonce=5)
    append(primary, (proof_action(old_job, old_winner, winner=True),))
    first_settlement = summary(primary)
    assert set(primary.pending()) == {tail.proof_id, old_winner.proof_id}
    assert primary.state().paid == frozenset()
    next_job = make_job(primary, keys[2])
    next_winner = mine(next_job, full_block=True, extranonce=6)
    append(primary, (proof_action(next_job, next_winner, winner=True),))
    assert primary.state().paid == frozenset((tail.proof_id, old_winner.proof_id))
    assert set(primary.pending()) == {next_winner.proof_id}
    assert primary.state().reward_height == 2
    synchronize(primary, replicas[1:])
    record("old_winner_preserves_later_work", "An old job settles its committed work; the later canonical tail and winning proof are carried into the following settlement exactly once.",
           first_settlement=first_settlement, paid_later=[tail.proof_id.hex(), old_winner.proof_id.hex()],
           replicas=assert_converged(replicas))

    replicas, keys, registration = setup(PowRules(max_job_age=1))
    primary = replicas[0]
    old_job = make_job(primary, keys[0])
    old_proof = mine(old_job, extranonce=7)
    append(primary)
    append(primary)
    before = summary(primary)
    error = expect_error(lambda: append(primary, (proof_action(old_job, old_proof),)), "age")
    assert summary(primary) == before
    sibling = append(replicas[1], (proof_action(old_job, old_proof),), parent=registration.checkpoint_id)
    assert old_proof.proof_id in replicas[1].pending()
    append(replicas[1])
    append(replicas[1])
    synchronize(replicas[1], (replicas[0], replicas[2]))
    record("job_admission_age_depends_on_parent_branch", "The same old job is expired on the deeper branch and eligible at a recent checkpoint on its sibling; all replicas accept the greater-work valid branch.",
           rejection=error, eligible_sibling=sibling.checkpoint_id.hex(),
           replicas=assert_converged(replicas))

    replicas, _, _ = setup()
    parent = append(replicas[0])
    child = append(replicas[0])
    before = summary(replicas[1])
    try:
        replicas[1].add(child)
    except MissingData:
        pass
    else:
        raise AssertionError("child without checkpoint parent was accepted")
    assert summary(replicas[1]) == before
    replicas[1].add(parent)
    replicas[1].add(child)
    synchronize(replicas[0], (replicas[2],))
    record("missing_parent_retry", "A child waits for its missing checkpoint parent; resubmission after dependency delivery reproduces the same state.",
           replicas=assert_converged(replicas))

    replicas, keys, _ = setup()
    left_job, right_job = make_job(replicas[0], keys[0]), make_job(replicas[1], keys[1])
    left_proof = mine(left_job, full_block=True, extranonce=8)
    right_proof = mine(right_job, full_block=True, extranonce=9)
    left = append(replicas[0], (proof_action(left_job, left_proof, winner=True),))
    right = append(replicas[1], (proof_action(right_job, right_proof, winner=True),))
    left_balances, right_balances = dict(replicas[0].state().balances), dict(replicas[1].state().balances)
    assert set(left_balances) == {b"\x51"}
    assert set(right_balances) == {b"\x52"}
    assert left_balances != right_balances
    replicas[2].add(left)
    append(replicas[1])
    synchronize(replicas[1], (replicas[0], replicas[2]))
    assert dict(replicas[0].state().balances) == right_balances
    assert set(replicas[0].pending()) == {right_proof.proof_id}
    assert left_proof.proof_id not in {claim.proof_id for claim in replicas[0].state().claims}
    record("checkpoint_fork_reorganizes_lab_reward_accounting", "Greater checkpoint chainwork selects the right branch and rolls back the other branch's provisional payouts and work.",
           abandoned_checkpoint=left.checkpoint_id.hex(), chosen_checkpoint=right.checkpoint_id.hex(),
           previous_balances={script.hex(): amount for script, amount in left_balances.items()},
           bitcoin_fork_choice_tested=False, replicas=assert_converged(replicas))

    replicas, _, registration = setup()
    left = mine_checkpoint(replicas[0], parent=registration.checkpoint_id, start_nonce=0)
    right = mine_checkpoint(replicas[0], parent=registration.checkpoint_id, start_nonce=1000000)
    assert left.checkpoint_id != right.checkpoint_id
    replicas[0].add(left)
    replicas[0].add(right)
    replicas[1].add(right)
    replicas[1].add(left)
    replicas[2].add(Checkpoint.from_object(right.to_object()))
    replicas[2].add(Checkpoint.from_object(left.to_object()))
    assert replicas[0].tip == min(left.checkpoint_id, right.checkpoint_id)
    record("equal_work_tie_is_delivery_order_independent", "Identical checkpoint chainwork uses the same hash tie break regardless of arrival order or serialization round trip.",
           alternatives=[left.checkpoint_id.hex(), right.checkpoint_id.hex()],
           replicas=assert_converged(replicas))

    replicas, keys, _ = setup()
    job = make_job(replicas[0], keys[0])
    share = mine(job, extranonce=10)
    append(replicas[0], (proof_action(job, share),))
    synchronize(replicas[0], replicas[1:])
    before = summary(replicas[0])
    with tempfile.TemporaryDirectory(prefix="sharepool-pow-ledger-") as directory:
        path = Path(directory) / "ledger.json"
        replicas[0].save(path)
        restored = PowLedger.restore(path, replicas[0].rules)
    assert summary(restored) == before
    assert restored.import_objects(replicas[0].export()) == 0
    assert summary(restored) == before
    append(restored)
    synchronize(restored, replicas)
    record("restart_revalidation_and_duplicate_delivery", "Restoration revalidates the checkpoint archive, duplicate delivery leaves credit unchanged, and the restored node can extend the ledger.",
           before=before, replicas=assert_converged(replicas))

    return {"format": 1, "scope": "permissionless proof-of-work checkpoint reference scenarios",
            "passed": all(case["passed"] for case in cases), "scenario_count": len(cases),
            "replicas_per_scenario": 3,
            "assumptions": ["Deterministic public fixture keys and easy proof-of-work targets.",
                            "Direct bundle/checkpoint delivery; no real peer transport or ASIC integration.",
                            "Checkpoint-selected reward history is lab accounting, not Bitcoin fork choice.",
                            "Heartbeat epochs are checkpoint-based; this does not measure physical TH/s.",
                            "Quotas aggregate registered payout scripts; tags retain template and miner attribution.",
                            "A proof-of-work ledger chooses among disclosed histories; unobserved work cannot be accounted for."],
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).with_name("results") / "pow-ledger.json")
    args = parser.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{result['scenario_count']} permissionless checkpoint scenarios passed; report: {args.output}")


if __name__ == "__main__":
    main()
