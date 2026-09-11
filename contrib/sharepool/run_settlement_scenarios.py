#!/usr/bin/env python3
"""Run deterministic multi-node model scenarios and write a machine-readable report."""

import argparse
from dataclasses import replace
import json
from pathlib import Path
import tempfile

from proof_fixtures import make_share
from settlement_sim import (ANCHOR_HASH, REWARD, DEFAULT_CAP_HASHES_PER_SECOND,
                            DEFAULT_WINDOW_SECONDS, Node, SnapshotBundle,
                            make_candidate, payout_plan, credited_records)
from work_rate_budget import evaluate as evaluate_budget


def bundle(parent=None, prefix="tag", count=12, sequence=0):
    parent_hash = ANCHOR_HASH if parent is None else parent.block_id
    from settlement_sim import decode_header
    height = 1 if parent is None else decode_header(parent.header).m_height + 1
    shares = tuple(make_share((prefix + "-" + str(i)).encode(), parent_hash, height)
                   for i in range(count))
    return SnapshotBundle(parent_hash, height, shares, sequence=sequence,
                          previous_settlement=bytes(32) if parent is None else parent.root)


def deliver(node, block, snapshot):
    assert node.supply_snapshot(block.root, snapshot)
    return node.submit(block)


def state(node):
    return {"node": node.name, "tip": f"{node.tip:064x}",
            "valid_blocks": sum(s == "valid" for s in node.states.values()),
            "pending_blocks": sum(s == "pending" for s in node.states.values()),
            "invalid_blocks": sum(s == "invalid" for s in node.states.values()),
            "provisional_payout_total": sum(node.balances.values()),
            "active_share_count": len(node.consumed_shares)}


def run():
    cases = []

    def record(name, behavior, **details):
        cases.append({"name": name, "passed": True, "behavior": behavior, **details})

    original = bundle(count=10)
    block = make_candidate(original)
    left, right = Node("ordered"), Node("reversed")
    reversed_snapshot = replace(original, shares=tuple(reversed(original.shares)))
    assert original.root == reversed_snapshot.root
    assert deliver(left, block, original) == deliver(right, block, reversed_snapshot) == "valid"
    assert left.tip == right.tip and left.balances == right.balances
    record("snapshot_order_independence", "Same selected records produce the same root and settlement.",
           nodes=[state(left), state(right)])

    late = Node("missing-data")
    child_snapshot = bundle(block, prefix="child")
    child = make_candidate(child_snapshot)
    assert deliver(late, child, child_snapshot) == "pending"
    assert late.submit(block) == "pending"
    before = state(late)
    assert not late.supply_snapshot(block.root, child_snapshot)
    assert late.states[block.block_id] == late.states[child.block_id] == "pending"
    assert late.supply_snapshot(block.root, original)
    assert late.tip == child.block_id and sum(late.balances.values()) == 2 * REWARD
    record("missing_and_wrong_peer_data", "Wait, discard a wrong reply, then validate both parent and child when correct data arrives.",
           before=before, after=state(late))

    extra = make_share(b"tag-0", ANCHOR_HASH, 1, nonce_seed=91)
    newer = replace(original, sequence=1, shares=(*original.shares, extra))
    issued = Node("newer-local-job")
    issued.known_shares.update(s.share_id for s in newer.shares)
    issued.supply_snapshot(newer.root, newer)
    assert deliver(issued, block, original) == "valid"
    assert extra.share_id not in issued.consumed_shares
    record("older_issued_job", "Settle the winning job's snapshot, not a newer local share inventory.",
           included_shares=len(issued.consumed_shares), later_share_included=False)

    duplicate = replace(original, shares=(*original.shares, original.shares[0]))
    invalid = make_candidate(duplicate, payout_override=payout_plan(original))
    invalid_child_snapshot = bundle(invalid, prefix="invalid-child")
    invalid_child = make_candidate(invalid_child_snapshot)
    validator = Node("invalid-evidence")
    assert deliver(validator, invalid, duplicate) == "invalid"
    assert deliver(validator, invalid_child, invalid_child_snapshot) == "invalid"
    assert validator.tip == ANCHOR_HASH
    record("duplicate_committed_share", "Correctly committed duplicate proof invalidates the block and excludes descendants.",
           reasons=list(validator.reasons.values()), node=state(validator))

    normal_payouts = payout_plan(original)
    diverted = ((b"coordinator", REWARD),)
    stolen = make_candidate(original, salt=2, payout_override=diverted)
    payout_node = Node("payout-check")
    assert deliver(payout_node, stolen, original) == "invalid"
    assert payout_node.reasons[stolen.block_id] == "payouts"
    assert deliver(payout_node, block, original) == "valid"
    assert sum(amount for _, amount in normal_payouts) == REWARD
    record("payout_diversion", "A valid PoW and snapshot do not excuse coinbase outputs that violate the committed payout calculation.",
           rejection=payout_node.reasons[stolen.block_id])

    sa, sb = bundle(prefix="branch-A"), bundle(prefix="branch-B")
    ba, bb = make_candidate(sa), make_candidate(sb)
    a, b = Node("fork-A"), Node("fork-B")
    for node, first, first_s, second, second_s in ((a, ba, sa, bb, sb), (b, bb, sb, ba, sa)):
        assert deliver(node, first, first_s) == deliver(node, second, second_s) == "valid"
    assert a.tip == ba.block_id and b.tip == bb.block_id
    before = [state(a), state(b)]
    old_b_shares = set(b.consumed_shares)
    extension_snapshot = bundle(ba, prefix="extension")
    extension = make_candidate(extension_snapshot)
    for node in (a, b):
        assert deliver(node, extension, extension_snapshot) == "valid"
    assert a.tip == b.tip == extension.block_id and a.balances == b.balances
    assert not old_b_shares.intersection(b.consumed_shares)
    assert not any(tag.startswith(b"branch-B") for tag in b.balances)
    assert sum(b.balances.values()) == 2 * REWARD
    before_repeat = dict(b.balances)
    deliver(b, extension, extension_snapshot)
    assert b.balances == before_repeat
    record("same_rules_fork_and_reorg", "Equal-work tips may differ; more valid work converges nodes and replaces the old branch's provisional settlement.",
           before=before, after=[state(a), state(b)], duplicate_delivery_idempotent=True,
           unsigned_proposal_conflict_observed=bool(a.conflicts))

    with tempfile.TemporaryDirectory(prefix="sharepool-state-") as directory:
        path = Path(directory) / "node.json"
        b.save(path)
        restored = Node.restore(path)
        assert restored.tip == b.tip and restored.balances == b.balances
        assert restored.consumed_shares == b.consumed_shares
    record("restart_replay", "Revalidate stored objects and reconstruct the active settlement without double counting.")

    over_budget = bundle(prefix="over-budget")
    extra_work = make_share(b"over-budget-0", ANCHOR_HASH, 1, nonce_seed=12)
    over_budget = replace(over_budget, shares=(*over_budget.shares, extra_work))
    bad_under_strict_budget = make_candidate(over_budget)
    strict = Node("budget-2", cap_hashes_per_second=1, window_seconds=2)
    relaxed = Node("budget-4", cap_hashes_per_second=2, window_seconds=2)
    assert deliver(strict, ba, sa) == "valid"
    assert deliver(relaxed, bad_under_strict_budget, over_budget) == "valid"
    assert deliver(strict, bad_under_strict_budget, over_budget) == "invalid"
    assert deliver(relaxed, ba, sa) == "valid"
    longer_s = bundle(bad_under_strict_budget, prefix="relaxed-child")
    longer = make_candidate(longer_s)
    assert deliver(strict, longer, longer_s) == "invalid"
    assert deliver(relaxed, longer, longer_s) == "valid"
    assert strict.tip == ba.block_id and relaxed.tip == longer.block_id
    record("different_consensus_rules", "A group with 4 work units passes a budget of 4 but fails a budget of 2; more work cannot cure the invalid ancestor.",
           group_work=4, strict_budget=2, relaxed_budget=4,
           nodes=[state(strict), state(relaxed)])

    common_parent = ba
    for prefix in ("common-child", "common-grandchild"):
        common_snapshot = bundle(common_parent, prefix=prefix)
        common_parent = make_candidate(common_snapshot)
        for node in (strict, relaxed):
            assert deliver(node, common_parent, common_snapshot) == "valid"
    assert strict.tip == relaxed.tip == common_parent.block_id
    assert strict.balances == relaxed.balances
    record("different_rules_common_valid_branch_reconverges", "A branch valid under both caps can reunite nodes when it gains the greatest cumulative work.",
           nodes=[state(strict), state(relaxed)])

    local_history = (*original.shares, *(make_share(b"tag-0", ANCHOR_HASH, 1, nonce_seed=i)
                                       for i in range(100, 110)))
    full = replace(original, shares=local_history)
    assert not evaluate_budget(credited_records(full), cap_hashes_per_second=1,
                               window_seconds=2).passes
    observer = Node("observes-extra-work")
    observer.known_shares.update(s.share_id for s in local_history)
    assert deliver(observer, block, original) == "valid"
    record("omission_limitation", "A committed sample fits the work budget despite known extra work exceeding it; this model does not prove total-pool disclosure.",
           finding="Unresolved complete eligible-share history", committed_group_work=2,
           observed_group_work=22, per_group_budget=2)

    startup = []
    for count in (0, 1, 2, 9, 10):
        snapshot = bundle(prefix="startup", count=count)
        candidate = make_candidate(snapshot, payout_override=((b"bootstrap", REWARD),)) if count == 0 else make_candidate(snapshot)
        node = Node("startup-" + str(count))
        outcome = deliver(node, candidate, snapshot)
        assert outcome == ("valid" if count > 0 else "invalid")
        startup.append({"groups": count, "outcome": outcome})
    record("no_minimum_group_count", "Any nonempty group count may pass its absolute budgets; no pool-percentage threshold applies.",
           outcomes=startup, finding="Empty snapshots still cannot derive work-based payouts")
    return {"success": True, "scope": "Deterministic model nodes; actual synthetic BLAKE2b proofs; not live settlement consensus",
            "assumptions": {"pool": "pool-A", "window": "shares reference candidate's parent",
                            "cap_hashes_per_second": DEFAULT_CAP_HASHES_PER_SECOND,
                            "window_seconds": DEFAULT_WINDOW_SECONDS,
                            "window_time_basis": "configured nominal duration; no share arrival clock",
                            "reward": REWARD, "xor_key": "zero/public",
                            "snapshot_inclusion": "coordinator-disclosed set",
                            "supporting_templates": "zero-payout evidence jobs; eligibility as settlement-bearing reward-mining jobs is not established",
                            "signatures_and_full_bitcoin_consensus": False,
                            "balances": "provisional expected payouts; no maturity/spendability simulation"},
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / "simulation.json")
    args = parser.parse_args()
    report = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"success": True, "cases_passed": len(report["cases"]), "report": str(args.output)}))


if __name__ == "__main__":
    main()
