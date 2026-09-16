#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact arithmetic reference for separate-pool TIDES accounting, not consensus.

Source: https://ocean.xyz/docs/tides (read 2026-09-12). Its specified behavior is
ordered distinct shares, an eight-current-difficulty work window, issuance-time
cutoff, a smaller startup denominator, repeated rewards without deleting history,
per-user aggregation, and satoshi floors. Transaction fees enter the full reward;
per-share operator-fee tags survive in separate per-user rate buckets.

Explicit reference conventions where that document is not complete:
* Clip the oldest contribution to the exact remaining work; retain its full log
  record. The text does not spell out the partial-boundary algorithm.
* Floor each script's aggregate gross reward, then deduct separately floored
  script/rate-bucket fees. Mixed-rate integer evaluation order is not specified.
* Report rounding residue as unclaimed; never assign largest-remainder bonuses,
  add balances, or choose an undocumented recipient. Zero fees are the default.
* Reject a completely empty window rather than invent a coordinator fallback.
* Work is supplied in a common exact integer scale. Target/difficulty conversion,
  ordering consensus, PoW, signatures, membership, archival storage and native
  coinbase construction must be established by the caller. No conversion from
  target into Bitcoin chainwork is asserted to equal TIDES difficulty.

Finite output limits reject the complete proposal; they never truncate miners.
This module does not activate or modify any native protocol version.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path


MAX_WORK = (1 << 256) - 1
MAX_MONEY = 21_000_000 * 100_000_000
FEE_DENOMINATOR = 1_000_000
WINDOW_MULTIPLIER = 8


class EmptyWindow(ValueError):
    """No denominator exists; an explicit bootstrap policy is required."""


class OutputBudgetExceeded(ValueError):
    """Every positive entitlement must fit; no partial payout is returned."""


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {label}")
    return value


def _identity(value, label):
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise ValueError(f"invalid {label}")
    return value


def is_payout_script(script):
    """The same standard output shapes accepted by the experimental native code."""
    return type(script) is bytes and (
        (len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac") or
        (len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87") or
        (len(script) == 22 and script[:2] == b"\x00\x14") or
        (len(script) == 34 and script[:2] in (b"\x00\x20", b"\x51\x20")))


def _script(script):
    if not is_payout_script(script):
        raise ValueError("invalid payout script")
    return script


@dataclass(frozen=True)
class Share:
    sequence: int
    proof_id: bytes
    pool_id: bytes
    payout_script: bytes
    work: int
    fee_ppm: int = 0

    def __post_init__(self):
        _integer(self.sequence, 1, (1 << 64) - 1, "sequence")
        _identity(self.proof_id, "proof ID")
        _identity(self.pool_id, "pool ID")
        _script(self.payout_script)
        _integer(self.work, 1, MAX_WORK, "work")
        _integer(self.fee_ppm, 0, FEE_DENOMINATOR, "fee rate")


@dataclass(frozen=True)
class IssuedJob:
    """Frozen inputs; an authenticated native job must separately bind them.

    job_id is only an opaque audit reference, not a computed commitment or
    signature. The library neither authenticates the supplied prefix nor proves
    that it was the latest complete accepted log when mining work was issued.
    """
    job_id: bytes
    pool_id: bytes
    shares: tuple
    network_work: int
    subsidy: int
    transaction_fees: int
    max_outputs: int = 10_000
    fee_recipient: bytes | None = None

    def __post_init__(self):
        _identity(self.job_id, "job ID")
        _identity(self.pool_id, "pool ID")
        _integer(self.network_work, 1, MAX_WORK, "network work")
        _integer(self.subsidy, 0, MAX_MONEY, "subsidy")
        _integer(self.transaction_fees, 0, MAX_MONEY - self.subsidy, "transaction fees")
        _integer(self.max_outputs, 0, (1 << 64) - 1, "output budget")
        if type(self.shares) is not tuple:
            raise ValueError("job history must be an immutable tuple")
        ids = set()
        for expected, share in enumerate(self.shares, 1):
            if type(share) is not Share or share.sequence != expected or share.pool_id != self.pool_id:
                raise ValueError("job needs one contiguous per-pool history prefix")
            if share.proof_id in ids:
                raise ValueError("duplicate proof in history")
            ids.add(share.proof_id)
        if self.fee_recipient is not None:
            _script(self.fee_recipient)
        if any(share.fee_ppm for share in self.shares) and self.fee_recipient is None:
            raise ValueError("fee-tagged history needs a committed fee recipient")

    @property
    def cutoff_sequence(self):
        return len(self.shares)

    @property
    def cutoff_proof_id(self):
        return self.shares[-1].proof_id if self.shares else None

    @property
    def reward(self):
        return self.subsidy + self.transaction_fees


class PoolLog:
    """Append-only in-memory reference; keeps history outside the active window.

    Accepted order is supplied by the caller, not inferred from wall clocks.
    There is no payment reset, implicit expiry, reordering, or pruning method.
    """

    def __init__(self, pool_id):
        self.pool_id = _identity(pool_id, "pool ID")
        self._shares = []
        self._ids = set()

    @property
    def shares(self):
        return tuple(self._shares)

    def append(self, share):
        if type(share) is not Share or share.pool_id != self.pool_id or share.sequence != len(self._shares) + 1:
            raise ValueError("share does not extend this pool's contiguous history")
        if share.proof_id in self._ids:
            raise ValueError("duplicate proof")
        self._shares.append(share)
        self._ids.add(share.proof_id)

    def issue_job(self, job_id, network_work, subsidy, transaction_fees=0, *, max_outputs=10_000, fee_recipient=None):
        return IssuedJob(job_id, self.pool_id, self.shares, network_work, subsidy,
                         transaction_fees, max_outputs, fee_recipient)


@dataclass(frozen=True)
class Contribution:
    share: Share
    included_work: int


@dataclass(frozen=True)
class AddressReward:
    payout_script: bytes
    work: int
    gross: int
    operator_fee: int
    net: int


@dataclass(frozen=True)
class FeeBucket:
    payout_script: bytes
    fee_ppm: int
    work: int
    amount: int


@dataclass(frozen=True)
class Settlement:
    job: IssuedJob
    requested_work: int
    counted_work: int
    available_work: int
    contributions: tuple
    address_rewards: tuple
    fee_buckets: tuple
    operator_fee: int
    rounding_residue: int
    outputs: tuple


def evaluate_job(job):
    """Calculate all entitlements from the exact immutable issuance prefix.

    Output pairs are (canonical script bytes, satoshis), sorted by script. Zero
    entitlements remain in address_rewards but do not consume coinbase outputs.
    Pool fees go only to the job-bound fee recipient. Residue remains unclaimed.
    Re-evaluating a job, including after later work arrives, has no state effect.
    """
    if type(job) is not IssuedJob:
        raise ValueError("issued job required")
    available = sum(share.work for share in job.shares)
    requested = WINDOW_MULTIPLIER * job.network_work
    denominator = min(available, requested)
    if denominator == 0:
        raise EmptyWindow("empty TIDES history requires an explicit bootstrap policy")
    remaining, selected = denominator, []
    work, buckets = defaultdict(int), defaultdict(int)
    for share in reversed(job.shares):
        contribution = min(share.work, remaining)
        selected.append(Contribution(share, contribution))
        work[share.payout_script] += contribution
        buckets[share.payout_script, share.fee_ppm] += contribution
        remaining -= contribution
        if remaining == 0:
            break
    selected.reverse()
    fees_by_script, fee_records = defaultdict(int), []
    for (script, rate), amount in sorted(buckets.items()):
        fee = job.reward * amount * rate // (denominator * FEE_DENOMINATOR)
        fees_by_script[script] += fee
        fee_records.append(FeeBucket(script, rate, amount, fee))
    rewards, outputs = [], defaultdict(int)
    for script, amount in sorted(work.items()):
        gross = job.reward * amount // denominator
        fee = fees_by_script[script]
        rewards.append(AddressReward(script, amount, gross, fee, gross - fee))
        outputs[script] += gross - fee
    total_fee = sum(fees_by_script.values())
    if total_fee:
        outputs[job.fee_recipient] += total_fee
    residue = job.reward - sum(value.gross for value in rewards)
    ordered_outputs = tuple((script, amount) for script, amount in sorted(outputs.items()) if amount)
    if len(ordered_outputs) > job.max_outputs:
        raise OutputBudgetExceeded("complete TIDES payout exceeds the output budget")
    return Settlement(job, requested, denominator, available, tuple(selected), tuple(rewards),
                      tuple(fee_records), total_fee, residue, ordered_outputs)


def _vector(name, job):
    result = evaluate_job(job)
    return {
        "name": name,
        "pool_id": job.pool_id.hex(), "network_work": str(job.network_work),
        "subsidy": job.subsidy, "transaction_fees": job.transaction_fees,
        "shares": [{"sequence": share.sequence, "proof_id": share.proof_id.hex(),
                    "payout_script": share.payout_script.hex(), "work": str(share.work)} for share in job.shares],
        "expected": {
            "window_work": str(result.requested_work), "eligible_work": str(result.counted_work),
            "weights": {value.payout_script.hex(): str(value.work) for value in result.address_rewards},
            "payouts": {script.hex(): amount for script, amount in result.outputs},
            "rounding_residue": result.rounding_residue,
            "oldest_sequence": result.contributions[0].share.sequence,
            "oldest_work": str(result.contributions[0].included_work),
        },
    }


def known_answer_vectors():
    """Zero-operator-fee shared vectors; decimal strings preserve large work."""
    pool_id, job_id = b"A" * 32, b"J" * 32
    scripts = tuple(b"\x00\x14" + bytes([number]) * 20 for number in (1, 2, 3))

    def job(rows, network_work, subsidy, transaction_fees=0):
        log = PoolLog(pool_id)
        for sequence, (owner, amount) in enumerate(rows, 1):
            log.append(Share(sequence, sequence.to_bytes(32, "big"), pool_id, scripts[owner], amount))
        return log.issue_job(job_id, network_work, subsidy, transaction_fees)

    return {
        "schema": 1, "kind": "exact integer TIDES accounting reference; not native consensus",
        "window_multiplier": WINDOW_MULTIPLIER,
        "work_convention": "caller-supplied common exact integer work scale; no target conversion",
        "boundary": "clip oldest contribution; preserve full original share",
        "rounding": "floor per-address aggregate reward; residue unclaimed; no fractional carry",
        "operator_fee": "zero in these vectors",
        "cases": [
            _vector("startup_floor_residue", job(((0, 1), (1, 3)), 4, 101)),
            _vector("oldest_partial_boundary", job(((0, 4), (1, 4), (2, 1)), 1, 80)),
            _vector("aggregate_address_before_rounding", job(((0, 1), (1, 1), (0, 1)), 1, 2)),
            _vector("include_transaction_fees", job(((0, 1), (1, 3)), 4, 100, 12)),
            _vector("sub_satoshi_no_balance", job(((0, 1), (1, 1000)), 128, 100)),
            _vector("huge_work_and_max_money", job(((0, MAX_WORK), (1, MAX_WORK - 1), (2, MAX_WORK - 2)),
                                                 MAX_WORK, MAX_MONEY - 123, 123)),
            _vector("huge_partial_boundary", job(((0, MAX_WORK), (1, MAX_WORK)), 1 << 253, MAX_MONEY)),
            _vector("before_difficulty_increase", job(((0, 8), (1, 8)), 1, 100)),
            _vector("after_difficulty_increase_restores_history", job(((0, 8), (1, 8)), 2, 100)),
            _vector("same_cutoff_rewarded_again", job(((0, 8), (1, 8)), 2, 100)),
            _vector("zero_reward_keeps_window", job(((0, 1), (1, 1)), 1, 0)),
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Export exact zero-fee TIDES reference vectors; no native execution.")
    parser.add_argument("--vectors-output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(known_answer_vectors(), indent=2, sort_keys=True) + "\n"
    if args.vectors_output:
        args.vectors_output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
