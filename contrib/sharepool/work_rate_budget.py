#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact work budgets for supplied records in one externally agreed window.

A group passes the budget when its summed credited work is no greater than
cap_hashes_per_second * window_seconds. All records with the same canonical payout
script accumulate together, regardless of tag, miner, job, or submission order.

The caller must establish window membership, verified payout-script grouping, preassigned share
targets, valid proofs, and the complete eligible record set. This module does
none of those things. The configured duration is the full common window, never
the elapsed time between the first and last disclosed shares. Dividing credited
work by that duration estimates disclosed work rate; it does not prove an upper
bound on physical hashrate. Submission timestamps are not consensus inputs here.
"""

from dataclasses import dataclass
from typing import Iterable

from work_accounting import WorkAccountingResult, CreditedRecord, GroupWork
from work_accounting import evaluate as evaluate_accounting


@dataclass(frozen=True)
class WorkRateBudgetResult:
    accounting: WorkAccountingResult
    cap_hashes_per_second: int
    window_seconds: int

    @property
    def budget_work(self) -> int:
        return self.cap_hashes_per_second * self.window_seconds

    @property
    def offenders(self) -> tuple[GroupWork, ...]:
        return tuple(group for group in self.accounting.groups
                     if group.credited_work > self.budget_work)

    @property
    def passes(self) -> bool:
        """Whether nonempty supplied evidence meets the absolute work budget."""
        return self.accounting.total_work > 0 and not self.offenders


def evaluate(records: Iterable[CreditedRecord], *, cap_hashes_per_second: int,
             window_seconds: int) -> WorkRateBudgetResult:
    """Apply one budget per supplied payout-script group over the common window.

    Use credited work derived from preassigned share targets, not share counts
    or the achieved hash. Invalid record fields and duplicate share IDs raise
    ValueError via the accounting evaluator. Empty evidence does not pass;
    absence of disclosed shares is not verified zero hashrate.
    """
    for name, value in (("cap_hashes_per_second", cap_hashes_per_second),
                        ("window_seconds", window_seconds)):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer, excluding bool")
    return WorkRateBudgetResult(evaluate_accounting(records),
                                cap_hashes_per_second, window_seconds)
