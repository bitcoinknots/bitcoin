#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded local admission pressure, never consensus validity or a payment promise.

The gate supplies a fresh, conservative or exact quote for its deterministic
next settlement prefix. All resource fields include construction reservations;
recipient bytes are already included in snapshot/dependency bytes, not added
again here. A fitting conservative quote is sufficient; an oversized estimate
may be replaced by a fresh exact quote before refusing work.

This module performs no I/O, history walk, proof parsing or mutable reservation.
The caller binds the quote to the current tip and durable receipt revision,
authenticates its selected prefix and separately performs native validation.
Duplicate receipts are matched against exact durable bytes before this policy.
Already acknowledged receipts remain retained, even if fast blocks or a reorg
later prevent their admission. Expired/orphaned work is reported separately and
must not be supplied as eligible work in a new quote.
"""
from dataclasses import dataclass

from hash_snapshot import (MAX_CERTIFICATE_BYTES, MAX_COMPACT_SHARES,
    MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_SHARES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_ORIGIN_CHECKS, MAX_SHARE_AGE,
    MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES)


MAX_COUNTER = (1 << 63) - 1
# Largest current output-only builder allowance; the actual native tip may
# impose the smaller RDTS limit. See src/sharepool/mining_budget.h.
MAX_NATIVE_PAYOUT_BYTES = 999_612


def _integer(name, value, minimum=0, maximum=MAX_COUNTER):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid admission quote " + name)


@dataclass(frozen=True)
class AdmissionResources:
    """Actual or conservative upper bounds for one proposed settlement.

    Unique origins, transaction payloads/references and dependencies are charged
    by the caller's bounded accountant. ``recipient_bytes`` is the sum of full
    output encodings, excluding the output-count prefix; the complete snapshot
    count prefix and native historical recipient reservation are included in
    ``snapshot_bytes`` and ``dependency_bytes``. Count both current-pool and
    native historical recipients, including outputs whose value rounds to zero.
    ``origins`` and ``dependency_depth`` include mining construction headroom.
    """
    snapshot_bytes: int
    dependency_bytes: int
    proofs: int
    dependency_shares: int
    origins: int
    expanded_template_bytes: int
    template_references: int
    largest_template_bytes: int
    dependency_depth: int
    certificate_bytes: int
    recipient_count: int
    recipient_bytes: int

    def __post_init__(self):
        for name, value in vars(self).items():
            _integer(name, value)
        if (not self.snapshot_bytes or self.dependency_bytes < self.snapshot_bytes or
                self.dependency_shares < self.proofs or
                not 31 * self.recipient_count <= self.recipient_bytes <= 51 * self.recipient_count or
                self.recipient_bytes > self.snapshot_bytes):
            raise ValueError("inconsistent admission resource quote")


@dataclass(frozen=True)
class AdmissionQuote:
    """A scalar-only quote tied to one tip and durable receipt revision.

    Counts cover the eligible, unadmitted FIFO, including any newly offered
    proofs. ``selected_count`` is the quoted next-batch prefix;
    the caller verifies its exact identities/order. New proofs never overtake
    already acknowledged work. For an atomic offered batch, its origin height
    is the minimum across that batch. Dispatch quotes have no newly offered proof.
    An empty selected prefix with a nonempty eligible queue cannot drain it.
    """
    native_tip: str
    native_height: int
    receipt_revision: int
    eligible_count: int
    selected_count: int
    oldest_origin_height: object
    resources: AdmissionResources
    offered_count: int = 0
    offered_selected: int = 0
    offered_origin_height: object = None
    # Model callers may omit this field. A live gate must supply the ceiling
    # returned by the native payout-budget RPC for this exact parent context.
    native_payout_capacity_bytes: int = MAX_SNAPSHOT_BYTES

    def __post_init__(self):
        if (type(self.native_tip) is not str or len(self.native_tip) != 64 or
                any(c not in "0123456789abcdef" for c in self.native_tip)):
            raise ValueError("invalid admission quote native_tip")
        _integer("native_height", self.native_height, maximum=0x7fffffff)
        _integer("native_payout_capacity_bytes", self.native_payout_capacity_bytes, 1, MAX_SNAPSHOT_BYTES)
        for name in ("receipt_revision", "eligible_count", "selected_count"):
            _integer(name, getattr(self, name))
        _integer("offered_count", self.offered_count, maximum=MAX_COMPACT_SHARES)
        _integer("offered_selected", self.offered_selected, maximum=self.offered_count)
        if (type(self.resources) is not AdmissionResources or
                not self.offered_selected <= self.selected_count <= self.eligible_count or
                self.offered_count > self.eligible_count or self.resources.proofs != self.selected_count or
                self.selected_count - self.offered_selected > self.eligible_count - self.offered_count):
            raise ValueError("inconsistent admission prefix quote")
        first = max(1, self.native_height + 1 - MAX_SHARE_AGE)
        last = self.native_height + 1
        if self.eligible_count:
            _integer("oldest_origin_height", self.oldest_origin_height, first, last)
        elif self.oldest_origin_height is not None:
            raise ValueError("empty admission queue has an origin height")
        if self.offered_count:
            _integer("offered_origin_height", self.offered_origin_height, first, last)
            if self.offered_origin_height < self.oldest_origin_height:
                raise ValueError("offered origin precedes quoted oldest origin")
        elif self.offered_origin_height is not None:
            raise ValueError("dispatch quote has an offered origin")


@dataclass(frozen=True)
class AdmissionDecision:
    mode: str
    ack_allowed: bool
    dispatch_allowed: bool
    reasons: tuple
    resource_failures: tuple
    additional_inclusion_heights: object
    native_tip: str
    native_height: int
    receipt_revision: int
    eligible_count: int
    selected_count: int


class AdmissionRefused(ValueError):
    """A local capacity refusal, never a declaration that a proof is invalid."""
    local_policy = True
    consensus_invalid = False

    def __init__(self, decision):
        if type(decision) is not AdmissionDecision:
            raise ValueError("admission refusal requires its bounded decision")
        self.decision = decision
        self.reason_code = "local-admission-capacity"
        super().__init__(self.reason_code + ": " + ", ".join(decision.reasons))


@dataclass(frozen=True)
class AdmissionBudget:
    """Strict next-batch fit with one extra inclusion-height margin by default.

    DRAIN keeps an exact fitting settlement prefix mineable while refusing new
    local credits. Do not suppress a native-winning block because its separate
    share acknowledgement was refused. A margin is a local safety policy; it
    cannot guarantee settlement under future block timing, reorgs or data loss.
    """
    snapshot_budget: int = MAX_SNAPSHOT_BYTES
    safety_blocks: int = 1

    def __post_init__(self):
        _integer("snapshot_budget", self.snapshot_budget, 1024, MAX_SNAPSHOT_BYTES)
        _integer("safety_blocks", self.safety_blocks, 1, MAX_SHARE_AGE)

    def evaluate(self, quote):
        if type(quote) is not AdmissionQuote:
            raise ValueError("canonical admission quote required")
        resources = quote.resources
        payout_capacity = min(self.snapshot_budget, quote.native_payout_capacity_bytes)
        limits = (("snapshot_bytes", self.snapshot_budget),
            ("dependency_bytes", MAX_DEPENDENCY_BYTES),
            ("proofs", MAX_COMPACT_SHARES),
            ("dependency_shares", MAX_DEPENDENCY_SHARES),
            ("origins", MAX_ORIGIN_CHECKS),
            ("expanded_template_bytes", MAX_EXPANDED_TEMPLATE_BYTES),
            ("template_references", MAX_TEMPLATE_TX_REFERENCES),
            ("largest_template_bytes", MAX_TEMPLATE_BYTES),
            ("dependency_depth", MAX_DEPENDENCY_DEPTH),
            ("certificate_bytes", MAX_CERTIFICATE_BYTES),
            ("recipient_count", payout_capacity // 31),
            ("recipient_bytes", payout_capacity))
        failures = tuple(name for name, bound in limits if getattr(resources, name) > bound)
        reasons = []
        if failures:
            reasons.append("resource-budget")
        if quote.selected_count != quote.eligible_count:
            reasons.append("pending-prefix-does-not-fit")
        remaining = (None if quote.oldest_origin_height is None else
                     quote.oldest_origin_height + MAX_SHARE_AGE - (quote.native_height + 1))
        if remaining is not None and remaining < self.safety_blocks:
            reasons.append("admission-deadline-margin")
        if quote.offered_selected != quote.offered_count:
            reasons.append("offered-proof-not-selected")
        ready = not reasons
        # Dispatch is a separate assessment of already-retained work. A fitting
        # old prefix remains mineable during pressure; an empty prefix does not
        # drain a nonempty queue. No offered proof can borrow this exception.
        dispatch = (not quote.offered_count and not failures and
                    (quote.selected_count > 0 or quote.eligible_count == 0))
        return AdmissionDecision("OPEN" if ready else "DRAIN",
            ready and quote.offered_count > 0, dispatch, tuple(reasons), failures,
            remaining, quote.native_tip, quote.native_height, quote.receipt_revision,
            quote.eligible_count, quote.selected_count)

    def require_ack(self, quote):
        if type(quote) is not AdmissionQuote or not quote.offered_count:
            raise ValueError("new acknowledgement requires a nonempty offered proof quote")
        decision = self.evaluate(quote)
        if not decision.ack_allowed:
            raise AdmissionRefused(decision)
        return decision

    def dispatch(self, quote):
        if type(quote) is not AdmissionQuote or quote.offered_count:
            raise ValueError("dispatch requires an already-retained prefix quote")
        decision = self.evaluate(quote)
        if not decision.dispatch_allowed:
            raise AdmissionRefused(decision)
        return decision
