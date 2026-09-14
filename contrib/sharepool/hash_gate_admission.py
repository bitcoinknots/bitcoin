#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""V8 gate-local admission accounting; native validation and the journal are authoritative.

One owner keeps bounded resource metadata for one tip/receipt revision. A fresh
proof still supplies its complete canonical provenance and native verdict. The
metadata avoids choosing and serializing the entire pending batch on every ACK.
Conservative overflow falls back to the gate's exact deterministic batch fit.
"""
from dataclasses import dataclass, replace

from hash_admission_budget import AdmissionDecision, AdmissionQuote, AdmissionResources, AdmissionRefused
from hash_admission_accounting import CompactAdmissionAccountant, MetadataCapacity
from hash_gate_batch import EmptyBatchCapacity
from hash_snapshot import MAX_SHARE_AGE


@dataclass
class _State:
    key: tuple
    quote: AdmissionQuote
    accountant: object = None


@dataclass(frozen=True)
class _Ticket:
    key: tuple
    quote: AdmissionQuote
    accountant: object
    delta: object = None


def _key(gate, tip):
    return tip, gate._head()["receipt_revision"], gate._dispatch_policy()


def select_batch(gate, height, tip, parent, **options):
    """Translate only explicit local empty-batch resource exhaustion.

    No successful quote exists when construction fails before an empty root
    can fit. Its scalar inventory is still exact; do not invent a valid root,
    discard acknowledged work, or mislabel the failure as invalid miner work.
    """
    try:
        return gate._batch(height, tip, parent, **options)
    except EmptyBatchCapacity as error:
        if gate._admission_budget is None:
            raise
        gate._stable(tip)
        gate._check_seal()
        remaining = (None if error.oldest_origin_height is None else
                     error.oldest_origin_height + MAX_SHARE_AGE - (height + 1))
        decision = AdmissionDecision("DRAIN", False, False, ("resource-budget",),
            ("empty_settlement",), remaining, tip, height,
            gate._head()["receipt_revision"], error.eligible_count, 0)
        failure = AdmissionRefused(decision)
        failure.capacity_reason = error.reason
        failure.resources = error.resources
        raise failure from error


def _resources(batch):
    usage = batch["resources"]
    return AdmissionResources(
        snapshot_bytes=usage["reserved_snapshot_bytes"],
        dependency_bytes=usage["reserved_dependency_bytes"],
        proofs=len(batch["snapshot"].shares), dependency_shares=usage["dependency_shares"],
        origins=usage["origins"], expanded_template_bytes=usage["expanded_template_bytes"],
        template_references=usage["template_references"], largest_template_bytes=usage["largest_template_bytes"],
        dependency_depth=usage["dependency_depth"], certificate_bytes=usage["certificate_bytes"],
        recipient_count=usage["recipient_count"], recipient_bytes=usage["recipient_bytes"])


def _quote(gate, height, tip, batch, *, offered=()):
    selected = {proof.proof_id for proof in batch["snapshot"].shares}
    return AdmissionQuote(tip, height, gate._head()["receipt_revision"],
        batch["eligible_count"], len(selected), batch["oldest_origin_height"], _resources(batch),
        offered_count=len(offered), offered_selected=sum(proof.proof_id in selected for proof in offered),
        offered_origin_height=min((proof.envelope.height for proof in offered), default=None),
        native_payout_capacity_bytes=batch["resources"]["native_payout_capacity_bytes"])


def _accountant(gate, batch, staged):
    captured = []
    usage = gate._provenance(batch["snapshot"], staged, mining_job=True, captures=captured)
    return CompactAdmissionAccountant(batch["snapshot"],
        historical_recipient_count=batch["resources"]["historical_recipient_count"],
        historical_recipient_bytes=batch["resources"]["historical_recipient_bytes"],
        dependencies=tuple(captured), depth=usage["dependency_depth"] - 1,
        certificate_bytes=batch["resources"]["historical_certificate_bytes"])


def _refresh(gate, height, tip, parent, staged):
    key = _key(gate, tip)
    state = gate._admission_state
    if state is not None and state.key == key:
        return state
    batch = select_batch(gate, height, tip, parent, staged=staged)
    quote = _quote(gate, height, tip, batch)
    accountant = None
    if quote.selected_count == quote.eligible_count:
        try:
            accountant = _accountant(gate, batch, staged)
        except MetadataCapacity:
            pass  # Optional metadata must not replace the exact resource check.
    gate._stable(tip)
    gate._check_seal()
    if _key(gate, tip) != key:
        raise ValueError("admission context changed during resource capture")
    state = _State(key, quote, accountant)
    gate._admission_state = state
    return state


def status(gate):
    """Return a fresh OPEN/DRAIN decision for the already retained prefix."""
    if gate._admission_budget is None:
        raise ValueError("admission backpressure requires an enabled v8 gate")
    gate._check_seal()
    height, tip = gate._context()
    state = gate._admission_state
    if state is None or state.key != _key(gate, tip):
        staged = {}
        parent = gate._parent_snapshot(height, tip, staged)
        state = _refresh(gate, height, tip, parent, staged)
    decision = gate._admission_budget.dispatch(state.quote)
    gate._stable(tip)
    gate._check_seal()
    if state.key != _key(gate, tip):
        raise ValueError("admission context changed before status")
    return decision


def pre_ack(gate, share, record, *, height, tip, parent, staged, captures, provenance):
    """Quote one new proof after its fresh native check and before durable ACK."""
    if gate._admission_budget is None:
        return None
    state = _refresh(gate, height, tip, parent, staged)
    key = state.key
    existing = state.quote
    oldest = (share.envelope.height if existing.oldest_origin_height is None else
              min(existing.oldest_origin_height, share.envelope.height))
    # A pre-existing backlog cannot justify accepting still more promises.
    if existing.selected_count != existing.eligible_count:
        gate._admission_budget.require_ack(replace(existing,
            eligible_count=existing.eligible_count + 1, oldest_origin_height=oldest,
            offered_count=1, offered_selected=0, offered_origin_height=share.envelope.height))
    if state.accountant is not None:
        try:
            delta = state.accountant.preview_delta(share, record, dependencies=tuple(captures),
                depth=provenance["dependency_depth"])
            if delta.duplicate:
                raise ValueError("admission metadata differs from durable receipt inventory")
            quote = AdmissionQuote(tip, height, key[1], delta.proof_count, delta.proof_count,
                delta.min_pending_origin_height, delta.resources, offered_count=1,
                offered_selected=1, offered_origin_height=share.envelope.height,
                native_payout_capacity_bytes=existing.native_payout_capacity_bytes)
            gate._admission_budget.require_ack(quote)
            if _key(gate, tip) != key:
                raise ValueError("admission context changed during preview")
            return _Ticket(key, quote, state.accountant, delta)
        except (MetadataCapacity, AdmissionRefused):
            # Tight CompactSize/recipient budgets can fit more than the safe
            # upper estimate. Only a fresh exact prefix may override refusal.
            pass
    batch = select_batch(gate, height, tip, parent, staged=staged, offered=(share,), templates=(record,))
    quote = _quote(gate, height, tip, batch, offered=(share,))
    gate._admission_budget.require_ack(quote)
    accountant = None
    try:
        accountant = _accountant(gate, batch, staged)
    except MetadataCapacity:
        pass
    gate._stable(tip)
    gate._check_seal()
    if _key(gate, tip) != key:
        raise ValueError("admission context changed before acknowledgement")
    return _Ticket(key, quote, accountant)


def post_ack(gate, ticket, accepted):
    """Update only optional metadata after the irreversible local receipt commit."""
    if ticket is None or not accepted:
        return
    try:
        key = _key(gate, ticket.key[0])
        if key != (ticket.key[0], ticket.key[1] + 1, ticket.key[2]):
            gate._admission_state = None
            return
        if ticket.delta is not None:
            ticket.accountant.commit(ticket.delta)
        quote = replace(ticket.quote, receipt_revision=key[1], offered_count=0,
            offered_selected=0, offered_origin_height=None)
        gate._admission_state = _State(key, quote, ticket.accountant)
    except Exception:
        # A failed optional allocation cannot revoke a durable receipt or turn
        # its successful acknowledgement into a false failure to the miner.
        gate._admission_state = None


def authorize_offers(gate, height, tip, batch, offered):
    """Check bulk ACK pressure or whether a retained prefix can drain."""
    if gate._admission_budget is not None:
        quote = _quote(gate, height, tip, batch, offered=offered)
        if offered:
            return gate._admission_budget.require_ack(quote)
        return gate._admission_budget.dispatch(quote)
