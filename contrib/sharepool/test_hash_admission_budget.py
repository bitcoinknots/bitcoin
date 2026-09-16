#!/usr/bin/env python3
"""Local pressure decisions preserve deadlines and exact resource boundaries."""
from dataclasses import FrozenInstanceError, replace
import unittest

from hash_admission_budget import (AdmissionBudget, AdmissionDecision, AdmissionQuote,
    AdmissionRefused, AdmissionResources, MAX_COUNTER)
from hash_snapshot import (MAX_CERTIFICATE_BYTES, MAX_COMPACT_SHARES,
    MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_SHARES,
    MAX_EXPANDED_TEMPLATE_BYTES, MAX_ORIGIN_CHECKS, MAX_SHARE_AGE,
    MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES)


def resources(proofs=1, **changes):
    base = AdmissionResources(snapshot_bytes=2048, dependency_bytes=4096,
        proofs=proofs, dependency_shares=proofs, origins=2,
        expanded_template_bytes=512, template_references=1,
        largest_template_bytes=512, dependency_depth=1, certificate_bytes=0,
        recipient_count=1, recipient_bytes=31)
    return replace(base, **changes)


def quote(*, offered=True, count=1, selected=None, origin=102, **changes):
    selected = count if selected is None else selected
    base = AdmissionQuote(native_tip="11" * 32, native_height=101,
        receipt_revision=7, eligible_count=count, selected_count=selected,
        oldest_origin_height=origin if count else None, resources=resources(selected),
        offered_count=int(offered), offered_selected=int(offered and selected == count),
        offered_origin_height=origin if offered else None)
    return replace(base, **changes)


class AdmissionBudgetTests(unittest.TestCase):
    def test_fresh_complete_quote_allows_one_ack_without_claiming_validity(self):
        value = quote(count=3)
        decision = AdmissionBudget().require_ack(value)
        self.assertEqual((decision.mode, decision.ack_allowed, decision.dispatch_allowed),
                         ("OPEN", True, False))
        self.assertEqual(decision.additional_inclusion_heights, MAX_SHARE_AGE)
        self.assertEqual((decision.native_tip, decision.native_height, decision.receipt_revision),
                         (value.native_tip, value.native_height, value.receipt_revision))
        self.assertEqual(decision.reasons, ())
        self.assertEqual(AdmissionBudget().require_ack(value), decision)

    def test_incomplete_byte_fitting_prefix_refuses_new_credit_but_can_drain(self):
        pending = quote(count=100, selected=62)
        with self.assertRaises(AdmissionRefused) as error:
            AdmissionBudget(snapshot_budget=65536).require_ack(pending)
        decision = error.exception.decision
        self.assertEqual(decision.mode, "DRAIN")
        self.assertEqual(decision.reasons,
            ("pending-prefix-does-not-fit", "offered-proof-not-selected"))
        self.assertTrue(error.exception.local_policy)
        self.assertFalse(error.exception.consensus_invalid)
        self.assertEqual(error.exception.reason_code, "local-admission-capacity")
        retained = replace(pending, offered_count=0, offered_selected=0, offered_origin_height=None)
        draining = AdmissionBudget(snapshot_budget=65536).dispatch(retained)
        self.assertEqual((draining.mode, draining.dispatch_allowed), ("DRAIN", True))
        self.assertEqual((retained.eligible_count, retained.selected_count), (100, 62))

    def test_atomic_external_batch_requires_every_new_proof_in_the_next_prefix(self):
        # Two durable receipts precede three newly offered proofs. Admission
        # never acknowledges just the fitting subset of that atomic batch.
        full = quote(count=5, offered_count=3, offered_selected=3)
        self.assertTrue(AdmissionBudget().require_ack(full).ack_allowed)
        partial = replace(full, selected_count=4, offered_selected=2, resources=resources(4))
        with self.assertRaises(AdmissionRefused) as error:
            AdmissionBudget().require_ack(partial)
        self.assertEqual(error.exception.decision.reasons,
                         ("pending-prefix-does-not-fit", "offered-proof-not-selected"))
        self.assertFalse(error.exception.decision.ack_allowed)
        self.assertFalse(error.exception.decision.dispatch_allowed)
        with self.assertRaises(ValueError):
            replace(full, offered_selected=2)  # Cannot select three old receipts from two.
        boundary = quote(count=MAX_COMPACT_SHARES, offered_count=MAX_COMPACT_SHARES,
                         offered_selected=MAX_COMPACT_SHARES)
        self.assertTrue(AdmissionBudget().require_ack(boundary).ack_allowed)
        with self.assertRaises(ValueError):
            replace(boundary, offered_count=MAX_COMPACT_SHARES + 1)

    def test_one_height_margin_is_exact_and_does_not_expire_existing_ack(self):
        budget = AdmissionBudget()
        # Next settlement is 102. Origin 100 remains eligible through 103,
        # leaving one additional inclusion height after that next settlement.
        self.assertTrue(budget.require_ack(quote(origin=100)).ack_allowed)
        last_chance = quote(origin=99)
        with self.assertRaises(AdmissionRefused) as error:
            budget.require_ack(last_chance)
        self.assertEqual(error.exception.decision.additional_inclusion_heights, 0)
        self.assertEqual(error.exception.decision.reasons, ("admission-deadline-margin",))
        old_ack = replace(last_chance, offered_count=0, offered_selected=0, offered_origin_height=None)
        self.assertTrue(budget.dispatch(old_ack).dispatch_allowed)
        self.assertEqual(budget.dispatch(old_ack).mode, "DRAIN")

    def test_oldest_pending_deadline_controls_even_when_new_proof_is_fresh(self):
        pending = quote(count=2, origin=99, offered_origin_height=102)
        with self.assertRaises(AdmissionRefused) as error:
            AdmissionBudget().require_ack(pending)
        self.assertEqual(error.exception.decision.additional_inclusion_heights, 0)
        self.assertEqual(pending.offered_origin_height, 102)

    def test_empty_queue_can_dispatch_but_empty_selected_prefix_cannot_drain(self):
        empty = quote(offered=False, count=0)
        self.assertEqual(AdmissionBudget().dispatch(empty).mode, "OPEN")
        self.assertIsNone(AdmissionBudget().dispatch(empty).additional_inclusion_heights)
        with self.assertRaises(AdmissionRefused):
            AdmissionBudget().dispatch(quote(offered=False, count=3, selected=0))

    def test_every_native_resource_limit_is_checked_at_and_beyond_boundary(self):
        fields = {"dependency_bytes": MAX_DEPENDENCY_BYTES,
            "dependency_shares": MAX_DEPENDENCY_SHARES, "origins": MAX_ORIGIN_CHECKS,
            "expanded_template_bytes": MAX_EXPANDED_TEMPLATE_BYTES,
            "template_references": MAX_TEMPLATE_TX_REFERENCES,
            "largest_template_bytes": MAX_TEMPLATE_BYTES,
            "dependency_depth": MAX_DEPENDENCY_DEPTH,
            "certificate_bytes": MAX_CERTIFICATE_BYTES}
        policy = AdmissionBudget()
        for field, limit in fields.items():
            with self.subTest(field=field):
                fitting = quote(resources=resources(**{field: limit}))
                self.assertTrue(policy.require_ack(fitting).ack_allowed)
                oversized = replace(fitting, resources=replace(fitting.resources, **{field: limit + 1}))
                with self.assertRaises(AdmissionRefused) as error:
                    policy.require_ack(oversized)
                self.assertIn(field, error.exception.decision.resource_failures)
        for count, allowed in ((MAX_COMPACT_SHARES, True), (MAX_COMPACT_SHARES + 1, False)):
            value = quote(count=count)
            self.assertEqual(policy.evaluate(value).ack_allowed, allowed)
            if not allowed:
                self.assertIn("proofs", policy.evaluate(value).resource_failures)

    def test_local_snapshot_and_native_dependency_limits_are_independent(self):
        policy = AdmissionBudget(snapshot_budget=65536)
        at_limit = resources(snapshot_bytes=65536, dependency_bytes=MAX_DEPENDENCY_BYTES)
        self.assertTrue(policy.require_ack(quote(resources=at_limit)).ack_allowed)
        too_large = replace(at_limit, snapshot_bytes=65537)
        with self.assertRaises(AdmissionRefused) as error:
            policy.require_ack(quote(resources=too_large))
        self.assertEqual(error.exception.decision.resource_failures, ("snapshot_bytes",))
        dispatch = quote(offered=False, resources=too_large)
        with self.assertRaises(AdmissionRefused):
            policy.dispatch(dispatch)

    def test_recipient_bytes_are_reserved_once_and_size_changes_can_stop_admission(self):
        policy = AdmissionBudget(snapshot_budget=1024)
        # The total already includes all recipient encodings and their prefix.
        fitting = resources(snapshot_bytes=1024, dependency_bytes=4096,
                            recipient_count=20, recipient_bytes=20 * 43)
        self.assertTrue(policy.require_ack(quote(resources=fitting)).ack_allowed)
        # Same proof count but more payout recipients consumes the actual byte
        # budget; no independent arbitrary miner-count cap is involved.
        many = replace(fitting, snapshot_bytes=1100, recipient_count=34, recipient_bytes=34 * 31)
        with self.assertRaises(AdmissionRefused) as error:
            policy.require_ack(quote(resources=many))
        self.assertEqual(error.exception.decision.resource_failures,
                         ("snapshot_bytes", "recipient_count", "recipient_bytes"))

    def test_conservative_refusal_can_be_replaced_by_exact_fit_without_cached_verdict(self):
        policy = AdmissionBudget(snapshot_budget=65536)
        conservative = quote(resources=resources(snapshot_bytes=65537, dependency_bytes=70000))
        with self.assertRaises(AdmissionRefused):
            policy.require_ack(conservative)
        exact = replace(conservative, resources=resources(snapshot_bytes=65000, dependency_bytes=69000))
        self.assertTrue(policy.require_ack(exact).ack_allowed)
        with self.assertRaises(AdmissionRefused):
            policy.require_ack(conservative)

    def test_native_payout_capacity_is_independent_of_snapshot_capacity(self):
        fitting = quote(resources=resources(recipient_count=2, recipient_bytes=62),
                        native_payout_capacity_bytes=62)
        self.assertTrue(AdmissionBudget().require_ack(fitting).ack_allowed)
        # The snapshot is still small; the current native output/weight budget
        # alone refuses the recipient reservation.
        with self.assertRaises(AdmissionRefused) as error:
            AdmissionBudget().require_ack(replace(fitting, native_payout_capacity_bytes=61))
        self.assertEqual(error.exception.decision.resource_failures, ("recipient_count", "recipient_bytes"))
        self.assertNotIn("snapshot_bytes", error.exception.decision.resource_failures)
        conservative = replace(fitting, resources=replace(fitting.resources, recipient_bytes=70))
        with self.assertRaises(AdmissionRefused):
            AdmissionBudget().require_ack(conservative)
        self.assertTrue(AdmissionBudget().require_ack(fitting).ack_allowed)
        for capacity in (0, True, MAX_SNAPSHOT_BYTES + 1):
            with self.assertRaises(ValueError):
                replace(fitting, native_payout_capacity_bytes=capacity)
    def test_quote_freshness_belongs_to_gate_and_new_context_changes_deadline(self):
        policy = AdmissionBudget()
        original = quote(origin=100)
        self.assertTrue(policy.require_ack(original).ack_allowed)
        after_block = replace(original, native_height=102, native_tip="22" * 32, receipt_revision=8)
        with self.assertRaises(AdmissionRefused):
            policy.require_ack(after_block)
        # The evaluator deliberately has no global native context. Integration
        # must reject stale tip/head bindings; it cannot cache OPEN as validity.
        self.assertTrue(policy.require_ack(original).ack_allowed)
        with self.assertRaises(ValueError):
            replace(after_block, native_height=104)  # Now expired, not eligible.

    def test_policy_quotes_resources_and_decisions_are_immutable(self):
        policy = AdmissionBudget()
        value = quote()
        for obj, name in ((policy, "safety_blocks"), (value, "receipt_revision"),
                          (value.resources, "snapshot_bytes"), (policy.evaluate(value), "mode")):
            with self.subTest(obj=type(obj).__name__), self.assertRaises(FrozenInstanceError):
                setattr(obj, name, 0)

    def test_invalid_inputs_fail_before_a_pressure_or_validity_decision(self):
        for options in ({"snapshot_budget": True}, {"snapshot_budget": 1023},
                        {"snapshot_budget": MAX_SNAPSHOT_BYTES + 1},
                        {"safety_blocks": 0}, {"safety_blocks": 4}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                AdmissionBudget(**options)
        for changes in ({"native_tip": "AA" * 32}, {"native_height": True},
                        {"receipt_revision": MAX_COUNTER + 1}, {"eligible_count": -1},
                        {"selected_count": 2}, {"oldest_origin_height": 98},
                        {"offered_count": 2}, {"offered_selected": True},
                        {"offered_origin_height": 101}, {"resources": {}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(quote(), **changes)
        for changes in ({"snapshot_bytes": True}, {"dependency_bytes": 1},
                        {"recipient_count": 2, "recipient_bytes": 31},
                        {"dependency_shares": 0}, {"origins": MAX_COUNTER + 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                resources(**changes)
        with self.assertRaises(ValueError):
            AdmissionBudget().require_ack(quote(offered=False))
        with self.assertRaises(ValueError):
            AdmissionBudget().dispatch(quote())
        with self.assertRaises(ValueError):
            AdmissionBudget().evaluate({})
        with self.assertRaises(ValueError):
            AdmissionRefused({})


if __name__ == "__main__":
    unittest.main()
