#!/usr/bin/env python3
"""Bounded per-operation graph work; no native throughput claims."""
from dataclasses import replace
import unittest
from unittest.mock import patch

import hash_snapshot as codec
from hash_gate_batch import check_graph
from test_hash_compact import compact_fixture


def graph_fixture(alternatives=16, inherited_proofs=96):
    origin, opening = compact_fixture()
    proofs = tuple(codec.solve_share(origin, opening, start_nonce=nonce) for nonce in range(inherited_proofs))
    parent_block, parent = compact_fixture(templates=(origin,), shares=proofs)
    children = [compact_fixture(height=2, native_parent=parent_block.sha256, parent_snapshot=parent, pool=100 + index)
                for index in range(alternatives)]
    openings = {opening.hash: opening for _, opening in children}
    _, root = compact_fixture(height=2, native_parent=parent_block.sha256, parent_snapshot=parent,
        templates=tuple(block for block, _ in children),
        shares=tuple(codec.solve_share(block, opening) for block, opening in children))
    def ancestor(identity, height):
        if identity != parent_block.sha256 or height != 1:
            raise AssertionError("graph changed the native-parent request binding")
        return parent
    return root, openings, parent, ancestor


class GraphLatencyTests(unittest.TestCase):
    def test_complete_canonical_graph_accounting_and_one_callback_per_hash(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=4, inherited_proofs=12)
        expected = {value.hash: value.serialize() for value in (root, parent, *openings.values())}
        callbacks = []
        result = check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=ancestor,
                             on_snapshot=lambda identity, raw: callbacks.append((identity, raw)))
        self.assertEqual(dict(callbacks), expected)
        self.assertEqual(len(callbacks), len(expected))
        self.assertEqual(result, {"snapshot_bytes": len(root.serialize()), "dependency_bytes": sum(map(len, expected.values())),
                                 "origins": 4, "dependency_shares": 16, "dependency_depth": 1})

    def test_each_unique_input_is_captured_once_inside_the_operation(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=4, inherited_proofs=12)
        capture, calls = codec.Snapshot.capture, []
        def counted(value):
            calls.append(value)
            return capture(value)
        with patch.object(codec.Snapshot, "capture", counted):
            check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=ancestor)
        self.assertEqual(len(calls), 6)  # Root, native parent and four alternate jobs.
        self.assertEqual(len({id(value) for value in calls}), 6)

    def test_later_callback_cannot_change_a_captured_parent(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=4, inherited_proofs=12)
        expected = {value.hash: value.serialize() for value in (root, parent, *openings.values())}
        callbacks, changed = {}, False
        def lookup(identity):
            nonlocal changed
            if not changed:
                parent.payouts[0].nValue -= 1
                changed = True
            return openings[identity]
        check_graph(root, lookup=lookup, parent_snapshot=ancestor,
                    on_snapshot=lambda identity, raw: callbacks.__setitem__(identity, raw))
        self.assertTrue(changed)
        self.assertEqual(callbacks, expected)
        # A fresh operation observes the edit and rejects its stale signature.
        with self.assertRaisesRegex(ValueError, "authorization"):
            check_graph(root, lookup=lookup, parent_snapshot=ancestor)

    def test_new_operation_rechecks_changed_external_opening(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=2, inherited_proofs=8)
        check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=ancestor)
        changed = next(iter(openings.values()))
        changed.payouts[0].nValue -= 1
        with self.assertRaisesRegex(ValueError, "another commitment"):
            check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=ancestor)

    def test_missing_or_wrong_native_ancestry_is_never_cached_as_empty(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=2, inherited_proofs=8)
        with self.assertRaisesRegex(ValueError, "missing"):
            check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=lambda identity, height: None)
        bad = replace(parent, envelope=replace(parent.envelope, height=2))
        with self.assertRaises(ValueError):
            check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=lambda identity, height: bad)
        result = check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=ancestor)
        self.assertEqual(result["dependency_shares"], 10)


if __name__ == "__main__":
    unittest.main()
