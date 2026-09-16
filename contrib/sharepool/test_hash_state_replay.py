#!/usr/bin/env python3
"""Exact-prefix replay reuse, rolling age boundaries and fresh resource checks."""
from dataclasses import replace
import unittest
from unittest.mock import patch

import hash_snapshot as codec
from hash_state_cache import CompactStateCache
from test_hash_compact import compact_fixture
from test_hash_snapshot import SECRET
from native_enforcement import sign_schnorr


class CompactStateReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain, cls.blocks, cls.snapshots = {}, {}, {}
        previous = None
        for height in range(1, 10):
            options = {"height": height, "parent_snapshot": previous}
            if previous is not None:
                options["native_parent"] = cls.blocks[height - 1].sha256
            origin, opening = compact_fixture(**options)
            proof = codec.solve_share(origin, opening)
            block, previous = compact_fixture(templates=(origin,), shares=(proof,), **options)
            cls.chain[block.sha256] = previous
            cls.blocks[height], cls.snapshots[height] = block, previous

    def lookup(self, identity, height):
        value = self.chain[identity]
        self.assertEqual(value.envelope.height, height)
        return value

    def run_materializer(self, value, cache, **options):
        return codec.materialize_compact_state(value, parent_snapshot=self.lookup, state_cache=cache, **options)

    def test_repeated_target_and_different_job_reuse_only_exact_common_prefix(self):
        cache = CompactStateCache()
        target = self.snapshots[5]
        _, alternate = compact_fixture(height=5, native_parent=self.blocks[4].sha256,
            parent_snapshot=self.snapshots[4], pool=81, ntime=1700000081)
        expected = self.run_materializer(alternate, None)
        with patch.object(codec, "apply_tides_state", wraps=codec.apply_tides_state) as apply, \
                patch.object(codec, "verify_schnorr", wraps=codec.verify_schnorr) as verify, \
                patch.object(cache, "put", wraps=cache.put) as put:
            self.run_materializer(target, cache)
            self.assertEqual((apply.call_count, verify.call_count, put.call_count), (4, 4, 2))
            self.run_materializer(target, cache)
            self.assertEqual((apply.call_count, verify.call_count, put.call_count), (4, 4, 2))
            observed = self.run_materializer(alternate, cache)
            self.assertEqual((apply.call_count, verify.call_count, put.call_count), (5, 5, 3))
        self.assertEqual((observed.post_state, observed.certificates, observed.history_head),
                         (expected.post_state, expected.certificates, expected.history_head))

    def test_warm_result_still_reads_charges_and_notifies_complete_native_suffix(self):
        cache = CompactStateCache()
        target = self.snapshots[5]
        self.run_materializer(target, cache)
        calls, openings = [], []
        def parent(identity, height):
            calls.append((identity, height))
            return self.lookup(identity, height)
        def observer(value, raw):
            openings.append((value.envelope.height, raw))
        with patch.object(codec, "apply_tides_state", side_effect=AssertionError("replayed warm target")):
            codec.materialize_compact_state(target, parent_snapshot=parent, state_cache=cache, on_snapshot=observer)
        self.assertEqual([height for _, height in calls], [4, 3, 2])
        self.assertEqual(openings, [(height, self.snapshots[height].serialize()) for height in range(2, 6)])
        total, proofs = sum(len(raw) for _, raw in openings), sum(len(self.snapshots[h].shares) for h in range(2, 6))
        # The cache must not be consulted after any fresh availability, resource
        # or observer failure, even though this exact successful key is warm.
        with patch.object(cache, "get", side_effect=AssertionError("used cache before fresh checks")):
            with self.assertRaisesRegex(ValueError, "missing"):
                codec.materialize_compact_state(target, parent_snapshot=lambda *args: None, state_cache=cache)
            with patch.object(codec, "MAX_DEPENDENCY_BYTES", total - 1):
                with self.assertRaisesRegex(ValueError, "dependency budget"):
                    self.run_materializer(target, cache)
            with patch.object(codec, "MAX_DEPENDENCY_SHARES", proofs - 1):
                with self.assertRaisesRegex(ValueError, "dependency budget"):
                    self.run_materializer(target, cache)
            def refuse(*args):
                raise ValueError("observer refused opening")
            with self.assertRaisesRegex(ValueError, "observer refused"):
                self.run_materializer(target, cache, on_snapshot=refuse)

    def test_shifted_left_boundary_misses_and_expires_each_old_cohort(self):
        cache = CompactStateCache()
        for height in range(4, 10):
            target = self.snapshots[height]
            with patch.object(codec, "apply_tides_state", wraps=codec.apply_tides_state) as apply:
                observed = self.run_materializer(target, cache)
            # The previous parent's cache entry includes one older cohort.
            # It cannot replace this child's exact four-opening suffix.
            self.assertEqual(apply.call_count, 4)
            self.assertEqual({entry.origin_height for entry in observed.post_state}, set(range(height - 3, height + 1)))
            self.assertEqual((observed.post_state, observed.certificates, observed.history_head),
                             (target.post_state, target.certificates, target.history_head))

    def test_intermediate_computed_head_cannot_masquerade_as_checked_target(self):
        cache = CompactStateCache()
        # Deliberately start the helper's suffix at an already signed ancestor
        # with earlier committed history. Native chain validity is separate;
        # this exercises the distinction between an intermediate computed head
        # and the raw ancestor head restored before calculating its child.
        self.run_materializer(self.snapshots[3], cache, activation_height=2)
        raw = self.snapshots[2].serialize()
        partial = cache.get((2, 7, (raw,)))
        self.assertIsNotNone(partial)
        self.assertNotEqual(partial.history_head, self.snapshots[2].history_head)
        with patch.object(codec, "apply_tides_state", side_effect=AssertionError("replayed cached prefix")), \
                patch.object(cache, "put", side_effect=AssertionError("stored rejected target")):
            with self.assertRaisesRegex(ValueError, "history head"):
                self.run_materializer(self.snapshots[2], cache, activation_height=2)

    def test_failed_target_does_not_publish_its_successful_prefix(self):
        target = self.snapshots[5]
        bad = replace(target, history_head=target.history_head ^ 1)
        bad = replace(bad, owner_signature=sign_schnorr(SECRET, bad.owner_message))
        cache = CompactStateCache()
        with patch.object(cache, "put", side_effect=AssertionError("stored prefix of failed target")):
            with self.assertRaisesRegex(ValueError, "history head"):
                self.run_materializer(bad, cache)
        self.assertEqual(cache.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
