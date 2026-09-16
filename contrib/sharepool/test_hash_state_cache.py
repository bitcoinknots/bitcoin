#!/usr/bin/env python3
"""Exact-ancestry memoization preserves reads, charges and failure semantics."""
from dataclasses import replace
import unittest
import weakref
from unittest.mock import patch

import hash_snapshot as codec
from hash_gate_batch import check_graph
from hash_state_cache import CompactStateCache, ENTRY_OVERHEAD
from test_hash_compact import compact_fixture
from test_hash_graph_latency import graph_fixture


def cache_fixture(proofs=2, **options):
    origin, opening = compact_fixture()
    shares = tuple(codec.solve_share(origin, opening, start_nonce=n) for n in range(proofs))
    _, value = compact_fixture(templates=(origin,), shares=shares, **options)
    result = codec.materialize_compact_state(value, parent_snapshot=lambda identity, height: None)
    return (1, 7, (value.serialize(),)), result, value


class CompactStateCacheTests(unittest.TestCase):
    def test_exact_raw_activation_profile_and_branch_keys(self):
        key, derived, value = cache_fixture()
        cache = CompactStateCache()
        self.assertTrue(cache.put(key, derived))
        self.assertIs(cache.get(key), derived)
        self.assertIsNone(cache.get((2, 7, key[2])))
        changed = key[2][0][:-1] + bytes([key[2][0][-1] ^ 1])
        self.assertIsNone(cache.get((1, 7, (changed,))))
        self.assertIsNone(cache.get((1, 7, (b"other native prefix", *key[2]))))
        with self.assertRaisesRegex(ValueError, "key"):
            cache.get((1, 6, key[2]))
        for bad in ((True, 7, key[2]), (0, 7, key[2]), (1, 7, ()),
                    (1, 7, (bytearray(key[2][0]),)), (1, 7, key[2] * 5)):
            with self.assertRaises(ValueError):
                cache.get(bad)

    def test_retained_outputs_records_and_header_metadata_are_immutable(self):
        key, derived, value = cache_fixture()
        cache = CompactStateCache()
        self.assertTrue(cache.put(key, derived))
        saved = cache.get(key)
        original = saved.serialize(), saved.post_state, saved.shares[0].proof_id
        with self.assertRaises(AttributeError):
            saved.payouts[0].nValue = 0
        with self.assertRaises(AttributeError):
            saved.post_state[0].origin_height = 123
        with self.assertRaises(AttributeError):
            saved.post_state += saved.post_state
        header = saved.shares[0].header
        header.nNonce += 1
        value.payouts[0].nValue -= 1
        self.assertEqual((saved.serialize(), saved.post_state, saved.shares[0].proof_id), original)
        charge = cache.stats()["bytes"]
        for share in saved.shares:
            share.header_facts
            share.proof_id
        self.assertEqual(cache.stats()["bytes"], charge)
        with self.assertRaisesRegex(ValueError, "immutable"):
            cache.put(key, replace(derived, payouts=value.payouts))
        with self.assertRaisesRegex(ValueError, "immutable"):
            cache.put(key, replace(derived, post_state=list(derived.post_state)))

    def test_byte_share_and_entry_limits_with_replacement_eviction_and_clear(self):
        key, derived, _ = cache_fixture()
        cache = CompactStateCache(max_entries=2)
        self.assertTrue(cache.put(key, derived))
        charged = cache.stats()["bytes"]
        self.assertGreater(charged, ENTRY_OVERHEAD + len(key[2][0]))
        self.assertEqual(cache.stats()["shares"], 4)  # Two proofs plus two state entries.
        self.assertTrue(cache.put(key, derived))
        self.assertEqual((cache.stats()["bytes"], cache.stats()["shares"]), (charged, 4))
        keys = [key, (1, 7, (b"prefix b", *key[2])), (1, 7, (b"prefix c", *key[2]))]
        self.assertTrue(cache.put(keys[1], derived))
        self.assertIsNotNone(cache.get(key))  # Make the first key most recent.
        self.assertTrue(cache.put(keys[2], derived))
        self.assertIsNone(cache.get(keys[1]))
        self.assertEqual(cache.stats()["entries"], 2)
        for options in ({"max_bytes": charged - 1}, {"max_shares": 3}, {"max_entries": 0}):
            small = CompactStateCache(**options)
            self.assertFalse(small.put(key, derived))
            self.assertEqual(small.stats()["entries"], 0)
            self.assertEqual(small.stats()["oversized"], 1)
        aggregate = CompactStateCache(max_shares=4)
        aggregate.put(key, derived)
        aggregate.put(keys[1], derived)
        self.assertEqual((aggregate.stats()["entries"], aggregate.stats()["shares"]), (1, 4))
        self.assertIsNone(aggregate.get(key))
        retained = weakref.ref(derived)
        del derived
        cache.clear()
        aggregate.clear()
        self.assertIsNone(retained())
        self.assertEqual(cache.stats(), {"entries": 0, "bytes": 0, "shares": 0,
                                        "hits": 0, "misses": 0, "oversized": 0})
        for options in ({"max_bytes": -1}, {"max_shares": True}, {"max_entries": 1.5}):
            with self.assertRaises(ValueError):
                CompactStateCache(**options)

    def test_repeated_graph_hit_still_fetches_and_charges_every_opening(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=3, inherited_proofs=5)
        cache, reads, callbacks = CompactStateCache(), [], []
        def native(identity, height):
            reads.append((identity, height))
            return ancestor(identity, height)
        def run():
            observed = []
            result = check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=native,
                state_cache=cache, on_snapshot=lambda identity, raw: observed.append((identity, raw)))
            callbacks.append(dict(observed))
            self.assertEqual(len(observed), len(callbacks[-1]))
            return result
        initial = run()
        reads.clear()
        repeated = run()
        self.assertTrue(reads)
        self.assertEqual(initial, repeated)
        self.assertEqual(callbacks[0], callbacks[1])
        self.assertGreater(cache.stats()["hits"], 0)
        with self.assertRaisesRegex(ValueError, "missing"):
            check_graph(root, lookup=lambda identity: openings[identity],
                        parent_snapshot=lambda identity, height: None, state_cache=cache)
        parent.payouts[0].nValue -= 1
        with self.assertRaisesRegex(ValueError, "authorization"):
            check_graph(root, lookup=lambda identity: openings[identity], parent_snapshot=native, state_cache=cache)

    def test_distinct_jobs_reuse_only_exact_shared_prefix_state(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=3, inherited_proofs=5)
        values = list(openings.values())
        cache = CompactStateCache()
        with patch.object(codec, "apply_tides_state", wraps=codec.apply_tides_state) as apply:
            first = codec.materialize_compact_state(values[0], parent_snapshot=ancestor, state_cache=cache)
            self.assertEqual(apply.call_count, 2)
            second = codec.materialize_compact_state(values[1], parent_snapshot=ancestor, state_cache=cache)
            self.assertEqual(apply.call_count, 3)  # New target, shared exact parent prefix.
            again = codec.materialize_compact_state(values[1], parent_snapshot=ancestor, state_cache=cache)
            self.assertEqual(apply.call_count, 3)
        self.assertEqual(second, again)
        self.assertEqual(first.post_state, second.post_state)
        self.assertNotEqual(first.hash, second.hash)

    def test_failed_target_never_populates_prefix_or_full_cache(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=1, inherited_proofs=2)
        value = next(iter(openings.values()))
        cache = CompactStateCache()
        invalid = replace(value, history_head=value.history_head ^ 1)
        # Re-sign the changed wire head, so failure occurs after prefix replay.
        from test_hash_snapshot import SECRET
        invalid = replace(invalid, owner_signature=codec.sign_schnorr(SECRET, invalid.owner_message))
        with self.assertRaisesRegex(ValueError, "history head"):
            codec.materialize_compact_state(invalid, parent_snapshot=ancestor, state_cache=cache)
        self.assertEqual(cache.stats()["entries"], 0)
        codec.materialize_compact_state(value, parent_snapshot=ancestor, state_cache=cache)
        self.assertGreater(cache.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
