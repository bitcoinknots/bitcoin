#!/usr/bin/env python3
"""Signature reuse preserves exact inputs, evidence reads and accounting checks."""
from dataclasses import replace
import unittest
from unittest.mock import patch

import hash_signature_cache
import hash_snapshot as codec
from hash_gate_batch import BatchLimit, check_graph
from hash_signature_cache import SignatureVerifyCache
from test_framework.key import compute_xonly_pubkey, sign_schnorr
from test_hash_graph_latency import graph_fixture
from test_hash_snapshot import SECRET


class SignatureCacheTests(unittest.TestCase):
    def inputs(self, number=1):
        message = number.to_bytes(32, "big")
        return compute_xonly_pubkey(SECRET)[0], sign_schnorr(SECRET, message), message

    def test_exact_public_inputs_and_failures_are_not_cached(self):
        cache = SignatureVerifyCache()
        public, signature, message = self.inputs()
        with patch.object(hash_signature_cache, "verify_schnorr", wraps=hash_signature_cache.verify_schnorr) as verify:
            self.assertTrue(cache.verify(public, signature, message))
            self.assertTrue(cache.verify(bytes(bytearray(public)), bytes(bytearray(signature)), bytes(bytearray(message))))
            self.assertEqual(verify.call_count, 1)
            other_key = compute_xonly_pubkey((int.from_bytes(SECRET, "big") + 1).to_bytes(32, "big"))[0]
            for changed in ((other_key, signature, message),
                            (public, bytes([signature[0] ^ 1]) + signature[1:], message),
                            (public, signature, bytes([message[0] ^ 1]) + message[1:])):
                self.assertFalse(cache.verify(*changed))
                self.assertFalse(cache.verify(*changed))
            self.assertEqual(verify.call_count, 7)
        self.assertEqual(cache.stats()["entries"], 1)
        self.assertEqual(cache.stats()["failures"], 6)
        self.assertTrue(cache.verify(*self.inputs(2)))
        self.assertEqual(cache.stats()["entries"], 2)

    def test_fixed_input_bounds_and_memory_eviction(self):
        cache = SignatureVerifyCache(max_entries=2)
        first, second, third = [self.inputs(number) for number in (1, 2, 3)]
        self.assertTrue(cache.verify(*first))
        charge = cache.stats()["bytes"]
        self.assertGreater(charge, sum(map(len, first)))
        cache.verify(*second)
        cache.verify(*first)
        cache.verify(*third)
        self.assertEqual(cache.stats()["entries"], 2)
        misses = cache.stats()["misses"]
        cache.verify(*second)
        self.assertEqual(cache.stats()["misses"], misses + 1)
        for options in ({"max_bytes": charge - 1}, {"max_entries": 0}):
            tiny = SignatureVerifyCache(**options)
            self.assertTrue(tiny.verify(*first))
            self.assertEqual(tiny.stats()["entries"], 0)
            self.assertEqual(tiny.stats()["oversized"], 1)
        byte_bound = SignatureVerifyCache(max_bytes=charge)
        for inputs in (first, second, third):
            self.assertTrue(byte_bound.verify(*inputs))
            self.assertEqual(byte_bound.stats()["bytes"], charge)
            self.assertEqual(byte_bound.stats()["entries"], 1)
        for position in range(3):
            for invalid in (bytearray(first[position]), b"", first[position] + b"\0"):
                values = list(first)
                values[position] = invalid
                with self.assertRaises(ValueError):
                    cache.verify(*values)
        for options in ({"max_bytes": -1}, {"max_entries": True}, {"max_bytes": 1.5}):
            with self.assertRaises(ValueError):
                SignatureVerifyCache(**options)
        cache.clear()
        self.assertTrue(all(value == 0 for value in cache.stats().values()))

    def test_graph_signature_hits_still_read_charge_and_replay_state(self):
        root, openings, parent, ancestor = graph_fixture(alternatives=8, inherited_proofs=3)
        cache, reads, observed = SignatureVerifyCache(), [], []
        def lookup(identity):
            reads.append(identity)
            return openings[identity]
        def run():
            return check_graph(root, lookup=lookup, parent_snapshot=ancestor,
                signature_cache=cache, on_snapshot=lambda identity, raw: observed.append((identity, raw)))
        with patch.object(hash_signature_cache, "verify_schnorr", wraps=hash_signature_cache.verify_schnorr) as verify:
            with patch.object(codec, "apply_tides_state", wraps=codec.apply_tides_state) as apply:
                first = run()
                signature_calls, state_calls = verify.call_count, apply.call_count
                first_reads, first_observed = list(reads), list(observed)
                reads.clear()
                observed.clear()
                self.assertEqual(run(), first)
                self.assertEqual(verify.call_count, signature_calls)
                self.assertGreater(apply.call_count, state_calls)
        self.assertEqual(reads, first_reads)
        self.assertEqual(observed, first_observed)
        self.assertGreater(cache.stats()["hits"], 0)
        with patch("hash_gate_batch.MAX_DEPENDENCY_BYTES", 1), self.assertRaises(BatchLimit):
            run()
        with self.assertRaisesRegex(ValueError, "missing"):
            check_graph(root, lookup=lookup, parent_snapshot=lambda *args: None, signature_cache=cache)
        parent.payouts[0].nValue -= 1
        with self.assertRaisesRegex(ValueError, "authorization"):
            run()

    def test_valid_signature_does_not_cache_an_invalid_history_verdict(self):
        unused, openings, unused_parent, ancestor = graph_fixture(alternatives=1, inherited_proofs=2)
        value = next(iter(openings.values()))
        invalid = replace(value, history_head=value.history_head ^ 1)
        invalid = replace(invalid, owner_signature=sign_schnorr(SECRET, invalid.owner_message))
        cache = SignatureVerifyCache()
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "history head"):
                codec.materialize_compact_state(invalid, parent_snapshot=ancestor, signature_cache=cache)
        self.assertGreater(cache.stats()["hits"], 0)
        self.assertEqual(codec.materialize_compact_state(value, parent_snapshot=ancestor, signature_cache=cache).history_head,
                         value.history_head)


if __name__ == "__main__":
    unittest.main()
