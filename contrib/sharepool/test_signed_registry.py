#!/usr/bin/env python3
"""Authorization, immutability, replay, and canonical encoding registry tests."""

from dataclasses import FrozenInstanceError, replace
import copy
import unittest

from signed_registry import (MAX_ENTRIES, MAX_SCRIPT_BYTES, NETWORK_ID, RegistryChange,
                             RegistryEntry, RegistrySnapshot, apply_change, empty_registry,
                             miner_id_for_key, private_key, public_key, register, sign,
                             update, verify)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.genesis = empty_registry()
        self.alice = private_key(1)
        self.bob = private_key(2)
        self.carol = private_key(3)
        self.alice_change = register(self.genesis, self.alice, b"alice-tag", b"\x51")
        self.first = apply_change(self.genesis, self.alice_change)
        self.alice_id = self.alice_change.entry.miner_id

    def test_real_ecdsa_authentication_and_malformed_inputs(self):
        payload = b"fixture payload"
        signature = sign(self.alice, payload)
        self.assertTrue(verify(public_key(self.alice), payload, signature))
        self.assertEqual(signature, sign(self.alice, payload))
        self.assertFalse(verify(public_key(self.bob), payload, signature))
        self.assertFalse(verify(public_key(self.alice), payload + b"!", signature))
        for malformed in (b"", b"\x30", b"\x30\x00", bytes(72), bytes(73), "not bytes"):
            self.assertFalse(verify(public_key(self.alice), payload, malformed))
        for malformed in (b"", bytes(33), bytes(65), b"\x02" + bytes([255]) * 32):
            self.assertFalse(verify(malformed, payload, signature))

    def test_registration_requires_identity_key_and_possession(self):
        self.assertEqual(self.alice_id, miner_id_for_key(public_key(self.alice)))
        self.assertEqual(self.first.entry(self.alice_id).tag, b"alice-tag")
        bad_signature = replace(self.alice_change,
                                new_signature=sign(self.bob, self.alice_change.payload))
        with self.assertRaisesRegex(ValueError, "new signing key"):
            apply_change(self.genesis, bad_signature)
        forged = replace(self.alice_change, entry=replace(self.alice_change.entry, miner_id=bytes(32)))
        forged = replace(forged, new_signature=sign(self.alice, forged.payload))
        with self.assertRaisesRegex(ValueError, "identity"):
            apply_change(self.genesis, forged)

    def test_update_requires_both_keys_and_preserves_old_payout_version(self):
        change = update(self.first, self.alice_id, self.alice, self.bob, b"\x52")
        next_version = apply_change(self.first, change)
        self.assertEqual(next_version.entry(self.alice_id).signing_key, public_key(self.bob))
        self.assertEqual(next_version.entry(self.alice_id).tag, b"alice-tag")
        self.assertEqual(next_version.entry(self.alice_id).payout_script, b"\x52")
        self.assertEqual(self.first.entry(self.alice_id).payout_script, b"\x51")
        self.assertEqual(next_version.previous_root, self.first.root)
        for field in ("old_signature", "new_signature"):
            with self.subTest(field=field):
                bad = replace(change, **{field: sign(self.carol, change.payload)})
                with self.assertRaisesRegex(ValueError, "signing key"):
                    apply_change(self.first, bad)
        wrong_old = update(self.first, self.alice_id, self.carol, self.bob, b"\x52")
        with self.assertRaisesRegex(ValueError, "previous signing key"):
            apply_change(self.first, wrong_old)

    def test_payout_update_without_rotation_and_removed_key_cannot_update(self):
        change = update(self.first, self.alice_id, self.alice, self.alice, b"\x52")
        second = apply_change(self.first, change)
        self.assertEqual(second.entry(self.alice_id).signing_key, public_key(self.alice))
        third = apply_change(second, update(second, self.alice_id, self.alice, self.bob, b"\x53"))
        with self.assertRaisesRegex(ValueError, "previous signing key"):
            apply_change(third, update(third, self.alice_id, self.alice, self.carol, b"\x54"))

    def test_replay_and_forked_predecessor_rejected(self):
        with self.assertRaisesRegex(ValueError, "predecessor"):
            apply_change(self.first, self.alice_change)
        change = update(self.first, self.alice_id, self.alice, self.bob, b"\x52")
        competing = apply_change(self.first, update(self.first, self.alice_id, self.alice,
                                                    self.carol, b"\x53"))
        with self.assertRaisesRegex(ValueError, "predecessor"):
            apply_change(competing, change)
        for mutated in (replace(change, previous_root=bytes(32)),
                        replace(change, sequence=change.sequence + 1),
                        replace(change, pool_id=b"other-pool"),
                        replace(change, network_id=b"other-network")):
            with self.assertRaisesRegex(ValueError, "predecessor"):
                apply_change(self.first, mutated)

    def test_context_is_signed_not_only_checked_at_apply(self):
        other = empty_registry(pool_id=b"other-pool")
        retargeted = replace(self.alice_change, pool_id=other.pool_id, previous_root=other.root)
        with self.assertRaisesRegex(ValueError, "new signing key"):
            apply_change(other, retargeted)
        mutated = replace(self.alice_change,
                          entry=replace(self.alice_change.entry, payout_script=b"\x52"))
        with self.assertRaisesRegex(ValueError, "new signing key"):
            apply_change(self.genesis, mutated)

    def test_duplicate_tags_keys_and_miner_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate registry tag"):
            apply_change(self.first, register(self.first, self.bob, b"alice-tag", b"\x52"))
        with self.assertRaisesRegex(ValueError, "duplicate registry miner_id"):
            apply_change(self.first, register(self.first, self.alice, b"new-tag", b"\x52"))
        second = apply_change(self.first, register(self.first, self.bob, b"bob-tag", b"\x52"))
        with self.assertRaisesRegex(ValueError, "duplicate registry signing_key"):
            apply_change(second, update(second, self.alice_id, self.alice, self.bob, b"\x53"))

    def test_update_cannot_change_tag_or_impersonate_other_owner(self):
        change = update(self.first, self.alice_id, self.alice, self.bob, b"\x52")
        retagged = replace(change, entry=replace(change.entry, tag=b"other-tag"))
        retagged = replace(retagged, old_signature=sign(self.alice, retagged.payload),
                           new_signature=sign(self.bob, retagged.payload))
        with self.assertRaisesRegex(ValueError, "tag cannot change"):
            apply_change(self.first, retagged)
        second = apply_change(self.first, register(self.first, self.carol, b"carol-tag", b"\x53"))
        carol_id = miner_id_for_key(public_key(self.carol))
        forged = update(second, carol_id, self.alice, self.bob, b"\x54")
        with self.assertRaisesRegex(ValueError, "previous signing key"):
            apply_change(second, forged)

    def test_registry_and_change_serialization_roundtrip(self):
        second = apply_change(self.first, register(self.first, self.bob, b"bob-tag", b"\x52"))
        self.assertEqual(second, RegistrySnapshot.from_object(second.to_object()))
        self.assertEqual(self.alice_change, RegistryChange.from_object(self.alice_change.to_object()))
        reordered = replace(second, entries=tuple(reversed(second.entries)))
        self.assertEqual(second.root, reordered.root)
        self.assertEqual(second.to_object(), reordered.to_object())

    def test_wire_objects_reject_unknown_fields_and_noncanonical_encodings(self):
        second = apply_change(self.first, register(self.first, self.bob, b"bob-tag", b"\x52"))
        variants = []
        obj = second.to_object(); obj["extra"] = 1; variants.append(obj)
        obj = second.to_object(); obj["sequence"] = True; variants.append(obj)
        obj = second.to_object(); obj["previous_root"] = obj["previous_root"].upper(); variants.append(obj)
        obj = second.to_object(); obj["entries"].reverse(); variants.append(obj)
        obj = second.to_object(); obj["entries"][0]["tag"] += " "; variants.append(obj)
        obj = second.to_object(); obj["entries"][0]["payout_script"] = "5"; variants.append(obj)
        for obj in variants:
            with self.subTest(obj=obj):
                with self.assertRaises(ValueError):
                    RegistrySnapshot.from_object(obj)
        for key, value in (("type", "other-change"), ("sequence", True),
                           ("old_signature", "00 "), ("operation", "remove")):
            obj = self.alice_change.to_object(); obj[key] = value
            with self.assertRaises(ValueError):
                RegistryChange.from_object(obj)

    def test_values_are_immutable_and_mutable_byte_inputs_are_copied(self):
        raw_tag, raw_script, raw_pool, raw_root = bytearray(b"tag"), bytearray(b"\x51"), bytearray(b"pool-A"), bytearray(32)
        entry = RegistryEntry(self.alice_id, raw_tag, public_key(self.alice), raw_script)
        source_entries = [entry]
        snapshot = RegistrySnapshot(1, raw_root, source_entries, pool_id=raw_pool)
        root = snapshot.root
        raw_tag[0] = 0; raw_script[0] = 0; raw_pool[0] = 0; raw_root[0] = 1
        source_entries.clear()
        self.assertEqual(snapshot.root, root)
        self.assertEqual(snapshot.entries[0].tag, b"tag")
        with self.assertRaises(FrozenInstanceError):
            snapshot.sequence = 99
        change_obj = self.alice_change.to_object()
        original = copy.deepcopy(change_obj)
        decoded = RegistryChange.from_object(change_obj)
        change_obj["entry"]["tag"] = "00"
        self.assertEqual(decoded.to_object(), original)

    def test_bounded_fields_and_snapshot_count(self):
        for sequence in (-1, True, 1.0, 1 << 63):
            with self.assertRaises(ValueError):
                replace(self.first, sequence=sequence)
        for seed in (-1, True, 1.0, 1 << 256):
            with self.assertRaises(ValueError):
                private_key(seed)
        for patch in ({"tag": b""}, {"tag": bytes(65)}, {"miner_id": bytes(31)},
                      {"payout_script": b""}, {"payout_script": bytes(MAX_SCRIPT_BYTES + 1)},
                      {"signing_key": bytes(33)}):
            with self.assertRaises(ValueError):
                replace(self.alice_change.entry, **patch)
        with self.assertRaisesRegex(ValueError, "too many"):
            replace(self.first, entries=(self.alice_change.entry for _ in range(MAX_ENTRIES + 1)))
        with self.assertRaises(ValueError):
            RegistrySnapshot.from_object({**self.first.to_object(), "entries": [{}] * (MAX_ENTRIES + 1)})

    def test_aggregate_registry_bytes_are_bounded(self):
        entries = []
        for index in range(54):
            public = public_key(private_key(100 + index))
            entries.append(RegistryEntry(miner_id_for_key(public), f"tag-{index}".encode(),
                                         public, bytes(MAX_SCRIPT_BYTES)))
        with self.assertRaisesRegex(ValueError, "serialization exceeds size limit"):
            RegistrySnapshot(1, self.genesis.root, entries)

    def test_signed_conflicting_updates_do_not_select_canonical_history(self):
        a = apply_change(self.first, update(self.first, self.alice_id, self.alice, self.bob, b"\x52"))
        b = apply_change(self.first, update(self.first, self.alice_id, self.alice, self.carol, b"\x53"))
        self.assertEqual(a.sequence, b.sequence)
        self.assertEqual(a.previous_root, b.previous_root)
        self.assertNotEqual(a.root, b.root)
        self.assertNotEqual(a.entry(self.alice_id).payout_script, b.entry(self.alice_id).payout_script)


if __name__ == "__main__":
    unittest.main()
