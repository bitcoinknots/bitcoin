#!/usr/bin/env python3
"""Streaming startup keeps lifetime, body, origin and rollback authentication."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hash_gate_archive
import hash_gate_startup
from hash_mining_gate import HashMiningGate, PROOF, SNAPSHOT, TEMPLATE
from hash_snapshot import solve_share
import native_archive
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT


class HashGateStartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hash-gate-startup-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.rpc = FakeRPC()
        self.origin, self.opening = fixture()
        self.options = dict(rpc=self.rpc, pool=3, public_key=self.opening.envelope.public_key, payout_script=SCRIPT)
        self.gate = HashMiningGate(self.directory / "source.sqlite", **self.options)
        self.rpc.gate = self.gate
        self.addCleanup(self.gate.close)
        self.gate.register_snapshot(self.opening.serialize())
        self.gate.register_template(self.origin.serialize())
        self.nonce = 0

    def proof(self):
        proof = solve_share(self.origin, self.opening, start_nonce=self.nonce)
        self.nonce = proof.header.nNonce + 1
        self.assertTrue(self.gate.receive(proof))
        return proof

    def test_segments_stream_once_and_proof_bodies_are_not_reread(self):
        proofs = [self.proof() for _ in range(5)]
        first = self.gate.rotate_archive(self.directory / "first.spharc")
        proofs.extend(self.proof() for _ in range(5))
        self.gate.rotate_archive(self.directory / "second.spharc")
        proofs.append(self.proof())
        head = self.gate.archive_head()
        with patch.object(self.gate, "_read", wraps=self.gate._read) as reads, \
                patch.object(hash_gate_archive, "records", wraps=hash_gate_archive.records) as streams:
            self.gate._verify_store(first)
        self.assertEqual(streams.call_count, 2)
        self.assertFalse(any(call.args[0] == PROOF for call in reads.call_args_list))
        self.assertEqual(len(reads.call_args_list), 2)
        self.assertEqual(self.gate.archive_head(), head)
        self.gate.close()
        self.gate = HashMiningGate(self.directory / "source.sqlite", **self.options)
        self.rpc.gate = self.gate
        self.addCleanup(self.gate.close)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(len(self.gate.eligible_shares()), len(proofs))

    def test_database_scalar_binding_and_offsets_cannot_reuse_valid_segment(self):
        self.proof()
        self.gate.rotate_archive(self.directory / "cold.spharc")
        head = self.gate.archive_head()
        for column, replacement in (("offset", 13), ("digest", "01" * 32), ("root", "02" * 32),
                ("revision", 5), ("height", 2), ("parent", "03" * 32), ("segment", 2),
                ("size", 0), ("data", b"unexpected")):
            previous = self.gate.db.execute(f"SELECT {column} FROM journal WHERE sequence=1").fetchone()[0]
            with self.gate.db:
                self.gate.db.execute(f"UPDATE journal SET {column}=? WHERE sequence=1", (replacement,))
            try:
                with self.subTest(column=column), self.assertRaises(ValueError):
                    self.gate._verify_store(head)
            finally:
                with self.gate.db:
                    self.gate.db.execute(f"UPDATE journal SET {column}=? WHERE sequence=1", (previous,))
            self.assertEqual(hash_gate_archive.read_head(self.gate.head_path), head)
        self.gate._verify_store(head)

    def test_cold_bytes_are_rechecked_without_timestamp_or_cached_verdict(self):
        self.proof()
        cold = self.directory / "cold.spharc"
        head = self.gate.rotate_archive(cold)
        raw = cold.read_bytes()
        for changed in (raw[:-1] + bytes([raw[-1] ^ 1]), raw[:-1], raw + b"\0"):
            cold.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.gate._verify_store(head)
        cold.write_bytes(raw)
        self.gate._verify_store(head)
        cold.unlink()
        with self.assertRaisesRegex(ValueError, "cold archive data is unavailable"):
            self.gate._verify_store(head)
        self.assertEqual(hash_gate_archive.read_head(self.gate.head_path), head)

    def test_protected_high_water_and_missing_segment_rows_are_preserved(self):
        self.proof()
        first = self.gate.rotate_archive(self.directory / "first.spharc")
        self.proof()
        head = self.gate.rotate_archive(self.directory / "second.spharc")
        self.gate._verify_store(first)
        for prefix in (dict(first, root="01" * 32), dict(head, events=head["events"] + 1),
                       dict(head, binding="02" * 32)):
            with self.assertRaises(ValueError):
                self.gate._verify_store(prefix)
        saved = self.gate.db.execute("SELECT * FROM segments WHERE id=1").fetchone()
        with self.gate.db:
            self.gate.db.execute("DELETE FROM segments WHERE id=1")
        with self.assertRaisesRegex(ValueError, "complete journal prefix"):
            self.gate._verify_store(head)
        with self.gate.db:
            self.gate.db.execute("INSERT INTO segments VALUES (?,?,?,?)", saved)
        self.gate._verify_store(head)

    def test_hash_chain_alone_does_not_establish_exact_proof_origin(self):
        proof = solve_share(self.origin, self.opening)
        bad = replace(proof, owner_signature=bytes(64))
        # Deliberate private storage corruption with an internally valid event
        # chain: startup must still check the complete origin binding.
        self.gate._persist([(PROOF, bad.serialize())])
        with self.assertRaisesRegex(ValueError, "proof does not bind"):
            self.gate._verify_store(self.gate.archive_head())

    def test_warm_origin_facts_still_compare_each_proof_signature_and_envelope(self):
        proof = self.proof()
        for bad in (replace(proof, owner_signature=bytes(64)),
                    replace(proof, envelope=replace(proof.envelope, pool=4))):
            facts = hash_gate_startup._OriginFacts()
            with patch.object(self.gate, "_read", wraps=self.gate._read) as reads:
                facts.require(self.gate, proof)
                with self.assertRaisesRegex(ValueError, "proof does not bind"):
                    facts.require(self.gate, bad)
            self.assertEqual(reads.call_count, 2)

    def test_origin_facts_are_bounded_and_eviction_reauthenticates_dependencies(self):
        first = self.proof()
        origin, opening = fixture(ntime=1700000002)
        self.gate.register_snapshot(opening.serialize())
        self.gate.register_template(origin.serialize())
        second = solve_share(origin, opening)
        facts = hash_gate_startup._OriginFacts(max_entries=1)
        with patch.object(self.gate, "_read", wraps=self.gate._read) as reads:
            for proof in (first, first, second, first):
                facts.require(self.gate, proof)
                self.assertEqual(len(facts.entries), 1)
                self.assertLessEqual(facts.bytes, facts.max_bytes)
        self.assertEqual(reads.call_count, 6)
        for limits in ({"max_entries": 0}, {"max_bytes": 1}):
            facts = hash_gate_startup._OriginFacts(**limits)
            with patch.object(self.gate, "_read", wraps=self.gate._read) as reads:
                facts.require(self.gate, first)
                facts.require(self.gate, first)
            self.assertEqual(reads.call_count, 4)
            self.assertEqual((len(facts.entries), facts.bytes), (0, 0))

    def test_origin_facts_never_survive_a_full_pass_or_hide_changed_origin(self):
        self.proof()
        head = self.gate.archive_head()
        self.gate._verify_store(head)
        with patch.object(self.gate, "_read", wraps=self.gate._read) as reads:
            self.gate._verify_store(head)
        self.assertEqual(reads.call_count, 2)
        raw = self.origin.serialize()
        with self.gate.db:
            self.gate.db.execute("UPDATE journal SET data=? WHERE kind=?",
                (raw[:-1] + bytes([raw[-1] ^ 1]), TEMPLATE))
        with self.assertRaises(ValueError):
            self.gate._verify_store(head)
        self.assertEqual(hash_gate_archive.read_head(self.gate.head_path), head)

    def test_proof_can_precede_origin_but_entire_later_origin_is_checked(self):
        gate = HashMiningGate(self.directory / "late.sqlite", **self.options)
        self.addCleanup(gate.close)
        proof = solve_share(self.origin, self.opening)
        gate._persist([(PROOF, proof.serialize()), (SNAPSHOT, self.opening.serialize()),
                      (TEMPLATE, self.origin.serialize())])
        head = gate.archive_head()
        with patch.object(gate, "_next", wraps=gate._next) as events:
            gate._verify_store(head)
        self.assertEqual(events.call_count, 3)
        with gate.db:
            gate.db.execute("UPDATE journal SET root=? WHERE kind=?", ("01" * 32, TEMPLATE))
        with self.assertRaisesRegex(ValueError, "missing or corrupt"):
            gate._verify_store(head)
        self.assertEqual(hash_gate_archive.read_head(gate.head_path), head)

    def test_rollover_performs_one_full_verification_and_preserves_head(self):
        self.proof()
        head = self.gate.archive_head()
        with patch.object(self.gate, "_verify_store", wraps=self.gate._verify_store) as checks:
            self.gate.rotate_archive(self.directory / "cold.spharc")
        self.assertEqual(checks.call_count, 1)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.gate.resident_bytes(), 0)
        with patch.object(self.gate, "_verify_store", wraps=self.gate._verify_store) as checks:
            self.gate.export_archive(self.directory / "export.spharc")
        self.assertEqual(checks.call_count, 1)

    def test_mutation_during_export_does_not_publish_or_discard_resident_bytes(self):
        self.proof()
        head, resident = self.gate.archive_head(), self.gate.resident_bytes()
        original = self.gate._read
        reads = 0

        def changed(kind, identity):
            nonlocal reads
            raw = original(kind, identity)
            reads += 1
            # Startup streams bodies directly and its single proof checks two
            # origins. This modifies the next exported body after verification.
            return raw[:-1] + bytes([raw[-1] ^ 1]) if reads == 3 else raw

        path = self.directory / "refused.spharc"
        with patch.object(self.gate, "_read", side_effect=changed), self.assertRaises(ValueError):
            self.gate.rotate_archive(path)
        self.assertFalse(path.exists())
        self.assertEqual(self.gate.resident_bytes(), resident)
        self.assertEqual(self.gate.archive_head(), head)
        self.assertEqual(self.gate.db.execute("SELECT count(*) FROM segments").fetchone()[0], 0)
        self.gate._verify_store(head)


if __name__ == "__main__":
    unittest.main()
