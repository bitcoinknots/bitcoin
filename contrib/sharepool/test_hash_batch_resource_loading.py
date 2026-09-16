#!/usr/bin/env python3
"""Bounded source loading preserves the deterministic acknowledged prefix.

Origins have real template commitments, signatures and solved regtest shares.
The RPC double covers gate behavior; native UTXO/script validation is separate
functional coverage. Large transactions below are canonical encoding fixtures.
"""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hash_gate_batch
import hash_mining_gate
from hash_mining_gate import HashMiningGate, TEMPLATE
from hash_snapshot import CompactTemplateRecord, TemplateRecord, solve_share, share_target
from native_enforcement import compact_size, verify_schnorr
from test_hash_mining_gate import FakeRPC
from test_hash_snapshot import fixture, SCRIPT
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_RETURN


class HashBatchResourceLoadingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hash-batch-loading-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.serial = 0
        self.sources = self.make_sources()
        self.gate = self.open_gate(self.sources)

    def make_sources(self, *, large_transactions=False, shared=True):
        sources = []
        for index in range(6):
            transactions = []
            if large_transactions:
                transaction = CTransaction()
                transaction.vin = [CTxIn(COutPoint(1 if shared else index + 1, 0))]
                transaction.vout = [CTxOut(0, CScript([OP_RETURN, bytes([1 if shared else index + 1]) * 8192]))]
                transaction.rehash()
                transactions.append(transaction)
            block, opening = fixture(ntime=1700000001 + index, transactions=transactions)
            self.assertTrue(verify_schnorr(opening.envelope.public_key, opening.owner_signature, opening.owner_message))
            record = CompactTemplateRecord.from_record(TemplateRecord.from_block(block))
            proof = solve_share(block, opening)
            self.assertLessEqual(proof.header.rehash(), share_target(proof.header.nBits, proof.envelope.version))
            sources.append((block, opening, record, proof))
        self.assertEqual(len({record.template_id for _, _, record, _ in sources}), 6)
        self.assertEqual(len({proof.proof_id for _, _, _, proof in sources}), 6)
        return sorted(sources, key=lambda source: source[3].proof_id)

    def open_gate(self, sources, *, budget=hash_mining_gate.MAX_SNAPSHOT_BYTES):
        rpc = FakeRPC()
        self.serial += 1
        gate = HashMiningGate(self.directory / f"gate-{self.serial}.sqlite", rpc=rpc, pool=3,
            public_key=sources[0][1].envelope.public_key, payout_script=SCRIPT, snapshot_budget=budget)
        rpc.gate = gate
        self.addCleanup(gate.close)
        for block, opening, _, _ in sources:
            gate.register_snapshot(opening.serialize())
            gate.register_template(block.serialize())
        # V4's deterministic order is numeric proof ID, independent of receipt
        # arrival. Reverse arrival makes a wrong dispatch-order prefix visible.
        for _, _, _, proof in reversed(sources):
            self.assertTrue(gate.receive(proof))
        return gate

    def assert_prefix(self, gate, sources, selected, *, forbidden_from, bounds=()):
        head = gate.archive_head()
        forbidden = {f"{record.template_id:064x}" for _, _, record, _ in sources[forbidden_from:]}
        original = gate._evidence
        reads = []

        def evidence(kind, identity, staged=None):
            if kind == TEMPLATE:
                self.assertNotIn(identity, forbidden, "source past the first disallowed record was materialized")
                reads.append(identity)
            return original(kind, identity, staged)

        with ExitStack() as stack:
            for module, field, value in bounds:
                stack.enter_context(patch.object(module, field, value))
            stack.enter_context(patch.object(gate, "_evidence", side_effect=evidence))
            batch = gate.batch_status()
        self.assertEqual(batch["selected_proofs"], tuple(f"{source[3].proof_id:064x}" for source in sources[:selected]))
        self.assertEqual(batch["eligible_count"], len(sources))
        self.assertEqual(batch["deferred_count"], len(sources) - selected)
        self.assertEqual(gate.archive_head(), head)
        return batch, reads

    def test_origin_limit_reserves_new_job_before_loading_another_source(self):
        bounds = ((hash_gate_batch, "MAX_ORIGIN_CHECKS", 4),)
        self.assert_prefix(self.gate, self.sources, 3, forbidden_from=3, bounds=bounds)
        # Raising the allowance by one admits exactly the next acknowledged
        # source, without changing order or deleting any deferred receipt.
        bounds = ((hash_gate_batch, "MAX_ORIGIN_CHECKS", 5),)
        self.assert_prefix(self.gate, self.sources, 4, forbidden_from=4, bounds=bounds)

    def test_expanded_byte_limit_stops_after_the_first_oversized_source(self):
        limit = sum(source[2].expanded_bytes for source in self.sources[:2])
        self.assert_prefix(self.gate, self.sources, 2, forbidden_from=3,
            bounds=((hash_mining_gate, "MAX_EXPANDED_TEMPLATE_BYTES", limit),))

    def test_reference_limit_is_charged_per_template_even_when_transactions_match(self):
        limit = sum(len(source[2].transactions) for source in self.sources[:2])
        self.assert_prefix(self.gate, self.sources, 2, forbidden_from=3,
            bounds=((hash_mining_gate, "MAX_TEMPLATE_TX_REFERENCES", limit),))

    def test_rejected_full_trial_does_not_cache_origin_availability_for_retry(self):
        first = f"{self.sources[0][2].template_id:064x}"
        seen, original = False, self.gate._evidence
        head = self.gate.archive_head()

        def evidence(kind, identity, staged=None):
            nonlocal seen
            if kind == TEMPLATE and identity == first:
                if seen:
                    raise ValueError("origin is unavailable after rejected full trial")
                seen = True
            return original(kind, identity, staged)

        with patch.object(hash_gate_batch, "MAX_ORIGIN_CHECKS", 4), \
                patch.object(self.gate, "_evidence", side_effect=evidence), \
                self.assertRaisesRegex(ValueError, "origin is unavailable"):
            self.gate.batch_status()
        self.assertEqual(self.gate.archive_head(), head)

    def test_shared_transaction_wire_bytes_are_charged_once(self):
        sources = self.make_sources(large_transactions=True)
        reference = self.open_gate(sources)
        budget = reference.batch_status()["resources"]["snapshot_bytes"]
        unique = {transaction.wtxid: transaction.raw for _, _, record, _ in sources for transaction in record.transactions}
        actual_transaction_bytes = sum(len(compact_size(len(raw))) + len(raw) for raw in unique.values())
        repeated_transaction_bytes = sum(len(compact_size(len(transaction.raw))) + len(transaction.raw)
            for _, _, record, _ in sources for transaction in record.transactions)
        self.assertLess(actual_transaction_bytes, budget)
        self.assertGreater(repeated_transaction_bytes, budget)
        gate = self.open_gate(sources, budget=budget)
        batch, _ = self.assert_prefix(gate, sources, 6, forbidden_from=6)
        self.assertEqual(batch["resources"]["snapshot_bytes"], budget)

    def test_unique_transaction_wire_limit_does_not_load_the_rest_of_the_queue(self):
        sources = self.make_sources(large_transactions=True, shared=False)
        prefix_gate = self.open_gate(sources[:2])
        budget = prefix_gate.batch_status()["resources"]["snapshot_bytes"]
        first_three = {transaction.wtxid: transaction.raw for _, _, record, _ in sources[:3] for transaction in record.transactions}
        self.assertGreater(sum(len(compact_size(len(raw))) + len(raw) for raw in first_three.values()), budget)
        gate = self.open_gate(sources, budget=budget)
        self.assert_prefix(gate, sources, 2, forbidden_from=3)


if __name__ == "__main__":
    unittest.main()
