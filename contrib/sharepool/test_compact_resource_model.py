#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "functional"))

from compact_resource_model import closure_resources, job_proof_bytes, report, v7_snapshot_resources
from hash_snapshot import EnvelopeV2, Reader, Share, Snapshot, TemplateRecord, rules_hash
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut, ser_uint256


def encoding_fixture(jobs, proofs, recipients, script_bytes=22, disjoint=False):
    prefix = b"\x00\x14" if script_bytes == 22 else b"\x51\x20"
    payouts = tuple(CTxOut(1, prefix + i.to_bytes(script_bytes - 2, "big")) for i in range(recipients))
    envelope = EnvelopeV2(1, rules_hash(7), 4, 5, 6, bytes(32), prefix + bytes(script_bytes - 2), version=7)
    records = []
    blocks = {}
    for index in range(jobs):
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(index + 2 if disjoint else 2, 0))]
        transaction.vout = [CTxOut(1, envelope.payout_script)]
        coinbase = create_coinbase(4)
        coinbase.vin[0].scriptSig = index.to_bytes(4, "little") + bytes(96)
        coinbase.vout = list(payouts)
        block = create_block(5, coinbase, 6, height=4, header_v2=True, txlist=[transaction])
        block.m_mm_rhs = index + 100
        add_witness_commitment(block)
        record = TemplateRecord.from_block(block)
        records.append(record)
        blocks[record.template_id] = block
    records.sort(key=lambda record: ser_uint256(record.template_id))
    shares = []
    for index in range(proofs):
        # Balanced by canonical dictionary/template rank, not by creation order.
        block = blocks[records[index % jobs].template_id]
        header = CBlockHeader(block)
        header.nNonce = index + 1
        shares.append(Share(header.serialize(), envelope, bytes(64)))
    shares.sort(key=lambda share: share.proof_id)
    value = Snapshot(envelope, bytes(64), templates=tuple(records), shares=tuple(shares), payouts=payouts)
    body = len(next(iter(blocks.values())).serialize()) if blocks else 100_000
    return value, dict(proofs=proofs, origins=jobs, recipients=recipients, script_bytes=script_bytes,
                      body_bytes=body, noncoinbase_transactions=1,
                      transaction_sets=jobs if disjoint and jobs else 1)


def wire_job_proof_sections(raw):
    reader = Reader(raw)
    EnvelopeV2.read(reader)
    reader.take(96)
    for _ in range(reader.size(16 * 1024 * 1024)):
        reader.variable(16 * 1024 * 1024)
    for _ in range(reader.size(16 * 1024 * 1024)):
        reader.take(196)
        for _ in range(reader.size(16 * 1024 * 1024)):
            reader.size(16 * 1024 * 1024)
    begin = reader.stream.tell()
    jobs = reader.size(65536)
    for _ in range(jobs):
        reader.size(65536)
        EnvelopeV2.read(reader)
        reader.take(64)
    job_bytes = reader.stream.tell() - begin
    proofs = reader.size(32768)
    begin = reader.stream.tell()
    widths = {33: 0, 35: 0}
    for _ in range(proofs):
        start = reader.stream.tell()
        reader.size(65536)
        reader.take(32)
        widths[reader.stream.tell() - start] += 1
    return job_bytes, reader.stream.tell() - begin, widths


class CompactResourceModelTests(unittest.TestCase):
    def test_empty_opening_exact_wire_across_recipient_compactsize_boundaries(self):
        for script_bytes in (22, 34):
            for count in (0, 1, 252, 253):
                snapshot, options = encoding_fixture(0, 0, count, script_bytes)
                predicted = v7_snapshot_resources(**options, recent_proofs=90000, recent_origins=999)
                self.assertEqual(predicted["bytes"]["snapshot_lower"], len(snapshot.serialize()))
                self.assertEqual(predicted["bytes"]["snapshot_upper"], len(snapshot.serialize()))
                self.assertEqual(predicted["bytes"]["recent_state"], 0)
                self.assertEqual(predicted["bytes"]["certificates_with_count"], 0)

    def test_real_shared_disjoint_tables_and_compact_job_boundaries(self):
        for jobs, proofs, recipients, script_bytes, disjoint in (
                (1, 1, 3, 22, False), (2, 5, 253, 34, False),
                (5, 9, 3, 22, True), (253, 506, 3, 22, False),
                (254, 509, 3, 22, False)):
            with self.subTest(jobs=jobs, proofs=proofs):
                snapshot, options = encoding_fixture(jobs, proofs, recipients, script_bytes, disjoint)
                raw = snapshot.serialize()
                predicted = v7_snapshot_resources(**options)
                self.assertLessEqual(predicted["bytes"]["snapshot_lower"], len(raw))
                self.assertGreaterEqual(predicted["bytes"]["snapshot_upper"], len(raw))
                self.assertEqual(Snapshot.deserialize(raw).serialize(), raw)
                jobs_size, proofs_size, widths = wire_job_proof_sections(raw)
                self.assertEqual(predicted["bytes"]["job_table_with_count"], jobs_size)
                self.assertEqual(predicted["bytes"]["proofs"], proofs_size)
                self.assertEqual(predicted["compact_records"]["proof_payload_33_byte_records"], widths[33])
                self.assertEqual(predicted["compact_records"]["proof_payload_35_byte_records"], widths[35])

    def test_repeated_coinbase_outputs_and_expanded_work_are_not_compressed(self):
        settings = dict(proofs=20115, origins=100, recipients=100, recent_proofs=80460, recent_origins=400)
        shared = v7_snapshot_resources(**settings)
        disjoint = v7_snapshot_resources(**settings, transaction_sets=100)
        self.assertEqual(shared["bytes"]["expanded_templates"], disjoint["bytes"]["expanded_templates"])
        self.assertEqual(shared["transaction_references"], disjoint["transaction_references"])
        self.assertEqual(shared["bytes"]["unique_coinbases_raw"], 100 * shared["bytes"]["coinbase_per_origin_raw"])
        larger = v7_snapshot_resources(**(settings | {"recipients": 1000}))
        self.assertGreater(larger["bytes"]["unique_coinbases_raw"], shared["bytes"]["unique_coinbases_raw"])
        self.assertGreater(disjoint["bytes"]["snapshot_lower"], shared["bytes"]["snapshot_upper"])

    def test_cold_closure_charges_prior_cohorts_and_distinct_exact_openings(self):
        root = v7_snapshot_resources(proofs=20115, origins=100, recipients=100)
        opening = v7_snapshot_resources(proofs=0, origins=0, recipients=100)
        graph = closure_resources(root, root, opening)
        self.assertEqual(graph["charged_raw_proof_instances"], 5 * 20115)
        self.assertEqual(graph["closure_upper_bytes"], 5 * root["bytes"]["snapshot_upper"] + 100 * opening["bytes"]["snapshot_upper"])
        self.assertTrue(graph["predicates"]["raw_proof_instances_within_131072"])
        aged = closure_resources(root, root, opening, prior_native_snapshots=7)
        self.assertEqual(aged["charged_raw_proof_instances"], 8 * 20115)
        self.assertFalse(aged["predicates"]["raw_proof_instances_within_131072"])
        repeated = closure_resources(root, root, root, extra_origins=100, lower_bound_only=True)
        self.assertEqual(repeated["charged_raw_proof_instances"], 105 * 20115)
        self.assertFalse(repeated["predicates"]["closure_lower_within_64MiB"])
        self.assertTrue(repeated["lower_bound_only_due_to_omitted_recursive_dependencies"])

    def test_compact_wire_fit_does_not_remove_proof_work_or_recipient_ceiling(self):
        upper = v7_snapshot_resources(proofs=32768, origins=100, recipients=100)
        opening = v7_snapshot_resources(proofs=0, origins=0, recipients=100)
        self.assertTrue(upper["predicates"]["snapshot_upper_bound_within_16MiB"])
        self.assertFalse(closure_resources(upper, upper, opening)["predicates"]["raw_proof_instances_within_131072"])
        burst = v7_snapshot_resources(proofs=92628, origins=100, recipients=100)
        self.assertTrue(burst["predicates"]["snapshot_upper_bound_within_16MiB"])
        self.assertFalse(burst["predicates"]["compact_proofs_within_32768"])
        recipients = v7_snapshot_resources(proofs=0, origins=0, recipients=32246)
        self.assertFalse(recipients["predicates"]["payout_reservation_within_4million_WU"])

    def test_historical_inputs_remain_unchanged_and_comparisons_are_explicit(self):
        path = Path(__file__).with_name("results") / "tides-v6-resource-budget.json"
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        result = report(path)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        self.assertEqual(result["historical_v6_input"]["sha256"], before)
        self.assertEqual(result["native_bits_hex"], "17034219")
        self.assertEqual(result["active_native_shift_unchanged"], 10)
        self.assertEqual(len(result["workloads"]), 28)
        for row in result["workloads"]:
            self.assertFalse(row["production_capacity_or_variance_contract_established"])

    def test_index_boundaries_and_invalid_assumptions(self):
        one = job_proof_bytes(253, 253)
        two = job_proof_bytes(254, 254)
        self.assertEqual(one["proof_payload_bytes"], 253 * 33)
        self.assertEqual(two["proof_payload_bytes"], 253 * 33 + 35)
        self.assertEqual(job_proof_bytes(0, 100)["jobs"], 0)
        for proofs, jobs in ((-1, 1), (1, 0), (True, 1), (1.0, 1)):
            with self.assertRaises(ValueError):
                job_proof_bytes(proofs, jobs)
        with self.assertRaises(ValueError):
            job_proof_bytes(1, 1, jobs=2)
        with self.assertRaises(ValueError):
            job_proof_bytes(65537, 65537)


if __name__ == "__main__":
    unittest.main()
