#!/usr/bin/env python3
"""Conservative v8 wire sizes; synthetic codec jobs are not native verdicts."""
from copy import deepcopy
from dataclasses import replace
import unittest

from hash_admission_accounting import CompactAdmissionAccountant, MetadataCapacity
from hash_admission_budget import AdmissionBudget, AdmissionQuote, AdmissionRefused
from hash_snapshot import CompactTemplateRecord, Share, Snapshot, solve_share
from test_framework.messages import CBlockHeader, CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness, ser_uint256
from test_hash_compact import compact_fixture
from test_hash_snapshot import SCRIPT
from test_hash_variable import variable_fixture


def record(block):
    from hash_snapshot import TemplateRecord
    return CompactTemplateRecord.from_record(TemplateRecord.from_block(block))


def accountant(snapshot, **options):
    return CompactAdmissionAccountant(snapshot, historical_recipient_count=1,
        historical_recipient_bytes=31, **options)


def share(block, opening, nonce=0):
    header = CBlockHeader(block)
    header.nNonce = nonce
    return Share(header.serialize(), opening.envelope, opening.owner_signature)


def settlement(base, records, proofs):
    return replace(base, templates=tuple(sorted(records, key=lambda item: ser_uint256(item.template_id))),
        shares=tuple(sorted(proofs, key=lambda item: item.proof_id)))


class CompactAdmissionAccountingTests(unittest.TestCase):
    def test_empty_and_incremental_shared_job_upper_bound_and_pure_preview(self):
        block, opening = variable_fixture()
        acct = accountant(opening)
        self.assertGreaterEqual(acct.resources.snapshot_bytes, len(opening.serialize()))
        before = acct.stats(), acct.resources, acct.pending_proof_ids
        proof = share(block, opening)
        first = acct.preview_delta(proof, record(block), dependencies=(opening.capture(),), depth=1)
        self.assertEqual((acct.stats(), acct.resources, acct.pending_proof_ids), before)
        actual = settlement(opening, (record(block),), (proof,))
        self.assertGreaterEqual(first.resources.snapshot_bytes, len(actual.serialize()))
        self.assertEqual(first.resources.dependency_bytes-first.resources.snapshot_bytes, len(opening.serialize()))
        acct.commit(first)
        self.assertTrue(acct.contains_proof(proof.proof_id))
        self.assertEqual((acct.proof_count, acct.min_pending_origin_height), (1, 1))
        second = acct.preview_delta(share(block, opening, 1), record(block), dependencies=(opening.capture(),), depth=1)
        self.assertEqual(second.resources.snapshot_bytes-first.resources.snapshot_bytes, 41)
        acct.commit(second)
        self.assertEqual({key: acct.stats()[key] for key in ('templates','transactions','jobs','proofs','recipients','dependencies')},
                         {'templates':1,'transactions':1,'jobs':1,'proofs':2,'recipients':1,'dependencies':1})

    def test_compact_size_proof_and_job_index_boundaries_do_not_enlarge_old_charges(self):
        block, opening = variable_fixture()
        for count in (252, 253):
            # One job, changing the proof vector's CompactSize count.
            proofs = tuple(share(block, opening, nonce) for nonce in range(count))
            value = settlement(opening, (record(block),), proofs)
            acct = accountant(value)
            self.assertGreaterEqual(acct.resources.snapshot_bytes, len(value.serialize()))
            self.assertEqual(acct.proof_count, count)
            # Distinct canonical headers exercise template/job table counts and
            # indexes. Attestations are placeholders for wire sizing only.
            records, proofs = [], []
            for index in range(count):
                other = deepcopy(block)
                other.nTime += index
                records.append(record(other))
                proofs.append(share(other, opening))
            value = settlement(opening, records, proofs)
            acct = accountant(value)
            self.assertGreaterEqual(acct.resources.snapshot_bytes, len(value.serialize()))
            self.assertEqual(acct.stats()['jobs'], count)
            self.assertEqual(acct.stats()['transactions'], 1)

    def test_transaction_count_and_reference_index_compact_size_boundaries(self):
        for count in (252, 253):
            transactions=[]
            for index in range(count-1):
                tx=CTransaction()
                tx.vin=[CTxIn(COutPoint(index+1,0),b'',0xffffffff)]
                tx.vout=[CTxOut(1,b'\x51')]
                tx.rehash()
                transactions.append(tx)
            block,opening=variable_fixture(transactions=transactions)
            value=settlement(opening,(record(block),),(share(block,opening),))
            acct=accountant(value)
            self.assertEqual(acct.stats()['transactions'],count)
            self.assertEqual(acct.resources.template_references,count)
            self.assertGreaterEqual(acct.resources.snapshot_bytes,len(value.serialize()))

    def test_changed_witness_is_distinct_and_same_template_id_cannot_relabel_body(self):
        block,opening=variable_fixture()
        x=deepcopy(block)
        x.vtx[0].wit.vtxinwit=[CTxInWitness()]
        x.vtx[0].wit.vtxinwit[0].scriptWitness.stack=[b'x'*32]
        y=deepcopy(x)
        y.vtx[0].wit.vtxinwit[0].scriptWitness.stack=[b'y'*32]
        a,b=record(x),record(y)
        self.assertEqual(a.template_id,b.template_id)
        acct=accountant(opening)
        acct.commit(acct.preview_delta(share(x,opening),a))
        before=acct.stats(),acct.resources
        with self.assertRaisesRegex(ValueError,'conflicting compact admission templates'):
            acct.preview_delta(share(y,opening,1),b)
        self.assertEqual((acct.stats(),acct.resources),before)
        y.nTime+=1
        delta=acct.preview_delta(share(y,opening),record(y))
        acct.commit(delta)
        self.assertEqual(acct.stats()['transactions'],2)
        self.assertEqual(acct.stats()['origins'],2)

    def test_descriptor_assignment_and_signature_mutations_do_not_reuse_job(self):
        block,opening=variable_fixture(share_work_bits=2)
        acct=accountant(opening)
        proof=share(block,opening)
        acct.commit(acct.preview_delta(proof,record(block)))
        before=acct.stats(),acct.resources
        for changed in (replace(share(block,opening,1),owner_signature=b'x'*64),
                        replace(share(block,opening,1),envelope=replace(opening.envelope,share_work_bits=3))):
            with self.assertRaisesRegex(ValueError,'conflicting compact admission jobs'):
                acct.preview_delta(changed,record(block))
            self.assertEqual((acct.stats(),acct.resources),before)

    def test_dependencies_dedup_and_old_proposed_root_can_later_be_an_origin(self):
        block,opening=variable_fixture()
        captured=opening.capture()
        acct=accountant(opening,dependencies=(captured,captured))
        self.assertEqual(acct.stats()['dependencies'],0)
        delta=acct.preview_delta(share(block,opening),record(block),dependencies=(captured,captured),depth=2)
        self.assertEqual(delta.resources.dependency_bytes-delta.resources.snapshot_bytes,len(captured.raw))
        self.assertEqual(delta.resources.dependency_depth,3)
        acct.commit(delta)
        self.assertEqual(acct.stats()['dependencies'],1)
        _,child=variable_fixture(templates=(block,),shares=(share(block,opening),),ntime=1700000002)
        child_capture=child.capture()
        later=acct.preview_delta(share(block,opening,1),record(block),dependencies=(captured,child_capture),depth=1)
        self.assertEqual(later.resources.dependency_bytes-later.resources.snapshot_bytes,len(captured.raw)+len(child_capture.raw))
        self.assertEqual(later.resources.dependency_shares,3)  # two root proofs + one dependency proof
        self.assertEqual(later.resources.origins,2)  # one full body plus mining headroom
        self.assertEqual(later.resources.dependency_depth,3)

    def test_recipients_reserve_native_history_and_only_distinct_current_pool_scripts(self):
        block,opening=variable_fixture()
        acct=CompactAdmissionAccountant(opening,historical_recipient_count=2,historical_recipient_bytes=74)
        first=acct.preview_delta(share(block,opening),record(block))
        self.assertEqual((first.resources.recipient_count,first.resources.recipient_bytes),(3,74+39))
        acct.commit(first)
        foreign,foreign_opening=variable_fixture(pool=4,ntime=1700000002)
        delta=acct.preview_delta(share(foreign,foreign_opening),record(foreign))
        self.assertEqual(delta.resources.recipient_bytes,first.resources.recipient_bytes)
        acct.commit(delta)
        other,other_opening=variable_fixture(payout_script=b'\x51\x20'+b'z'*32,ntime=1700000003)
        delta=acct.preview_delta(share(other,other_opening),record(other))
        self.assertEqual((delta.resources.recipient_count,delta.resources.recipient_bytes),(4,74+39+51))

    def test_duplicate_stale_foreign_and_refused_previews_never_change_committed_totals(self):
        block,opening=variable_fixture()
        acct=accountant(opening)
        proof=share(block,opening)
        first=acct.preview_delta(proof,record(block))
        parallel=acct.preview_delta(share(block,opening,1),record(block))
        other=accountant(opening)
        with self.assertRaisesRegex(ValueError,'foreign or stale'):
            other.commit(first)
        acct.commit(first)
        before=acct.stats(),acct.resources,acct.pending_proof_ids
        with self.assertRaisesRegex(ValueError,'foreign or stale'):
            acct.commit(parallel)
        duplicate=acct.preview_delta(proof,record(block))
        self.assertTrue(duplicate.duplicate)
        acct.commit(duplicate)
        self.assertEqual((acct.stats(),acct.resources,acct.pending_proof_ids),before)
        with self.assertRaisesRegex(ValueError,'conflicting compact admission proofs'):
            acct.preview_delta(replace(proof,owner_signature=b'z'*64),record(block))
        second=acct.preview_delta(share(block,opening,1),record(block))
        q=AdmissionQuote('11'*32,0,1,2,2,1,second.resources,1,1,1)
        with self.assertRaises(AdmissionRefused):
            AdmissionBudget(snapshot_budget=1024).require_ack(q)
        self.assertEqual((acct.stats(),acct.resources,acct.pending_proof_ids),before)

    def test_metadata_limits_fail_before_retention_and_no_full_data_is_kept(self):
        block,opening=variable_fixture()
        for limits in ({'max_entries':1},{'max_metadata_bytes':1024}):
            acct=accountant(opening,**limits)
            before=acct.stats(),acct.resources
            with self.assertRaises(MetadataCapacity):
                acct.preview_delta(share(block,opening),record(block))
            self.assertEqual((acct.stats(),acct.resources),before)
        acct=accountant(opening)
        acct.commit(acct.preview_delta(share(block,opening),record(block),dependencies=(opening.capture(),)))
        def metadata(value):
            if type(value) is tuple:
                return all(metadata(child) for child in value)
            return type(value) is int or type(value) is bytes and len(value)==32
        self.assertTrue(all(metadata(key) and metadata(value) for entries in acct._maps.values() for key,value in entries.items()))
        self.assertLessEqual(acct.stats()['metadata_bytes'],acct.max_metadata_bytes)
        self.assertLessEqual(acct.stats()['metadata_entries'],acct.max_entries)

    def test_rejects_legacy_wrong_record_and_unbounded_dependency_input(self):
        block,opening=variable_fixture()
        _,legacy=compact_fixture()
        with self.assertRaisesRegex(ValueError,'requires v8'):
            accountant(legacy)
        acct=accountant(opening)
        different,_=variable_fixture(ntime=1700000002)
        before=acct.stats()
        with self.assertRaisesRegex(ValueError,'differs from its compact origin'):
            acct.preview_delta(share(block,opening),record(different))
        with self.assertRaisesRegex(ValueError,'requires v8 dependencies'):
            acct.preview_delta(share(block,opening),record(block),dependencies=(legacy.capture(),))
        with self.assertRaises(MetadataCapacity):
            acct.preview_delta(share(block,opening),record(block),dependencies=iter(()))
        self.assertEqual(acct.stats(),before)


if __name__=='__main__':
    unittest.main()
