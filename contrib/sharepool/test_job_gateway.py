#!/usr/bin/env python3
"""Job refresh races, signed history cursor behavior, and immutable old jobs."""

from dataclasses import replace
from pathlib import Path
import tempfile
import threading
import unittest

from job_gateway import Gateway, LedgerConflict
from live_protocol import (Engine, MissingData, Rules, append_receipt, issue_job,
                           mine, propose_job)
from signed_registry import private_key, public_key, register, update


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.coordinator, self.miner = private_key(501), private_key(502)
        self.rules = Rules(public_key(self.coordinator))
        self.engine = Engine(self.rules)
        change = register(self.engine.registry(self.engine.genesis_registry), self.miner,
                          b"miner", b"\x51")
        self.registry_root = self.engine.add_change(change)
        self.gateway = Gateway(self.engine, self.miner, self.registry_root)
        self.server = Engine(self.rules)
        self.server.import_objects(self.engine.export())

    def callback(self, miner_id, registry_root, ledger_root, parent, serial):
        return propose_job(self.server, self.coordinator, miner_id, registry_root,
                           ledger_root, parent, serial)

    def refresh(self):
        job = self.gateway.refresh(self.callback)
        self.server.add_job(job)
        return job

    def receipt(self, job, *, previous=None, nonce=0):
        proof = mine(job, start_nonce=nonce)
        return append_receipt(self.server, self.coordinator,
                              self.gateway.ledger_root if previous is None else previous, proof=proof)

    def test_verified_receipt_pauses_and_refreshes_sidechain_commitment(self):
        old = self.refresh()
        original_header = old.header
        receipt = self.receipt(old)
        self.gateway.ingest_receipt(receipt)
        self.assertIsNone(self.gateway.active_job)
        self.assertEqual(self.gateway.ledger_root, receipt.root)
        new = self.refresh()
        self.assertNotEqual(new.manifest.root, old.manifest.root)
        self.assertNotEqual(new.header, old.header)
        self.assertEqual(new.manifest.ledger_root, receipt.root)
        self.assertEqual(old.header, original_header)
        self.assertEqual(self.gateway.issued[old.job_id], old)

    def test_receipt_event_automatically_refreshes_and_ancestor_does_not_reissue(self):
        old = self.refresh()
        receipt = self.receipt(old)
        fresh = self.gateway.receive_and_refresh(receipt, self.callback)
        self.assertIs(self.gateway.active_job, fresh)
        self.assertEqual(fresh.manifest.ledger_root, receipt.root)
        self.assertNotEqual(fresh.header, old.header)
        generation = self.gateway.generation

        def unexpected(*args):
            raise AssertionError("duplicate receipt must not request another job")

        self.assertIs(self.gateway.receive_and_refresh(receipt, unexpected), fresh)
        self.assertEqual(self.gateway.generation, generation)

    def test_callback_receipt_race_does_not_sign_or_activate_stale_proposal(self):
        old = self.refresh()
        receipt = self.receipt(old)
        seen = []

        def racing(*args):
            proposal = self.callback(*args)
            seen.append(proposal.job_id)
            self.gateway.ingest_receipt(receipt)
            return proposal

        self.assertIsNone(self.gateway.refresh(racing))
        self.assertIsNone(self.gateway.active_job)
        self.assertNotIn(seen[0], self.engine.jobs)
        self.assertNotIn(seen[0], self.gateway.issued)
        self.assertEqual(self.refresh().manifest.ledger_root, receipt.root)

    def test_slow_callback_does_not_hold_replica_lock(self):
        old = self.refresh()
        receipt = self.receipt(old)
        entered, release = threading.Event(), threading.Event()
        results, failures = [], []

        def slow(*args):
            proposal = self.callback(*args)
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test callback was not released")
            return proposal

        def refresh_thread():
            try:
                results.append(self.gateway.refresh(slow))
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=refresh_thread)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.gateway.ingest_receipt(receipt)
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results, [None])
        self.assertIsNone(self.gateway.active_job)

    def test_concurrent_refresh_response_cannot_replace_newer_activation(self):
        nested = []

        def callback_with_faster_refresh(*args):
            stale = self.callback(*args)
            nested.append(self.gateway.refresh(self.callback))
            return stale

        self.assertIsNone(self.gateway.refresh(callback_with_faster_refresh))
        self.assertIs(self.gateway.active_job, nested[0])
        self.assertEqual(len(self.gateway.issued), 1)

    def test_coordinator_cannot_rewind_requested_ledger_or_registry(self):
        old = self.refresh()
        receipt = self.receipt(old)
        self.gateway.ingest_receipt(receipt)

        def rewind(miner_id, registry_root, ledger_root, parent, serial):
            return self.callback(miner_id, registry_root, self.engine.empty_ledger, parent, serial)

        with self.assertRaisesRegex(ValueError, "requested state"):
            self.gateway.refresh(rewind)
        self.assertIsNone(self.gateway.active_job)
        self.assertEqual(self.gateway.ledger_root, receipt.root)

    def test_invalid_receipt_preserves_active_job_head_and_generation(self):
        job = self.refresh()
        receipt = self.receipt(job)
        before = (self.gateway.active_job, self.gateway.ledger_root, self.gateway.generation)
        with self.assertRaisesRegex(ValueError, "authorization"):
            self.gateway.ingest_receipt(replace(receipt, signature=b"invalid"))
        self.assertEqual(before, (self.gateway.active_job, self.gateway.ledger_root, self.gateway.generation))
        self.assertNotIn(receipt.root, self.engine.receipts)

    def test_missing_receipt_dependency_can_be_retried_without_cursor_change(self):
        job = self.refresh()
        first = self.receipt(job)
        second = self.receipt(job, previous=first.root, nonce=100)
        before = (self.gateway.ledger_root, self.gateway.generation, self.gateway.active_job)
        with self.assertRaises(MissingData):
            self.gateway.ingest_receipt(second)
        self.assertEqual(before, (self.gateway.ledger_root, self.gateway.generation, self.gateway.active_job))
        self.gateway.ingest_receipt(first)
        self.gateway.ingest_receipt(second)
        generation = self.gateway.generation
        self.gateway.ingest_receipt(first)
        self.assertEqual(self.gateway.ledger_root, second.root)
        self.assertEqual(self.gateway.generation, generation)

    def test_old_job_can_win_after_refresh_and_requires_seal_for_next_parent(self):
        old = self.refresh()
        receipt = self.receipt(old)
        self.gateway.ingest_receipt(receipt)
        fresh = self.refresh()
        winner = mine(old, full_block=True, start_nonce=200)
        identity = self.gateway.ingest_block(winner)
        self.server.add_block(winner)
        self.assertEqual(self.engine.tip, identity)
        self.assertIsNone(self.gateway.active_job)
        self.assertEqual(self.gateway.ledger_root, receipt.root)
        self.assertIn(old.job_id, self.gateway.issued)
        self.assertIn(fresh.job_id, self.gateway.issued)
        with self.assertRaisesRegex(ValueError, "seal"):
            self.gateway.refresh(self.callback)
        seal = append_receipt(self.server, self.coordinator, receipt.root, winner=identity)
        self.gateway.ingest_receipt(seal)
        next_job = self.refresh()
        self.assertEqual(next_job.manifest.parent, identity)
        self.assertEqual(next_job.manifest.ledger_root, seal.root)

    def test_registry_payout_update_pauses_without_mutating_old_job(self):
        old = self.refresh()
        change = update(self.engine.registry(self.registry_root), self.gateway.miner_id,
                        self.miner, self.miner, b"\x52")
        updated = self.gateway.ingest_change(change)
        self.server.add_change(change)
        self.gateway.select_registry(updated)
        self.assertIsNone(self.gateway.active_job)
        fresh = self.refresh()
        self.assertNotEqual(old.coinbase, fresh.coinbase)
        self.assertEqual(old.manifest.registry_root, self.registry_root)
        self.assertEqual(fresh.manifest.registry_root, updated)
        with self.assertRaisesRegex(ValueError, "descendant"):
            self.gateway.select_registry(self.registry_root)

        def rewind(miner_id, registry_root, ledger_root, parent, serial):
            return self.callback(miner_id, self.registry_root, ledger_root, parent, serial)

        with self.assertRaisesRegex(ValueError, "requested state"):
            self.gateway.refresh(rewind)
        self.assertIs(self.gateway.active_job, fresh)

    def test_registry_arrival_during_callback_discards_old_version_proposal(self):
        old = self.refresh()
        change = update(self.engine.registry(self.registry_root), self.gateway.miner_id,
                        self.miner, self.miner, b"\x52")
        self.server.add_change(change)
        seen = []

        def racing(*args):
            proposal = self.callback(*args)
            seen.append(proposal.job_id)
            updated = self.gateway.ingest_change(change)
            self.gateway.select_registry(updated)
            return proposal

        self.assertIsNone(self.gateway.refresh(racing))
        self.assertIsNone(self.gateway.active_job)
        self.assertNotIn(seen[0], self.engine.jobs)
        self.assertNotEqual(self.refresh().coinbase, old.coinbase)

    def test_future_registry_receipt_survives_old_winner_before_registry_selection(self):
        old = self.refresh()
        change = update(self.engine.registry(self.registry_root), self.gateway.miner_id,
                        self.miner, self.miner, b"\x52")
        updated = self.gateway.ingest_change(change)
        self.server.add_change(change)
        future = issue_job(self.server, self.miner, self.coordinator, updated,
                           self.engine.empty_ledger, serial=100)
        self.gateway.ingest_job(future)
        receipt = self.receipt(future)
        self.gateway.ingest_receipt(receipt)
        self.assertEqual(self.gateway.registry_root, self.registry_root)
        winner = mine(old, full_block=True)
        self.gateway.ingest_block(winner)
        self.server.add_block(winner)
        self.assertEqual(self.gateway.ledger_root, receipt.root)
        self.gateway.select_registry(updated)
        seal = append_receipt(self.server, self.coordinator, receipt.root, winner=self.engine.tip)
        self.gateway.ingest_receipt(seal)
        self.assertEqual(self.refresh().manifest.registry_root, updated)

    def test_signed_receipt_siblings_pause_until_anchored_choice(self):
        old = self.refresh()
        left = self.receipt(old)
        right = self.receipt(old, previous=self.engine.empty_ledger, nonce=100)
        self.gateway.ingest_receipt(left)
        chosen = self.refresh()
        with self.assertRaises(LedgerConflict):
            self.gateway.ingest_receipt(right)
        self.assertEqual(self.gateway.ledger_root, left.root)
        self.assertIn(right.root, self.engine.receipts)
        self.assertIsNone(self.gateway.active_job)
        with self.assertRaises(LedgerConflict):
            self.gateway.refresh(self.callback)
        winner = mine(chosen, full_block=True)
        identity = self.gateway.ingest_block(winner)
        self.server.add_block(winner)
        seal = append_receipt(self.server, self.coordinator, left.root, winner=identity)
        self.gateway.ingest_receipt(seal)
        self.assertEqual(self.refresh().manifest.parent, identity)
        self.assertEqual(len(self.gateway.conflicts), 1)

    def test_cursor_restore_keeps_archive_but_requires_fresh_authorization(self):
        old = self.refresh()
        receipt = self.receipt(old)
        self.gateway.ingest_receipt(receipt)
        active = self.refresh()
        with tempfile.TemporaryDirectory(prefix="sharepool-gateway-") as directory:
            archive = Path(directory) / "engine.json"
            cursor = Path(directory) / "cursor.json"
            self.engine.save(archive)
            self.gateway.save_cursor(cursor)
            restored_engine = Engine.restore(archive, self.rules)
            restored = Gateway.restore_cursor(restored_engine, self.miner, cursor)
            self.assertNotIn(self.miner.get_bytes().hex(), cursor.read_text())
            self.assertIsNone(restored.active_job)
            self.assertEqual(restored.ledger_root, receipt.root)
            self.assertEqual(set(restored.issued), set(self.gateway.issued))
            self.assertGreater(restored.generation, self.gateway.generation)
            replacement = restored.refresh(self.callback)
            self.assertGreater(replacement.manifest.serial, active.manifest.serial)


if __name__ == "__main__":
    unittest.main()
