#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay corruption checks using synthetic easy-target share evidence."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from base_chain_settlement import SettlementCommitment
from live_protocol import canonical
from precommit_demo import uint256_from_compact
from settlement_sim import merkle_root
from testnet_hardware_capture import TESTNET4_GENESIS
from testnet_template import build_template, proof_from_sia
from verify_hardware_capture import verify_capture


def easy_fixture_builder(*args, **kwargs):
    """Only fixtures relax the Testnet4 target ceiling, preserving real hashes.

    Production build_template rejects this regtest-easy compact target. Mocking
    that single guard avoids billions of hashes in archive replay unit tests;
    ASIC/header PoW, block bytes and replay's actual target check remain real.
    """
    def target_for_builder(bits):
        return uint256_from_compact(0x1d00ffff if bits == 0x207fffff else bits)
    with patch("testnet_template.uint256_from_compact", side_effect=target_for_builder):
        return build_template(*args, **kwargs)


def capture_fixture(*, easy=False, credit=True, archive=True, include_share=True,
                    legacy_nonce=False, nonce_start=0, ntime="00" * 8, extranonce2="00" * 8):
    script = bytes.fromhex("0014" + "22" * 20)
    target = (1 << 256) - 1 if credit else 1
    rules = {"genesis": TESTNET4_GENESIS, "share_target": f"{target:064x}", "payout_script": script.hex()}
    rules_root = hashlib.sha256(canonical(rules)).hexdigest()
    gbt = {"rules": ["!segwit", "!blake2b"], "version": 0xa0000000, "height": 150400,
           "curtime": 1789158160, "mintime": 1789158000, "bits": "207fffff" if easy else "1d00ffff",
           "previousblockhash": "33" * 32, "coinbasevalue": 5_000_000_000,
           "weightlimit": 800000, "sizelimit": 4000000, "sigoplimit": 80000,
           "transactions": [], "coinbaseaux": {}}
    def job_entry(snapshot, offset=0):
        template = {**gbt, "curtime": gbt["curtime"] + offset}
        envelope = SettlementCommitment.create(network_genesis=TESTNET4_GENESIS, pool_id=b"fixture",
            rules_root=rules_root, snapshot_root=merkle_root([canonical(row) for row in snapshot]).hex(),
            base_parent=gbt["previousblockhash"], payouts=[(script.hex(), gbt["coinbasevalue"])])
        builder = easy_fixture_builder if easy else build_template
        job = builder(template, [(script, gbt["coinbasevalue"])], envelope.root, b"SharepoolGoldshellTest")
        return job, {"job_id": job.job_id, "gbt": template, "header": job.header_bytes.hex(),
            "coinbase": job.coinbase.hex(), "envelope": envelope.to_object(), "snapshot": snapshot,
            "rules": rules, "commitment": envelope.root.hex(), "share_target": f"{target:064x}"}
    first, entry = job_entry([])
    for nonce in range(128):
        value = nonce_start + nonce
        nonce_hex = f"{value:08x}" if legacy_nonce else value.to_bytes(8, "little").hex()
        proof = proof_from_sia(first, b"ABCD", bytes.fromhex(extranonce2), ntime, nonce_hex)
        if not easy or proof.hash_int <= uint256_from_compact(first.header.nBits):
            break
    else:
        raise AssertionError("bounded easy candidate search failed")
    row = {"hash": proof.display_hash, "header": proof.header.hex(), "work_header": proof.work.hex(),
           "job_id": first.job_id, "prefix": b"ABCD".hex(), "extranonce2": extranonce2,
           "ntime": ntime, "nonce": nonce_hex, "weight": (1 << 256) // (target + 1), "share_target": f"{target:064x}",
           "candidate": proof.hash_int <= uint256_from_compact(first.header.nBits)}
    rows = [row] if credit and include_share else []
    _, second = job_entry(rows, offset=1)
    candidates = [{"proof": copy.deepcopy(row), "block": proof.block.hex(),
                   "envelope": entry["envelope"], "commitment": entry["commitment"],
                   "credited_as_share": proof.hash_int <= target}] if row["candidate"] and archive else []
    return {"format": 1, "network": "testnet4", "genesis": TESTNET4_GENESIS,
            "jobs": [entry, second], "shares": rows, "candidates": candidates}


class HardwareReplayTests(unittest.TestCase):
    def replay_easy(self, report):
        with patch("verify_hardware_capture.build_template", side_effect=easy_fixture_builder):
            return verify_capture(report)

    def test_actual_hash_mapping_and_causal_snapshot_replay(self):
        result = verify_capture(capture_fixture())
        self.assertEqual(result["shares"], 1)
        self.assertEqual(result["jobs"], 2)
        self.assertEqual(result["committed_in_last_job"], 1)
        self.assertEqual(result["tail_after_last_job"], 0)

    def test_rewritten_proof_header_and_nonce_fail(self):
        for key, value in (("nonce", "ff" * 8), ("header", "00" * 164), ("work_header", "00" * 80)):
            report = copy.deepcopy(capture_fixture())
            report["shares"][0][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                verify_capture(report)

    def test_duplicate_proofs_and_jobs_fail(self):
        for key in ("shares", "jobs"):
            report = capture_fixture()
            report[key].append(copy.deepcopy(report[key][0]))
            with self.subTest(field=key), self.assertRaises(ValueError):
                verify_capture(report)

    def test_snapshot_cannot_reference_future_job(self):
        report = capture_fixture()
        report["jobs"].reverse()
        with self.assertRaisesRegex(ValueError, "future"):
            verify_capture(report)

    def test_forged_credit_and_snapshot_root_fail(self):
        report = capture_fixture()
        report["shares"][0]["weight"] = 100
        with self.assertRaises(ValueError):
            verify_capture(report)
        report = capture_fixture()
        report["jobs"][1]["snapshot"] = []
        with self.assertRaisesRegex(ValueError, "snapshot root"):
            verify_capture(report)

    def test_network_or_coinbase_substitution_fails(self):
        report = capture_fixture()
        report["network"] = "main"
        with self.assertRaises(ValueError):
            verify_capture(report)
        report = capture_fixture()
        report["jobs"][0]["coinbase"] = "00"
        with self.assertRaises(ValueError):
            verify_capture(report)

    def test_full_candidate_archive_and_credited_share_replay_once(self):
        result = self.replay_easy(capture_fixture(easy=True))
        self.assertEqual(result["shares"], 1)
        self.assertEqual(result["native_hash_matches"], 1)
        self.assertEqual(result["base_target_solutions"], 1)
        self.assertEqual(result["base_target_solutions_among_credited_shares"], 1)
        self.assertEqual(result["candidate_archive_count"], 1)
        self.assertEqual(result["candidate_only_count"], 0)
        self.assertEqual(result["total_target_work"], 1)
        self.assertTrue(result["candidate_archive_verified"])

    def test_candidate_only_replays_but_never_adds_share_credit(self):
        report = capture_fixture(easy=True, credit=False)
        self.assertGreater(report["candidates"][0]["proof"]["weight"], 0)
        result = self.replay_easy(report)
        self.assertEqual(result["shares"], 0)
        self.assertEqual(result["native_hash_matches"], 1)
        self.assertEqual(result["base_target_solutions"], 1)
        self.assertEqual(result["base_target_solutions_among_credited_shares"], 0)
        self.assertEqual(result["candidate_only_count"], 1)
        self.assertEqual(result["total_target_work"], 0)
        self.assertEqual(result["committed_in_last_job"], 0)

    def test_credited_base_solution_requires_complete_archive(self):
        with self.assertRaisesRegex(ValueError, "missing its candidate archive"):
            self.replay_easy(capture_fixture(easy=True, archive=False))
        with self.assertRaisesRegex(ValueError, "differs from credited share"):
            self.replay_easy(capture_fixture(easy=True, include_share=False))

    def test_candidate_only_cannot_be_inserted_as_credited_share(self):
        report = capture_fixture(easy=True, credit=False)
        report["shares"] = [copy.deepcopy(report["candidates"][0]["proof"])]
        with self.assertRaisesRegex(ValueError, "insufficient credited share"):
            self.replay_easy(report)

    def test_candidate_block_envelope_root_and_boolean_tampering_reject(self):
        for field, value in (("block", "00"), ("commitment", "00" * 32),
                             ("credited_as_share", False), ("credited_as_share", 1)):
            report = capture_fixture(easy=True)
            report["candidates"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "classification mismatch"):
                self.replay_easy(report)
        report = capture_fixture(easy=True)
        report["candidates"][0]["envelope"] = report["jobs"][1]["envelope"]
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            self.replay_easy(report)
        report = capture_fixture(easy=True)
        report["candidates"][0]["block"] += "00"
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            self.replay_easy(report)

    def test_candidate_nonce_header_and_full_proof_tampering_reject(self):
        for field, value in (("nonce", "ff" * 8), ("header", "00" * 164), ("work_header", "00" * 80),
                             ("candidate", False), ("job_id", "00" * 32)):
            report = capture_fixture(easy=True)
            report["candidates"][0]["proof"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay_easy(report)

    def test_duplicate_candidate_and_missing_archive_fields_reject(self):
        report = capture_fixture(easy=True)
        report["candidates"].append(copy.deepcopy(report["candidates"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate candidate"):
            self.replay_easy(report)
        for key in ("block", "proof", "commitment", "envelope", "credited_as_share"):
            report = capture_fixture(easy=True)
            del report["candidates"][0][key]
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "archive fields"):
                self.replay_easy(report)

    def test_ordinary_share_cannot_be_mislabeled_as_archived_block_candidate(self):
        report = capture_fixture()
        row, entry = report["shares"][0], report["jobs"][0]
        self.assertFalse(row["candidate"])
        report["candidates"] = [{"proof": copy.deepcopy(row), "block": "00", "envelope": entry["envelope"],
                                 "commitment": entry["commitment"], "credited_as_share": True}]
        with self.assertRaisesRegex(ValueError, "insufficient native target"):
            verify_capture(report)

    def test_easy_fixture_guard_is_never_relaxed_in_production_replay(self):
        with self.assertRaisesRegex(ValueError, "invalid compact target"):
            verify_capture(capture_fixture(easy=True))

    def test_replay_accepts_live_legacy_and_extended_search_encodings(self):
        work_headers = set()
        for ntime in ("a1b2c3d4", "D4C3B2A100000000"):
            for legacy_nonce in (True, False):
                report = capture_fixture(ntime=ntime, legacy_nonce=legacy_nonce, nonce_start=0x01020304,
                                         extranonce2="AA bb CC dd EE ff 00 11")
                with self.subTest(ntime=ntime, legacy_nonce=legacy_nonce):
                    self.assertTrue(verify_capture(report)["verified"])
                work_headers.add(report["shares"][0]["work_header"])
        # Different accepted wire spellings identify the same actual ASIC work.
        self.assertEqual(len(work_headers), 1)

    def test_legacy_search_encoding_replays_candidate_archive_too(self):
        report = capture_fixture(easy=True, legacy_nonce=True, nonce_start=0x01020304, ntime="A1B2C3D4")
        result = self.replay_easy(report)
        self.assertEqual(result["candidate_archive_count"], 1)
        self.assertTrue(result["candidate_archive_verified"])

    def test_replay_still_rejects_invalid_live_search_field_lengths(self):
        for field, value in (("ntime", "00" * 6), ("nonce", "00" * 9), ("extranonce2", "00" * 7),
                             ("extranonce2", " " * 257)):
            report = capture_fixture()
            report["shares"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify_capture(report)


if __name__ == "__main__":
    unittest.main()
