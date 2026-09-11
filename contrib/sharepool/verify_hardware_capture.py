#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay exact recorded ASIC work and immutable testnet template commitments.

This verifies captured bytes, not device provenance, arrival time, UTXO validity
or historical native RPC outcomes. Live native validation is a separate gate.
"""
import argparse
import hashlib
import json
from pathlib import Path

from base_chain_settlement import SettlementCommitment
from live_protocol import canonical, decode_coinbase
from precommit_demo import uint256_from_compact
from settlement_sim import merkle_root
from testnet_hardware_capture import TESTNET4_GENESIS
from testnet_template import build_template, proof_from_sia


def canonical_hex(value, size):
    if type(value) is not str or len(value) != size * 2:
        raise ValueError("capture has an invalid hexadecimal field length")
    raw = bytes.fromhex(value)
    if raw.hex() != value:
        raise ValueError("capture has noncanonical hexadecimal data")
    return raw


def verify_capture(report):
    if (type(report) is not dict or type(report.get("format")) is not int or
            report.get("format") != 1 or report.get("network") != "testnet4" or
            report.get("genesis") != TESTNET4_GENESIS):
        raise ValueError("wrong capture format or network")
    entries, records, candidates = report.get("jobs"), report.get("shares"), report.get("candidates")
    if (type(entries) is not list or not 1 <= len(entries) <= 32 or
            type(records) is not list or len(records) > 4096 or
            type(candidates) is not list or len(candidates) > 64 or not (records or candidates)):
        raise ValueError("capture job/share/candidate bounds")
    jobs, positions, envelopes = {}, {}, {}
    for index, entry in enumerate(entries):
        envelope = SettlementCommitment.from_object(entry["envelope"])
        rules = entry["rules"]
        if (rules.get("genesis") != TESTNET4_GENESIS or envelope.network_genesis != TESTNET4_GENESIS or
                hashlib.sha256(canonical(rules)).hexdigest() != envelope.rules_root):
            raise ValueError("capture rules commitment mismatch")
        target = int.from_bytes(canonical_hex(entry["share_target"], 32), "big")
        if not 0 < target < 1 << 256 or rules.get("share_target") != entry["share_target"]:
            raise ValueError("capture approved target mismatch")
        snapshot = entry["snapshot"]
        if type(snapshot) is not list or len(snapshot) > 4096:
            raise ValueError("capture snapshot bounds")
        if merkle_root([canonical(row) for row in snapshot]).hex() != envelope.snapshot_root:
            raise ValueError("capture snapshot root mismatch")
        job = build_template(entry["gbt"], [(bytes.fromhex(rules["payout_script"]), entry["gbt"]["coinbasevalue"])],
                             envelope.root, b"SharepoolGoldshellTest", chain="testnet4")
        if (job.job_id != entry["job_id"] or job.header_bytes.hex() != entry["header"] or
                job.coinbase.hex() != entry["coinbase"] or envelope.root.hex() != entry["commitment"] or
                envelope.base_parent != entry["gbt"]["previousblockhash"] or job.job_id in jobs):
            raise ValueError("capture does not reconstruct the same immutable native job")
        outputs = [(bytes(o.scriptPubKey).hex(), o.nValue) for o in decode_coinbase(job.coinbase).vout]
        expected = SettlementCommitment.create(network_genesis=TESTNET4_GENESIS, pool_id=envelope.pool_id,
            rules_root=envelope.rules_root, snapshot_root=envelope.snapshot_root,
            base_parent=envelope.base_parent, payouts=outputs)
        if expected != envelope:
            raise ValueError("capture coinbase allocation differs from committed payouts")
        jobs[job.job_id], positions[job.job_id], envelopes[job.job_id] = job, index, envelope

    def replay_row(row):
        fields = {"hash", "header", "work_header", "job_id", "prefix", "extranonce2", "ntime",
                  "nonce", "weight", "share_target", "candidate"}
        if type(row) is not dict or set(row) != fields or type(row["job_id"]) is not str:
            raise ValueError("invalid captured proof fields")
        identity = row["hash"]
        canonical_hex(identity, 32)
        if row["job_id"] not in jobs:
            raise ValueError("missing originating job")
        job = jobs[row["job_id"]]
        canonical_hex(row["header"], 164)
        canonical_hex(row["work_header"], 80)
        # Mirror live submission parsing. The shared Sia parser accepts legacy
        # 8-hex big-endian and extended 16-hex little-endian time/nonce fields.
        # The driver preserves extranonce2 spelling after bytes.fromhex; retain
        # that exact spelling in snapshot comparisons, rather than normalizing.
        if type(row["extranonce2"]) is not str or len(row["extranonce2"]) > 256:
            raise ValueError("invalid captured submission extranonce")
        proof = proof_from_sia(job, canonical_hex(row["prefix"], 4), bytes.fromhex(row["extranonce2"]),
                              row["ntime"], row["nonce"])
        target = int(entries[positions[job.job_id]]["share_target"], 16)
        candidate = proof.hash_int <= uint256_from_compact(job.header.nBits)
        if (proof.display_hash != identity or proof.header.hex() != row["header"] or
                proof.work.hex() != row["work_header"] or
                row["share_target"] != f"{target:064x}" or type(row["weight"]) is not int or
                row["weight"] != (1 << 256) // (target + 1) or row["candidate"] is not candidate):
            raise ValueError("capture proof, target-derived credit or native hash mismatch")
        return proof, candidate, proof.hash_int <= target

    by_hash, credited_candidates = {}, set()
    for row in records:
        proof, candidate, qualifies_share = replay_row(row)
        identity = proof.display_hash
        if identity in by_hash or not qualifies_share:
            raise ValueError("duplicate proof or insufficient credited share work")
        by_hash[identity] = row
        if candidate:
            credited_candidates.add(identity)
    by_candidate = {}
    for archive in candidates:
        if (type(archive) is not dict or
                set(archive) != {"proof", "block", "envelope", "commitment", "credited_as_share"}):
            raise ValueError("invalid candidate archive fields")
        row = archive["proof"]
        proof, candidate, qualifies_share = replay_row(row)
        identity = proof.display_hash
        if not candidate or identity in by_candidate:
            raise ValueError("duplicate candidate or insufficient native target work")
        envelope = envelopes[row["job_id"]]
        if (type(archive["credited_as_share"]) is not bool or archive["credited_as_share"] != qualifies_share or
                SettlementCommitment.from_object(archive["envelope"]) != envelope or
                archive["commitment"] != envelope.root.hex() or archive["block"] != proof.block.hex()):
            raise ValueError("candidate block, commitment or credit classification mismatch")
        if (qualifies_share and by_hash.get(identity) != row) or (not qualifies_share and identity in by_hash):
            raise ValueError("candidate archive differs from credited share records")
        by_candidate[identity] = row
    if not credited_candidates.issubset(by_candidate):
        raise ValueError("credited base-target solution is missing its candidate archive")
    previous = set()
    for index, entry in enumerate(entries):
        included = set()
        for row in entry["snapshot"]:
            identity = row["hash"]
            if (identity in included or by_hash.get(identity) != row or
                    positions.get(row["job_id"], index) >= index):
                raise ValueError("snapshot duplicates, alters, or references future work")
            included.add(identity)
        if not previous.issubset(included):
            raise ValueError("capture snapshot loses previously included work")
        previous = included
    all_proofs = {**by_hash, **by_candidate}
    return {"verified": True, "network": "testnet4", "jobs": len(jobs),
            "shares": len(by_hash), "unique_work_headers": len({row["work_header"] for row in all_proofs.values()}),
            "native_hash_matches": len(all_proofs), "base_target_solutions": len(by_candidate),
            "base_target_solutions_among_credited_shares": len(credited_candidates),
            "candidate_archive_count": len(by_candidate),
            "candidate_only_count": len(by_candidate) - len(credited_candidates),
            "candidate_archive_verified": True,
            "committed_in_last_job": len(previous), "tail_after_last_job": len(by_hash) - len(previous),
            "total_target_work": sum(row["weight"] for row in records),
            "payout_outputs_reconstructed": True, "snapshot_causality_verified": True,
            "native_consensus_validation": "separate live RPC evidence required"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.capture.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("capture file too large")
    result = verify_capture(json.loads(args.capture.read_bytes()))
    raw = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(raw)
    print(raw)


if __name__ == "__main__":
    main()
