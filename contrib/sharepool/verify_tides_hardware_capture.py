#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent bounded v6 Sia archive replay; no miner access.

Offline checks establish byte consistency, authorization and reference payout
arithmetic. A caller-provided fresh isolated native node establishes consensus
acceptance. Neither mode proves that physical hardware produced a nonce.

Historical v6-r1 captures must use this tool and its complete dependency tree
from commit 590cfe6. This revision validates v6-r2 admission-height cohorts; it
does not reinterpret old hardware evidence under the new consensus rules.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path

from hash_snapshot import Snapshot, apply_tides_state, job_hash, parse_share, share_target, share_work, TIDES_RULES_HASH
from native_enforcement import verify_schnorr
from native_mining_gate import REGTEST_GENESIS, parse_block
from testnet_template import TestnetTemplate, proof_from_sia
from test_framework.messages import CBlockHeader, uint256_from_compact
from verify_native_hardware_capture import require, wire, number

FORMAT = "sharepool-tides-sia-capture-v6-1"
HISTORICAL_R1_RULES = "765159ddb40e9c07a55450bb129e9771676bdc45e7ff841efa8de4a140ed3faf"


def verify_capture(report, *, native_rpc=None):
    require(not (type(report) is dict and report.get("rules") == HISTORICAL_R1_RULES),
            "historical v6-r1 capture: replay with the complete tool tree from commit 590cfe6; current v6-r2 native rules are incompatible")
    require(type(report) is dict and report.get("format") == FORMAT and report.get("network") == "regtest" and
            report.get("genesis") == REGTEST_GENESIS and report.get("rules") == f"{TIDES_RULES_HASH:064x}" and
            report.get("failure") is None, "successful isolated v6 capture required")
    for field, limit in (("jobs", 32), ("shares", 128), ("candidates", 128), ("events", 4096)):
        require(type(report.get(field)) is list and len(report[field]) <= limit, "capture record bound")
    difficulty = number(report.get("difficulty"), 1, 1 << 24)
    require(difficulty & (difficulty - 1) == 0, "invalid transport difficulty")
    assigned_target = ((1 << 224) - 1) // difficulty
    pool = int.from_bytes(wire(report["pool"], 32, exact=32), "big")
    script = wire(report["payout_script"], 34)
    jobs, rows, candidates, accepted = {}, {}, {}, {}
    for saved in report["jobs"]:
        raw, opening_raw = wire(saved["block"], 4_000_000), wire(saved["snapshot"], 16 * 1024 * 1024)
        block, opening = parse_block(raw), Snapshot.deserialize(opening_raw)
        envelope = opening.envelope
        require(envelope.version == 6 and envelope.rules == TIDES_RULES_HASH and envelope.genesis == int(REGTEST_GENESIS, 16) and
                envelope.pool == pool and envelope.payout_script == script and block.m_height == envelope.height and
                block.hashPrevBlock == envelope.native_parent and block.m_mm_rhs == opening.hash and
                opening.job_commitment == job_hash(block), "snapshot/job binding mismatch")
        require(verify_schnorr(envelope.public_key, opening.owner_signature, opening.owner_message), "invalid exact owner signature")
        require(block.m_header_v2 and block.nBits == 0x207fffff and block.m_flags == block.m_xor_key == block.m_xor_key_mask_clear_bits == 0 and
                block.nNonce == block.m_nonce2 == block.m_nonce3 == block.m_time_offset == block.m_extranonce == 0 and
                block.m_txcount == len(block.vtx) == 1 and block.hashMerkleRoot == block.calc_merkle_root(), "unsupported native job body")
        template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize(), (),
                                  opening.hash.to_bytes(32, "little"), 4_000_000, 4_000_000)
        require(template.block() == raw and saved["job_id"] == template.job_id and template.job_id not in jobs,
                "duplicate or inconsistent Sia job")
        require(saved["commitment"] == opening.hash_hex and saved["native_parent"] == f"{block.hashPrevBlock:064x}" and
                saved["height"] == block.m_height and saved["included_proofs"] == [f"{proof.proof_id:064x}" for proof in opening.shares] and
                saved["payouts"] == [{"script": bytes(output.scriptPubKey).hex(), "satoshis": output.nValue}
                                     for output in opening.payouts], "job metadata mismatch")
        require([output.serialize() for output in block.vtx[0].vout[:len(opening.payouts)]] ==
                [output.serialize() for output in opening.payouts], "coinbase payouts differ from snapshot")
        jobs[template.job_id] = saved, block, opening, template
    require(jobs, "missing capture jobs")
    for row in report["shares"]:
        require(row["job_id"] in jobs, "unknown proof job")
        saved, block, opening, template = jobs[row["job_id"]]
        proof = proof_from_sia(template, wire(row["prefix"], 4, exact=4), wire(row["extranonce2"], 8, exact=8), row["ntime"], row["nonce"])
        share = parse_share(wire(row["share_wire"], 1024))
        require(proof.display_hash == row["hash"] and row["hash"] not in rows and proof.header == wire(row["header"], 164, exact=164) and
                proof.work == wire(row["work_header"], 80, exact=80) and proof.block == wire(row["block"], 4_000_000) and
                share.header_bytes == proof.header and share.envelope == opening.envelope and
                share.owner_signature == opening.owner_signature and proof.hash_int <= share_target(block.nBits, 6), "proof replay mismatch")
        require(row["native_expected_work"] == share_work(block.nBits, 6) and
                row["assigned_target"] == f"{assigned_target:064x}" and
                row["meets_assigned_target"] is (proof.hash_int <= assigned_target) and
                row["native_target_solution"] is (proof.hash_int <= uint256_from_compact(block.nBits)) and
                type(row["parent_current_at_admission"]) is bool, "proof work accounting mismatch")
        response = row["native_share_response"]
        require(type(response) is dict and response.get("valid") is True and response.get("proof_id") == row["hash"], "missing native proof validation record")
        rows[row["hash"]] = row, share, proof
    for saved in report["candidates"]:
        identity = saved["hash"]
        require(identity in rows and identity not in candidates, "unknown or duplicate candidate")
        row, _, proof = rows[identity]
        require(row["native_target_solution"] and row["parent_current_at_admission"] and saved["job_id"] == row["job_id"] and
                wire(saved["block"], 4_000_000) == proof.block, "candidate differs from proof")
        candidates[identity] = saved
    submitted = set()
    for event in report["events"]:
        data = event["data"]
        if event["kind"] == "native_block_submission":
            require(data["hash"] in candidates and data["hash"] not in submitted and data["result"] is None, "failed or duplicate submission")
            submitted.add(data["hash"])
        if event["kind"] == "native_block_accepted":
            require(data["hash"] in submitted and data["hash"] not in accepted and
                    data["job_id"] == rows[data["hash"]][0]["job_id"], "inconsistent native acceptance")
            accepted[data["hash"]] = data
    require(set(candidates) == set(accepted) == submitted == {identity for identity, (row, _, __) in rows.items()
            if row["native_target_solution"] and row["parent_current_at_admission"]}, "incomplete native candidate results")
    chain = sorted(accepted, key=lambda identity: accepted[identity]["height"])
    ancestry, parents, admitted = {0: REGTEST_GENESIS}, {}, set()
    for height, identity in enumerate(chain, 1):
        _, block, opening, _ = jobs[accepted[identity]["job_id"]]
        require(accepted[identity]["height"] == height == block.m_height and
                f"{block.hashPrevBlock:064x}" == ancestry[height - 1], "captured chain is incomplete")
        ancestry[height], parents[height] = identity, opening
        admitted.update(f"{proof.proof_id:064x}" for proof in opening.shares)
    require(report["last_native_tip"] == ancestry[len(chain)] and report["unanchored_proofs"] == sorted(set(rows) - admitted), "admission summary mismatch")
    for saved, block, opening, _ in jobs.values():
        height = block.m_height
        require(height in range(1, len(chain) + 2) and f"{block.hashPrevBlock:064x}" == ancestry[height - 1], "job ancestry mismatch")
        derived = apply_tides_state(opening, parents.get(height - 1))
        require(derived.serialize() == opening.serialize(), "history commitment, replay state or certificates differ")
        cohorts, seen = {}, set()
        for snapshot in [parents[h] for h in range(1, height)] + [opening]:
            for share in snapshot.shares:
                identity = f"{share.proof_id:064x}"
                require(identity in rows and rows[identity][1].serialize() == share.serialize(), "uncaptured or altered admission")
                require(identity not in seen, "duplicate historical admission")
                seen.add(identity)
                if share.envelope.pool == pool:
                    cohorts.setdefault(snapshot.envelope.height, []).append(
                        (share.envelope.payout_script, share_work(share.header.nBits, 6)))
        reward = 5_000_000_000 >> (height // 150) if height // 150 < 64 else 0
        if cohorts:
            # Native target work is rational. Floor neither its denominator
            # nor the oldest partial admission-height cohort before calculating
            # satoshis. Origin height and numeric proof ID are not payout order.
            remaining = Fraction(8 * (1 << 256), uint256_from_compact(block.nBits) + 1)
            counted, by_script = Fraction(0), {}
            for admitted_height in sorted(cohorts, reverse=True):
                cohort = cohorts[admitted_height]
                total_work = sum(work for _, work in cohort)
                included = min(remaining, Fraction(total_work))
                counted += included
                for recipient, work in cohort:
                    by_script[recipient] = by_script.get(recipient, Fraction(0)) + included * work / total_work
                remaining -= included
                if not remaining:
                    break
            expected = tuple((recipient, int(Fraction(reward) * work / counted))
                             for recipient, work in sorted(by_script.items()) if Fraction(reward) * work / counted >= 1)
        else:
            expected = ((script, reward),) if reward else ()
        require(tuple((bytes(output.scriptPubKey), output.nValue) for output in opening.payouts) == expected,
                "independent TIDES payout mismatch")
    stats = report["stats"]
    counts = {"accepted": len(rows), "native_blocks_accepted": len(chain), "durable_acknowledgments_ready": len(rows),
        "block_candidates": sum(row["native_target_solution"] for row, _, __ in rows.values()),
        "old_parent_shares": sum(not row["parent_current_at_admission"] for row, _, __ in rows.values()),
        "assigned_difficulty_shares": sum(row["meets_assigned_target"] for row, _, __ in rows.values())}
    require(all(type(stats.get(key)) is int and stats[key] == value for key, value in counts.items()), "capture counters differ")
    if native_rpc is not None:
        info, net, profile = native_rpc("getblockchaininfo"), native_rpc("getnetworkinfo"), native_rpc("getsharepoolhashstatus")
        require(info.get("chain") == "regtest" and info.get("blocks") == 0 and native_rpc("getblockhash", 0) == REGTEST_GENESIS and
                native_rpc("getbestblockhash") == REGTEST_GENESIS and net.get("networkactive") is False and net.get("connections") == 0 and
                profile.get("mode") == "hash-only-v6-tides" and profile.get("activation_height") == 1 and
                profile.get("rules") == f"{TIDES_RULES_HASH:064x}", "native replay requires fresh isolated v6 regtest")
        for saved, _, opening, _ in jobs.values():
            require(native_rpc("submitsharepoolhashsnapshot", saved["snapshot"])["hash"] == opening.hash_hex, "native snapshot hash differs")
        for height in range(1, len(chain) + 2):
            for saved, block, _, __ in jobs.values():
                if block.m_height == height:
                    require(native_rpc("validatesharepoolhashtemplate", saved["block"])["valid"] is True, "native job replay rejected")
            for row, share, _ in rows.values():
                if share.envelope.height == height:
                    require(native_rpc("validatesharepoolhashshare", row["share_wire"])["valid"] is True, "native proof replay rejected")
            if height <= len(chain):
                require(native_rpc("submitblock", candidates[chain[height - 1]]["block"]) is None, "native block replay rejected")
                require(native_rpc("getbestblockhash") == chain[height - 1], "native replay tip mismatch")
        require(native_rpc("verifychain", 4, 0) is True, "native replay chain verification failed")
    return {"profile": "v6-tides", "rules_revision": 2, "jobs": len(jobs), "proofs": len(rows), "blocks": len(chain),
            "native_replay": native_rpc is not None, "physical_provenance_verified": False,
            "last_native_tip": ancestry[len(chain)]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    require(args.report.stat().st_size <= 64 * 1024 * 1024, "capture file exceeds byte limit")
    print(json.dumps(verify_capture(json.loads(args.report.read_text())), sort_keys=True))
