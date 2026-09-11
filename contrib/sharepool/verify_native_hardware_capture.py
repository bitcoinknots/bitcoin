#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay a complete successful SPN1 hardware test archive.

Offline verification checks captured bytes and accounting, not native consensus
or the physical source of a nonce. An optional caller-supplied RPC independently
replays jobs, proofs and blocks into a fresh, isolated, explicitly activated
regtest node. This module never accesses a miner or starts a network service.
"""
import argparse
import hashlib
import json
from pathlib import Path

from native_enforcement import (MAX_SHARE_AGE, RULES_HASH, SHARE_BITS, monetary_outputs,
    parse_coinbase, payouts_root, shares_root, state_root)
from native_mining_gate import REGTEST_GENESIS, immutable_header, parse_block, parse_share
from testnet_template import TestnetTemplate, proof_from_sia
from test_framework.key import verify_schnorr
from test_framework.messages import CBlockHeader, uint256_from_compact


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value, maximum, *, exact=None):
    require(type(value) is str and len(value) <= 2 * maximum and len(value) % 2 == 0,
            "invalid bounded hexadecimal field")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError("invalid hexadecimal field") from None
    require(raw.hex() == value and (exact is None or len(raw) == exact),
            "noncanonical hexadecimal field")
    return raw


def number(value, low, high):
    require(type(value) is int and low <= value <= high, "invalid integer field")
    return value


def check_manifest(block, pool):
    manifest, outputs = parse_coinbase(block.vtx[0])
    e = manifest.envelope
    require(block.m_header_v2 and block.m_flags == 0 and block.m_xor_key == 0 and
            block.m_xor_key_mask_clear_bits == 0 and block.nVersion & 0xe0000000 == 0x20000000 and
            block.m_txcount == len(block.vtx) == 1 and block.nBits == SHARE_BITS,
            "unsupported native hardware header profile")
    require(e.version == 1 and e.genesis == int(REGTEST_GENESIS, 16) and e.rules == RULES_HASH and
            e.pool == pool and e.height == block.m_height and e.native_parent == block.hashPrevBlock and
            e.root == block.m_mm_rhs, "manifest context or header commitment mismatch")
    require(verify_schnorr(e.public_key, manifest.owner_signature, e.owner_message),
            "invalid current owner authorization")
    require(shares_root(manifest.shares) == e.shares_root and
            state_root(manifest.post_state) == e.state_root and payouts_root(outputs) == e.payouts_root,
            "manifest Merkle or payout commitment mismatch")
    height = number(e.height, 1, 0x7ffffffe)
    halvings = height // 150
    reward = 5_000_000_000 >> halvings if halvings < 64 else 0
    expected = monetary_outputs(manifest.shares, reward=reward, fallback_script=e.payout_script)
    require([o.serialize() for o in outputs] == [o.serialize() for o in expected],
            "coinbase does not allocate the exact native subsidy")
    require(block.hashMerkleRoot == block.calc_merkle_root(), "native transaction Merkle root mismatch")
    return manifest, outputs


def verify_capture(report, *, native_rpc=None):
    """Verify all records; optionally mutate only a guarded fresh regtest chain."""
    require(type(report) is dict, "capture object required")
    capture = report.get("capture", report)
    require(type(capture) is dict and capture.get("format") == "sharepool-native-hardware-spn1-v1" and
            capture.get("network") == "regtest" and capture.get("genesis") == REGTEST_GENESIS and
            capture.get("native_settlement_profile") == "SPN1" and
            capture.get("native_share_bits") == f"{SHARE_BITS:08x}", "unsupported capture profile")
    require(capture.get("failure") is None, "incomplete or failed native capture")
    pool = int.from_bytes(wire(capture.get("pool"), 32, exact=32), "big")
    require(pool != 0, "zero pool")
    difficulty = number(capture.get("difficulty"), 1, 1 << 24)
    require(difficulty & (difficulty - 1) == 0, "non-power-of-two transport difficulty")
    assigned_target, native_target = ((1 << 224) - 1) // difficulty, uint256_from_compact(SHARE_BITS)
    payout_script = wire(capture.get("payout_script"), 34)
    jobs, rows, candidates, accepted, by_normal_header = {}, {}, {}, {}, {}
    for field, limit in (("jobs", 32), ("shares", 128), ("candidates", 128), ("events", 4096)):
        require(type(capture.get(field)) is list and len(capture[field]) <= limit, "capture record bound")
    require(capture["jobs"], "missing native jobs")
    for saved in capture["jobs"]:
        raw = wire(saved["block"], 4_000_000)
        block = parse_block(raw)
        manifest, outputs = check_manifest(block, pool)
        template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize(), (),
            manifest.envelope.root.to_bytes(32, "little"), 4_000_000, 4_000_000)
        identity = template.job_id
        require(identity == saved["job_id"] and identity not in jobs and template.block() == raw,
                "duplicate or inconsistent native job")
        require(wire(saved["header"], 164, exact=164) == template.header_bytes and
                wire(saved["coinbase"], 4_000_000) == template.coinbase and
                wire(saved["manifest"], 65536) == manifest.serialize() and
                saved["commitment"] == f"{manifest.envelope.root:064x}" and
                saved["native_parent"] == f"{block.hashPrevBlock:064x}" and
                type(saved["height"]) is int and saved["height"] == block.m_height and
                saved["included_proofs"] == [f"{s.proof_id:064x}" for s in manifest.shares] and
                saved["payouts"] == [{"script": bytes(o.scriptPubKey).hex(), "satoshis": o.nValue} for o in outputs] and
                saved["assigned_target"] == f"{assigned_target:064x}" and
                manifest.envelope.payout_script == payout_script,
                "job archive differs from committed native template")
        require(saved.get("native_gate_authorized") is True and saved.get("native_proposal_result") is None,
                "job lacks native admission record")
        jobs[identity] = (saved, block, manifest, template)
        by_normal_header[immutable_header(block)] = identity
    for row in capture["shares"]:
        require(row["job_id"] in jobs, "proof references an unknown job")
        saved, block, manifest, template = jobs[row["job_id"]]
        proof = proof_from_sia(template, wire(row["prefix"], 4, exact=4),
            wire(row["extranonce2"], 8, exact=8), row["ntime"], row["nonce"])
        require(proof.display_hash == row["hash"] and proof.display_hash not in rows and
                proof.header == wire(row["header"], 164, exact=164) and
                proof.work == wire(row["work_header"], 80, exact=80) and
                proof.block == wire(row["block"], 4_000_000), "ASIC/header/full block replay mismatch")
        share = parse_share(wire(row["share_wire"], 1024))
        require(share.header_bytes == proof.header and share.envelope == manifest.envelope and
                share.owner_signature == manifest.owner_signature and proof.hash_int <= native_target,
                "native share attribution or PoW mismatch")
        assigned = proof.hash_int <= assigned_target
        require(type(row["meets_assigned_target"]) is bool and row["meets_assigned_target"] == assigned and
                row["native_target_solution"] is True and type(row["parent_current_at_admission"]) is bool and
                type(row["native_expected_work"]) is int and row["native_expected_work"] == 2 and
                row["native_share_bits"] == f"{SHARE_BITS:08x}" and
                row["assigned_target"] == f"{assigned_target:064x}", "share target or credit mismatch")
        response = row["native_share_response"]
        expected = {"valid": True, "proof_id": proof.display_hash, "pool": f"{pool:064x}",
            "origin_height": share.envelope.height, "owner": share.envelope.public_key.hex(),
            "payout_script": share.envelope.payout_script.hex(), "share_bits": f"{SHARE_BITS:08x}"}
        require(type(response) is dict and all(type(response.get(k)) is type(v) and response[k] == v
                for k, v in expected.items()), "native proof response mismatch")
        rows[proof.display_hash] = (row, share, proof)
    for entry in capture["candidates"]:
        identity = entry["hash"]
        require(identity not in candidates and identity in rows, "duplicate or unknown candidate")
        row, unused_share, proof = rows[identity]
        require(entry["job_id"] == row["job_id"] and wire(entry["block"], 4_000_000) == proof.block and
                row["parent_current_at_admission"] is True, "candidate archive mismatch")
        candidates[identity] = entry
    require(set(candidates) == {identity for identity, (row, _, __) in rows.items()
            if row["parent_current_at_admission"]}, "missing full native candidate archive")
    submissions = set()
    for event in capture["events"]:
        if event["kind"] == "native_block_submission":
            data = event["data"]
            require(data["hash"] in candidates and data["hash"] not in submissions and data["result"] is None,
                    "failed, repeated or unknown native submission")
            submissions.add(data["hash"])
        elif event["kind"] == "native_block_accepted":
            data, identity = event["data"], event["data"]["hash"]
            require(identity in candidates and identity not in accepted, "unknown or duplicate native acceptance")
            row, share, proof = rows[identity]
            saved, block, manifest, unused = jobs[row["job_id"]]
            require(type(data["height"]) is int and data["height"] == share.envelope.height and
                    data["commitment"] == f"{manifest.envelope.root:064x}" and
                    data["included_proofs"] == saved["included_proofs"], "native acceptance metadata mismatch")
            accepted[identity] = (data["height"], block, manifest, proof)
    require(set(accepted) == submissions == set(candidates), "candidate archive lacks complete acceptance evidence")
    chain = sorted(accepted, key=lambda identity: accepted[identity][0])
    parent, previous, paid = REGTEST_GENESIS, None, set()
    for height, identity in enumerate(chain, 1):
        actual_height, block, manifest, proof = accepted[identity]
        require(actual_height == height and f"{block.hashPrevBlock:064x}" == parent,
                "accepted records do not form a complete native chain")
        parent, previous = identity, manifest
    require(capture.get("last_native_tip") == parent, "reported native tip mismatch")
    ancestors = {0: REGTEST_GENESIS, **{i: identity for i, identity in enumerate(chain, 1)}}
    for saved, block, manifest, unused in jobs.values():
        h = block.m_height
        require(h <= len(chain) + 1 and f"{block.hashPrevBlock:064x}" == ancestors[h - 1],
                "origin job does not extend captured native ancestry")
        if h == 1:
            require(manifest.parent_envelope is None and not manifest.parent_state, "activation parent state")
        else:
            previous = accepted[ancestors[h - 1]][2]
            require(manifest.parent_envelope == previous.envelope and manifest.parent_state == previous.post_state,
                    "native parent state opening mismatch")
        already = {entry.proof_id for entry in manifest.parent_state}
        for share in manifest.shares:
            identity = f"{share.proof_id:064x}"
            require(identity in rows and rows[identity][1].serialize() == share.serialize(),
                    "settlement contains an uncaptured or altered proof")
            require(share.proof_id not in already and max(1, h - MAX_SHARE_AGE) <= share.envelope.height <= h,
                    "replayed or expired settled proof")
            require(immutable_header(share.header) in by_normal_header, "unknown full origin body")
            already.add(share.proof_id)
    for identity in chain:
        paid.update(f"{share.proof_id:064x}" for share in accepted[identity][2].shares)
    pending = sorted(set(rows) - paid)
    require(capture.get("pending_proofs") == pending, "historical settled/pending accounting mismatch")
    stats = capture.get("stats", {})
    counts = {"accepted": len(rows), "block_candidates": len(rows), "native_blocks_accepted": len(chain),
        "assigned_difficulty_shares": sum(row["meets_assigned_target"] for row, _, __ in rows.values()),
        "old_parent_shares": sum(not row["parent_current_at_admission"] for row, _, __ in rows.values()),
        "durable_acknowledgments_ready": len(rows)}
    require(all(type(stats.get(k)) is int and stats[k] == v for k, v in counts.items()), "capture counter mismatch")
    if "native_chain" in report:
        evidence = report["native_chain"]
        require(evidence["height"] == len(chain) and evidence["bestblockhash"] == parent and
                [b["hash"] for b in evidence["blocks"]] == chain, "native RPC chain evidence mismatch")
    if native_rpc is not None:
        info, net = native_rpc("getblockchaininfo"), native_rpc("getnetworkinfo")
        require(info.get("chain") == "regtest" and type(info.get("blocks")) is int and info["blocks"] == 0 and
                info.get("bestblockhash") == REGTEST_GENESIS and native_rpc("getblockhash", 0) == REGTEST_GENESIS and
                net.get("networkactive") is False and net.get("connections") == 0,
                "native replay requires a fresh isolated regtest chain")
        base = native_rpc("getblocktemplate", {"rules": ["segwit", "blake2b", "sharepool"],
                                               "capabilities": ["skip_validity_test"]})
        profile = base.get("sharepool", {})
        require("!sharepool" in base.get("rules", []) and profile.get("activation_height") == 1 and
                profile.get("rules_root") == f"{RULES_HASH:064x}", "native SPN1 replay profile is not active")
        for height in range(1, len(chain) + 2):
            for saved, block, unused_manifest, unused_template in jobs.values():
                if block.m_height == height:
                    require(native_rpc("getblocktemplate", {"mode": "proposal", "rules":
                        ["segwit", "blake2b", "sharepool"], "data": saved["block"]}) is None,
                        "native replay rejected a full origin proposal")
            for identity, (row, share, unused) in rows.items():
                if share.envelope.height == height:
                    answer = native_rpc("validatesharepoolshare", row["share_wire"])
                    require(answer.get("valid") is True and answer.get("proof_id") == identity,
                            "native replay rejected a captured ASIC proof")
            if height <= len(chain):
                identity = chain[height - 1]
                require(native_rpc("submitblock", accepted[identity][3].block.hex()) is None and
                        native_rpc("getblockhash", height) == identity and native_rpc("getbestblockhash") == identity,
                        "native replay rejected the captured winning block")
    return {"format": "sharepool-native-hardware-verification-v1", "network": "regtest",
        "jobs_verified": len(jobs), "asic_proofs_replayed": len(rows), "native_expected_work": 2 * len(rows),
        "assigned_difficulty_proofs": counts["assigned_difficulty_shares"],
        "accepted_blocks_verified": len(chain), "historically_settled_proofs": len(paid),
        "pending_proofs": pending, "last_native_tip": parent,
        "independent_native_replay": native_rpc is not None,
        "physical_origin": "Requires separate device/session evidence; hashes alone do not identify hardware."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    args = parser.parse_args()
    with Path(args.capture).open("rb") as source:
        raw = source.read(64_000_001)
    require(len(raw) <= 64_000_000, "capture JSON byte bound")
    result = verify_capture(json.loads(raw))
    result["capture_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
