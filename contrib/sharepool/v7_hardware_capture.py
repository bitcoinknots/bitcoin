#!/usr/bin/env python3
"""Bounded public-evidence capture/replay for the isolated v7 ASIC test.

No device credentials, pool configuration or bridge client belongs here.
Replaying nonce bytes establishes their validity, not their physical provenance.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from hash_snapshot import Snapshot, job_hash, parse_share, share_target
from hash_stratum import transport_target
from native_enforcement import verify_schnorr
from native_mining_gate import REGTEST_GENESIS, parse_block
from testnet_template import TestnetTemplate, proof_from_sia
from test_framework.messages import CBlockHeader

RPC_METHODS = frozenset(("submitsharepoolhashsnapshot", "validatesharepoolhashtemplate",
                         "validatesharepoolhashshare", "submitblock"))
MAX_BYTES, MAX_RECORD_BYTES, MAX_RECORDS = 128 * 1024 * 1024, 40 * 1024 * 1024, 4096


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      default=lambda value: str(value)).encode()


def write_terminal_report(path, report, *, successful=False):
    """Publish a terminal outcome; unfinished or exceptional exits fail closed."""
    result = {**report, "result": "passed" if successful is True else "failed"}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical(result) + b"\n")
        output.flush()
        os.fsync(output.fileno())


def submission_params(data):
    """Require the exact authorized five-field submit captured by this service."""
    params = data.get("params")
    if (type(params) is not list or len(params) != 5 or
            any(type(value) is not str or len(value) > 256 for value in params) or
            params[0] != "sharepool.regtest" or params[1] != data.get("job_id")):
        raise ValueError("captured submission authorization/job binding mismatch")
    return params


def require_captured_winner(block_hash, block_raw, proof_blocks):
    if proof_blocks.get(block_hash) != block_raw:
        raise ValueError("winning native block lacks its exact captured Sia proof")


class CaptureStore:
    def __init__(self, path):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE records(sequence INTEGER PRIMARY KEY, data BLOB NOT NULL)")
        self.count = self.bytes = 0
        self.failed = False

    def append(self, kind, data):
        try:
            if self.failed:
                raise ValueError("hardware capture already failed")
            raw = canonical({"sequence": self.count + 1, "kind": kind, "data": data})
            if len(raw) > MAX_RECORD_BYTES or self.bytes + len(raw) + 1 > MAX_BYTES or self.count >= MAX_RECORDS:
                raise ValueError("hardware capture evidence budget reached")
            with self.db:
                self.db.execute("INSERT INTO records VALUES (?,?)", (self.count + 1, raw))
            self.count += 1
            self.bytes += len(raw) + 1
        except Exception:
            self.failed = True
            raise

    def export(self, path):
        if self.failed:
            raise ValueError("failed capture cannot publish a complete export")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            for raw, in self.db.execute("SELECT data FROM records ORDER BY sequence"):
                output.write(raw + b"\n")
            output.flush()
            os.fsync(output.fileno())
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def close(self):
        self.db.close()


def replay_capture(path, rpc):
    """Authenticate public bytes, then replay on a fresh isolated native node."""
    if (rpc("getblockchaininfo")["chain"] != "regtest" or rpc("getblockcount") != 0 or
            rpc("getblockhash", 0) != REGTEST_GENESIS or rpc("getnetworkinfo")["networkactive"] is not False or
            rpc("getnetworkinfo")["connections"] != 0 or rpc("getsharepoolhashstatus")["mode"] != "hash-only-v7-compact-tides"):
        raise ValueError("fresh isolated v7 replay node required")
    if not 1 <= Path(path).stat().st_size <= MAX_BYTES:
        raise ValueError("capture file exceeds byte budget")
    jobs, proofs, calls, blocks, count, mode, difficulty = {}, set(), 0, 0, 0, None, None
    validated_proofs, validated_templates, policy, complete = set(), set(), None, None
    proof_blocks = {}
    with open(path, "rb") as source:
        while raw := source.readline(MAX_RECORD_BYTES + 2):
            count += 1
            if count > MAX_RECORDS or len(raw) > MAX_RECORD_BYTES + 1 or not raw.endswith(b"\n"):
                raise ValueError("capture record exceeds bound")
            record = json.loads(raw)
            if (type(record) is not dict or set(record) != {"sequence", "kind", "data"} or
                    type(record.get("sequence")) is not int or type(record.get("kind")) is not str or
                    type(record.get("data")) is not dict or raw != canonical(record) + b"\n" or record["sequence"] != count):
                raise ValueError("capture canonical sequence mismatch")
            if complete is not None:
                raise ValueError("capture continues after its final checkpoint")
            kind, data = record["kind"], record["data"]
            if kind == "policy":
                if count != 1 or data["profile"] != 7 or data["genesis"] != REGTEST_GENESIS:
                    raise ValueError("capture policy mismatch")
                mode, difficulty = data["mode"], data["transport_difficulty"]
                if (mode, difficulty) not in (("hardware", 4096), ("software", None)):
                    raise ValueError("capture transport policy mismatch")
                policy = data
            elif mode is None:
                raise ValueError("capture policy required before evidence")
            elif kind == "rpc":
                method, params = data["method"], data["params"]
                if method not in RPC_METHODS or type(params) is not list:
                    raise ValueError("capture RPC is outside replay scope")
                result = rpc(method, *params)
                # Native validation binds exact proof/template, context and pool;
                # operational cache/accounting diagnostics are not an oracle.
                expected = data["result"]
                if method == "submitblock":
                    if result != expected:
                        raise ValueError("captured native block did not validate independently")
                    blocks += int(result is None)
                elif isinstance(expected, dict):
                    for key in ("hash", "valid", "native_tip", "template_id", "proof_id", "pool", "payout_script",
                                "origin_height", "native_parent"):
                        if key in expected and result.get(key) != expected[key]:
                            raise ValueError("native replay response binding mismatch")
                    if method.startswith("validatesharepool") and (expected.get("valid") is not True or result.get("valid") is not True):
                        raise ValueError("capture claims invalid native work")
                    if method == "validatesharepoolhashshare":
                        validated_proofs.add(result["proof_id"])
                    elif method == "validatesharepoolhashtemplate":
                        validated_templates.add(params[0])
                else:
                    raise ValueError("capture native response shape mismatch")
                calls += 1
            elif kind == "job":
                block_raw, snapshot_raw = bytes.fromhex(data["block"]), bytes.fromhex(data["snapshot"])
                block, snapshot = parse_block(block_raw), Snapshot.deserialize(snapshot_raw)
                template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize_with_witness(),
                    tuple(tx.serialize_with_witness() for tx in block.vtx[1:]), block.m_mm_rhs.to_bytes(32, "little"),
                    4_000_000, 4_000_000)
                if (snapshot.envelope.version != 7 or snapshot.hash != block.m_mm_rhs or
                        snapshot.job_commitment != job_hash(block) or template.block() != block_raw or
                        snapshot.envelope.pool != policy["pool"] or snapshot.envelope.payout_script.hex() != policy["payout_script"] or
                        snapshot.envelope.public_key.hex() != policy["public_key"] or data["block"] not in validated_templates or
                        template.job_id != data["job_id"] or not verify_schnorr(snapshot.envelope.public_key,
                            snapshot.owner_signature, snapshot.owner_message)):
                    raise ValueError("captured exact job/snapshot/signature binding failed")
                if template.job_id in jobs or len(jobs) >= 32:
                    raise ValueError("capture job identity/count budget")
                jobs[template.job_id] = template, snapshot
                # This finite one-owner fixture uses coinbase-only blocks.
                # Check actual script/amount bytes in addition to native replay.
                if (len(block.vtx) != 1 or len(snapshot.payouts) != 1 or
                        bytes(snapshot.payouts[0].scriptPubKey).hex() != policy["payout_script"] or
                        snapshot.payouts[0].nValue != 5_000_000_000 or
                        block.vtx[0].vout[0].serialize() != snapshot.payouts[0].serialize()):
                    raise ValueError("captured actual coinbase payout mismatch")
            elif kind == "proof":
                params = submission_params(data)
                template, snapshot = jobs[data["job_id"]]
                proof = proof_from_sia(template, bytes.fromhex(data["prefix"]), bytes.fromhex(params[2]),
                                       params[3], params[4])
                share = parse_share(bytes.fromhex(data["share"]))
                if (proof.header != share.header_bytes or proof.work.hex() != data["work"] or
                        proof.block.hex() != data["block"] or proof.display_hash != data["hash"] or
                        share.envelope != snapshot.envelope or share.owner_signature != snapshot.owner_signature or
                        proof.display_hash not in validated_proofs or
                        proof.hash_int > transport_target(share_target(template.header.nBits, 7), difficulty) or
                        proof.display_hash in proofs or len(proofs) >= 64):
                    raise ValueError("ASIC/header proof reconstruction or target mismatch")
                proofs.add(proof.display_hash)
                proof_blocks[proof.display_hash] = proof.block
            elif kind == "complete":
                complete = data
            else:
                raise ValueError("unknown capture record")
    if (complete is None or not jobs or len(proofs) < 2 or blocks < 2 or rpc("getblockcount") < 2 or
            (complete["height"], complete["tip"]) != (rpc("getblockcount"), rpc("getbestblockhash")) or
            complete["stats"]["acknowledged"] != len(proofs) or not rpc("verifychain", 4, 0)):
        raise ValueError("insufficient independently replayed settlement evidence")
    by_hash = {snapshot.hash_hex: snapshot for unused, snapshot in jobs.values()}
    settled = set()
    for height in range(1, rpc("getblockcount") + 1):
        block_hash = rpc("getblockhash", height)
        block_raw = bytes.fromhex(rpc("getblock", block_hash, 0))
        require_captured_winner(block_hash, block_raw, proof_blocks)
        block = parse_block(block_raw)
        snapshot = by_hash[f"{block.m_mm_rhs:064x}"]
        settled.update(f"{share.proof_id:064x}" for share in snapshot.shares)
    if not settled or not settled.issubset(proofs):
        raise ValueError("winning blocks do not settle captured proof data")
    return {"jobs": len(jobs), "proofs": len(proofs), "rpc_calls": calls, "block_submissions": blocks,
            "height": rpc("getblockcount"), "tip": rpc("getbestblockhash"), "mode": mode,
            "native_chain_verified": True, "actual_coinbase_payouts_verified": True,
            "settled_proofs": len(settled), "unsettled_proofs": len(proofs - settled),
            "physical_provenance_proven_by_replay": False}
