#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded v6 Sia transport on a fresh isolated regtest node.

The caller supplies an external owner signer and owns node lifecycle and the
Goldshell restoration guard. This module never reads device credentials or
changes pools. No physical provenance is inferred from a submitted nonce.
"""
import ipaddress
import json
from pathlib import Path
import queue
import threading
import time

from hash_mining_gate import HashMiningGate
from hash_snapshot import Share, TIDES_RULES_HASH, share_target, share_work
from live_protocol import canonical
from native_enforcement import is_payout_script
from native_hardware_capture import NativeActiveJob, NativeCaptureStore, NativeHardwareCapture
from native_mining_gate import REGTEST_GENESIS
from testnet_template import TestnetTemplate, proof_from_sia
from test_framework.messages import CBlockHeader, uint256_from_compact

MAX_JOBS, MAX_PROOFS, MAX_ARCHIVE_BYTES = 32, 128, 64 * 1024 * 1024
FORMAT = "sharepool-tides-sia-capture-v6-1"


class TidesCaptureStore(NativeCaptureStore):
    def _budget(self, added):
        used = sum(self.db.execute(f"SELECT COALESCE(sum(length(data)),0) FROM {table}").fetchone()[0]
                   for table in ("jobs", "shares", "candidates", "events"))
        if added > MAX_ARCHIVE_BYTES - used:
            raise ValueError("TIDES capture archive byte limit")

    def job(self, identity, data):
        with self.lock:
            if self.db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= MAX_JOBS:
                raise ValueError("TIDES capture job limit")
            self._budget(len(canonical(data)))
            super().job(identity, data)

    def persist_native_proof(self, identity, job, data, candidate_data=None):
        with self.lock:
            self._budget(len(canonical(data)) + (len(canonical(candidate_data)) if candidate_data else 0))
            return super().persist_native_proof(identity, job, data, candidate_data)

    def event(self, kind, data):
        with self.lock:
            if self.db.execute("SELECT count(*) FROM events").fetchone()[0] >= 4096:
                raise ValueError("TIDES capture event limit")
            self._budget(len(canonical(data)))
            super().event(kind, data)

    def report(self):
        with self.lock:
            return {"format": FORMAT, "network": "regtest", "genesis": REGTEST_GENESIS,
                    "rules": f"{TIDES_RULES_HASH:064x}",
                    "jobs": [json.loads(row[0]) for row in self.db.execute("SELECT data FROM jobs ORDER BY rowid")],
                    "shares": self.snapshot(),
                    "candidates": [json.loads(row[0]) for row in self.db.execute("SELECT data FROM candidates ORDER BY rowid")],
                    "events": [{"kind": row[0], "data": json.loads(row[1])}
                               for row in self.db.execute("SELECT kind,data FROM events ORDER BY id")]}


class TidesHardwareCapture(NativeHardwareCapture):
    """Reuse only the legacy harness's transport, owner queue and lifecycle."""
    def __init__(self, rpc, store, *, gate_path, bind, miner_ip, signer, difficulty=4096):
        if type(difficulty) is not int or not 1 <= difficulty <= 1 << 24 or difficulty & (difficulty - 1):
            raise ValueError("test difficulty must be a bounded positive power of two")
        if not ipaddress.ip_address(bind[0]).is_private or not ipaddress.ip_address(miner_ip).is_private:
            raise ValueError("TIDES capture requires private test interfaces")
        if not isinstance(store, TidesCaptureStore) or not is_payout_script(signer.payout_script) or not callable(signer.sign_owner):
            raise ValueError("TIDES capture store and external owner signer required")
        if Path(gate_path).exists():
            raise ValueError("TIDES capture requires a fresh gate archive")
        self.owner_thread = threading.get_ident()
        self.rpc, self.store, self.bind, self.miner_ip, self.signer = rpc, store, bind, miner_ip, signer
        self.payout_script, self.pool, self.difficulty = signer.payout_script, signer.pool, difficulty
        self.share_target = ((1 << 224) - 1) // difficulty
        self.lock, self.rpc_lock = threading.RLock(), threading.RLock()
        self.stop, self.requests = threading.Event(), queue.Queue(maxsize=4)
        self.jobs, self.current, self.failure = {}, None, None
        self.stats = {key: 0 for key in ("accepted", "rejected", "connections", "block_candidates",
            "subscriptions", "authorizations", "notifications", "submissions", "assigned_difficulty_shares",
            "native_blocks_accepted", "old_parent_shares", "durable_acknowledgments_ready")}
        self.known, self.native_responses, self.accepted_blocks = {}, {}, {}
        self.last_tip, self.last_manifest, self.stop_reason = REGTEST_GENESIS, None, None
        self._inflight, self._gate_closed, self._admitting = None, False, False
        info, net = self._rpc("getblockchaininfo"), self._rpc("getnetworkinfo")
        profile = self._rpc("getsharepoolhashstatus")
        if (info.get("chain") != "regtest" or info.get("blocks") != 0 or
                self._rpc("getblockhash", 0) != REGTEST_GENESIS or self._rpc("getbestblockhash") != REGTEST_GENESIS or
                net.get("networkactive") is not False or net.get("connections") != 0 or
                profile.get("mode") != "hash-only-v6-tides" or profile.get("activation_height") != 1 or
                profile.get("rules") != f"{TIDES_RULES_HASH:064x}"):
            raise ValueError("TIDES capture requires a fresh isolated v6 regtest chain activated at height one")
        self.gate = HashMiningGate(gate_path, rpc=self._rpc, pool=self.pool, public_key=signer.public_key,
                                  payout_script=self.payout_script, profile_version=6)
        try:
            self.refresh()
        except BaseException:
            self.gate.close()
            self._gate_closed = True
            raise

    def _rpc(self, method, *params):
        self._owner()
        result = self.rpc(method, *params)
        if method == "validatesharepoolhashshare" and isinstance(result, dict):
            self.native_responses[result.get("proof_id")] = result
        return result

    def refresh(self):
        self._owner()
        if len(self.jobs) >= MAX_JOBS:
            self.stop_reason = "job_limit"
            self.stop.set()
            return False
        block, snapshot = self.gate.make_native(sign_owner=self.signer.sign_owner)
        if (not block.m_header_v2 or block.m_flags or block.m_xor_key or block.m_xor_key_mask_clear_bits or
                block.m_time_offset or block.m_nonce3 or len(block.vtx) != 1):
            raise ValueError("TIDES hardware fixture requires unmasked coinbase-only native jobs")
        raw = block.serialize()
        template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize(), (),
                                  snapshot.hash.to_bytes(32, "little"), 4_000_000, 4_000_000)
        if template.block() != raw:
            raise ValueError("Sia transport changes the exact native job")
        authorization = self.gate.authorize(raw, snapshot.serialize())
        self.gate.register_snapshot(snapshot.serialize())
        if not self.gate.ready_for_dispatch(authorization):
            raise ValueError("TIDES job changed before dispatch")
        with self.lock:
            if self.current and template.job_id == self.current.template.job_id:
                return True
            clean = self.current is None or authorization.native_parent != self.current.authorization.native_parent
            active = NativeActiveJob(template, snapshot, authorization, time.monotonic(), clean)
            self.store.job(template.job_id, {"job_id": template.job_id, "block": raw.hex(),
                "snapshot": snapshot.serialize().hex(), "height": block.m_height,
                "native_parent": authorization.native_parent, "commitment": snapshot.hash_hex,
                "included_proofs": [f"{proof.proof_id:064x}" for proof in snapshot.shares],
                "payouts": [{"script": bytes(output.scriptPubKey).hex(), "satoshis": output.nValue}
                            for output in snapshot.payouts], "receipt_sequence": authorization.receipt_sequence})
            self.jobs[template.job_id], self.current = active, active
        self.native_share_target = share_target(block.nBits, 6)
        return True

    def _process_proof(self, prefix, params):
        self._owner()
        if self.stats["accepted"] >= MAX_PROOFS:
            raise ValueError("TIDES proof capture limit")
        active = self.jobs.get(params[1])
        if active is None or time.monotonic() - active.issued > 180:
            raise ValueError("unknown or expired TIDES hardware job")
        proof = proof_from_sia(active.template, prefix, bytes.fromhex(params[2]), params[3], params[4])
        native_candidate = proof.hash_int <= uint256_from_compact(active.template.header.nBits)
        assigned = proof.hash_int <= self.share_target
        if (not assigned and not native_candidate) or proof.hash_int > share_target(active.template.header.nBits, 6):
            raise ValueError("insufficient assigned or native candidate work")
        if self.store.has_proof(proof.display_hash):
            raise ValueError("duplicate TIDES hardware proof")
        if active.authorization.block_for_header(proof.header) != proof.block:
            raise ValueError("hardware work changes the authorized job")
        share = Share(proof.header, active.manifest.envelope, active.manifest.owner_signature)
        self.gate.receive(share)
        self._admitting = True
        response = self.native_responses.get(proof.display_hash)
        if not response or response.get("valid") is not True:
            raise ValueError("missing native TIDES proof validation")
        current = self._rpc("getbestblockhash") == active.authorization.native_parent
        row = {"hash": proof.display_hash, "job_id": active.template.job_id, "header": proof.header.hex(),
            "block": proof.block.hex(), "work_header": proof.work.hex(), "share_wire": share.serialize().hex(),
            "prefix": prefix.hex(), "extranonce2": params[2], "ntime": params[3], "nonce": params[4],
            "native_share_response": response, "native_expected_work": share_work(share.header.nBits, 6),
            "assigned_target": f"{self.share_target:064x}", "meets_assigned_target": assigned,
            "native_target_solution": native_candidate, "parent_current_at_admission": current}
        candidate = {"hash": proof.display_hash, "job_id": active.template.job_id,
                     "block": proof.block.hex()} if native_candidate and current else None
        self.store.persist_native_proof(proof.display_hash, active.template.job_id, row, candidate)
        self.known[proof.display_hash] = share
        self.stats["accepted"] += 1
        self.stats["assigned_difficulty_shares"] += int(assigned)
        self.stats["block_candidates"] += int(native_candidate)
        self.stats["old_parent_shares"] += int(not current)
        if candidate:
            if self._rpc("getbestblockhash") != active.authorization.native_parent:
                raise RuntimeError("native tip changed before TIDES candidate submission")
            result = self._rpc("submitblock", proof.block.hex())
            self.store.event("native_block_submission", {"hash": proof.display_hash, "result": result})
            if result is not None or self._rpc("getbestblockhash") != proof.display_hash:
                raise RuntimeError("native node rejected the TIDES candidate")
            self.last_tip = proof.display_hash
            self.accepted_blocks[proof.display_hash] = {"parent": active.authorization.native_parent,
                                                       "job_id": active.template.job_id}
            self.stats["native_blocks_accepted"] += 1
            self.store.event("native_block_accepted", {"hash": proof.display_hash, "job_id": active.template.job_id,
                                                      "height": share.envelope.height})
        self.refresh()
        self.stats["durable_acknowledgments_ready"] += 1
        self._admitting = False
        return True

    def run(self, seconds=90):
        if type(seconds) not in (int, float) or not 0 < seconds <= 90:
            raise ValueError("TIDES hardware test duration must be at most 90 seconds")
        return super().run(seconds)

    def report(self):
        self._owner()
        result = self.store.report()
        admitted = {f"{share.proof_id:064x}" for entry in self.accepted_blocks.values()
                    for share in self.jobs[entry["job_id"]].manifest.shares}
        result.update(stats=dict(self.stats), failure=self.failure,
            stop_reason=self.stop_reason or "duration_or_caller_stop", last_native_tip=self.last_tip,
            pool=f"{self.pool:064x}", payout_script=self.payout_script.hex(), difficulty=self.difficulty,
            unanchored_proofs=sorted(set(self.known) - admitted),
            scope="Sia input capture with native v6 regtest validation; physical provenance is external evidence.")
        return result
