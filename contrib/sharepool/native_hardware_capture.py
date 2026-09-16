#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded physical Sia test of native SPN1 consensus on isolated regtest.

The caller owns node startup, a bounded RPC transport, and miner restoration.
A public fixture key is used only after the native regtest/profile guards pass.
All gate/RPC work runs on the constructing thread; Stratum threads only enqueue
bounded requests. This is a test instrument, not a production mining service.
"""
from dataclasses import dataclass, field
import ipaddress
import json
import queue
import threading
import time

from live_protocol import canonical
from native_enforcement import (MAX_SHARE_AGE, MAX_SHARES, SHARE_BITS, Share,
    candidate, is_payout_script, parse_coinbase)
from native_mining_gate import NativeMiningGate, REGTEST_GENESIS, parse_block, parse_share
from testnet_hardware_capture import CaptureStore, HardwareCapture
from testnet_template import TestnetTemplate, proof_from_sia
from test_framework.key import compute_xonly_pubkey
from test_framework.messages import CBlockHeader, uint256_from_compact

MAX_CAPTURE_JOBS = 32
MAX_CAPTURE_PROOFS = 128
FIXTURE_SECRET = (1).to_bytes(32, "big")


class NativeCaptureStore(CaptureStore):
    """The inherited store provides bounded sessions and thread-safe events."""
    def has_proof(self, identity):
        with self.lock:
            return self.db.execute("SELECT 1 FROM shares WHERE hash=?", (identity,)).fetchone() is not None

    def persist_native_proof(self, identity, job, data, candidate_data=None):
        # An already-durable gate receipt may be retried after an archive write
        # failure. Completing the second store is safe and must remain possible.
        encoded = canonical(data).decode()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            saved = self.db.execute("SELECT job,data FROM shares WHERE hash=?", (identity,)).fetchone()
            if saved:
                if saved != (job, encoded):
                    raise ValueError("proof archive retry changes its metadata")
                return False
            if self.db.execute("SELECT count(*) FROM shares").fetchone()[0] >= MAX_CAPTURE_PROOFS:
                raise ValueError("native proof archive is full")
            self.db.execute("INSERT INTO shares VALUES (?,?,?)", (identity, job, encoded))
            if candidate_data is not None:
                self.db.execute("INSERT INTO candidates VALUES (?,?)", (identity, canonical(candidate_data).decode()))
            return True

    def report(self):
        with self.lock:
            return {"format": "sharepool-native-hardware-spn1-v1", "network": "regtest",
                    "genesis": REGTEST_GENESIS, "native_settlement_profile": "SPN1",
                    "native_share_bits": f"{SHARE_BITS:08x}",
                    "jobs": [json.loads(r[0]) for r in self.db.execute("SELECT data FROM jobs ORDER BY rowid")],
                    "shares": self.snapshot(),
                    "candidates": [json.loads(r[0]) for r in self.db.execute("SELECT data FROM candidates ORDER BY rowid")],
                    "events": [{"kind": r[0], "data": json.loads(r[1])}
                               for r in self.db.execute("SELECT kind,data FROM events ORDER BY id")]}


@dataclass(frozen=True)
class NativeActiveJob:
    template: object
    manifest: object
    authorization: object
    issued: float
    clean: bool


@dataclass
class Request:
    kind: str
    payload: object
    done: object = field(default_factory=threading.Event)
    cancelled: object = field(default_factory=threading.Event)
    result: object = None
    error: object = None


class NativeHardwareCapture(HardwareCapture):
    def __init__(self, rpc, store, *, gate_path, bind, miner_ip, payout_script,
                 difficulty=4096, pool=0xabc123):
        # Deliberately do not call the Testnet4-only parent constructor.
        if type(difficulty) is not int or not 1 <= difficulty <= (1 << 24) or difficulty & (difficulty - 1):
            raise ValueError("test difficulty must be a bounded positive power of two")
        if (not ipaddress.ip_address(bind[0]).is_private or
                not ipaddress.ip_address(miner_ip).is_private):
            raise ValueError("native hardware capture requires private test interfaces")
        if not isinstance(store, NativeCaptureStore) or not is_payout_script(payout_script):
            raise ValueError("native capture store and exact standard payout script required")
        self.owner_thread = threading.get_ident()
        self.rpc, self.store, self.bind, self.miner_ip = rpc, store, bind, miner_ip
        self.payout_script, self.pool, self.difficulty = payout_script, pool, difficulty
        self.share_target = ((1 << 224) - 1) // difficulty
        self.native_share_target = uint256_from_compact(SHARE_BITS)
        self.lock, self.rpc_lock = threading.RLock(), threading.RLock()
        self.stop = threading.Event()
        self.requests = queue.Queue(maxsize=4)
        self.jobs, self.current, self.failure = {}, None, None
        self.stats = {"accepted": 0, "rejected": 0, "connections": 0, "block_candidates": 0,
                      "subscriptions": 0, "authorizations": 0, "notifications": 0, "submissions": 0,
                      "assigned_difficulty_shares": 0, "native_blocks_accepted": 0,
                      "old_parent_shares": 0, "durable_acknowledgments_ready": 0}
        self.known, self.native_responses, self.accepted_blocks = {}, {}, {}
        self.last_tip, self.last_manifest, self.stop_reason = None, None, None
        self._inflight, self._gate_closed, self._admitting = None, False, False
        info = self._rpc("getblockchaininfo")
        if info.get("chain") != "regtest" or self._rpc("getblockhash", 0) != REGTEST_GENESIS:
            raise ValueError("native hardware capture is restricted to regtest")
        net = self._rpc("getnetworkinfo")
        if net.get("networkactive") is not False or net.get("connections") != 0:
            raise ValueError("native hardware test requires isolated disabled P2P networking")
        from pathlib import Path
        if Path(gate_path).exists():
            raise ValueError("hardware test requires a fresh native gate store")
        self.gate = NativeMiningGate(gate_path, rpc=self._rpc, pool=pool,
            public_key=compute_xonly_pubkey(FIXTURE_SECRET)[0], payout_script=payout_script)
        try:
            self.refresh()
        except Exception:
            self.gate.close()
            self._gate_closed = True
            raise

    def _owner(self):
        if threading.get_ident() != self.owner_thread:
            raise RuntimeError("native gate operation must run on its owner thread")

    def _rpc(self, method, *params):
        self._owner()
        result = self.rpc(method, *params)
        if method == "validatesharepoolshare" and isinstance(result, dict):
            self.native_responses[result.get("proof_id")] = result
        return result

    def _eligible(self, height, parent_manifest, activation):
        paid = set() if parent_manifest is None else {e.proof_id for e in parent_manifest.post_state}
        result, ancestors = [], {}
        # Read the gate's durable receipts, including any partial archive write.
        for identity, raw in self.gate.db.execute("SELECT proof_id,data FROM receipts ORDER BY sequence"):
            share = parse_share(bytes(raw))
            if identity != f"{share.proof_id:064x}":
                raise ValueError("native receipt identity mismatch")
            origin = share.envelope.height
            if not max(activation, height - MAX_SHARE_AGE) <= origin <= height or share.proof_id in paid:
                continue
            if origin not in ancestors:
                ancestors[origin] = self._rpc("getblockhash", origin - 1)
            if ancestors[origin] == f"{share.header.hashPrevBlock:064x}":
                result.append(share)
        if len(result) > MAX_SHARES:
            raise ValueError("all known eligible work exceeds one native manifest")
        return tuple(sorted(result, key=lambda share: share.proof_id))

    def refresh(self):
        self._owner()
        if len(self.jobs) >= MAX_CAPTURE_JOBS:
            self.stop_reason = "job_limit"
            self.stop.set()
            return False
        gbt = self.gate.base_template()
        if gbt.get("transactions") != []:
            raise ValueError("isolated native hardware fixture requires an empty transaction template")
        height, parent = gbt["height"], gbt["previousblockhash"]
        if type(height) is not int or not 1 <= height < 0x7fffffff:
            raise ValueError("invalid native height")
        halvings = height // 150
        reward = (50 * 100_000_000) >> halvings if halvings < 64 else 0
        if gbt.get("coinbasevalue") != reward:
            raise ValueError("isolated regtest template reward is not the exact subsidy")
        if ("!blake2b" not in gbt.get("rules", []) or "!sharepool" not in gbt.get("rules", []) or
                int(gbt["bits"], 16) != SHARE_BITS or gbt["version"] & 0xE0000000 != 0xA0000000 or
                gbt["curtime"] < gbt["mintime"]):
            raise ValueError("unsupported native hardware GBT profile")
        activation = gbt["sharepool"]["activation_height"]
        parent_manifest = None
        if height > activation:
            parent_block = parse_block(bytes.fromhex(self._rpc("getblock", parent, 0)))
            parent_manifest, unused = parse_coinbase(parent_block.vtx[0])
            if f"{parent_block.rehash():064x}" != parent:
                raise ValueError("native parent body hash mismatch")
        shares = self._eligible(height, parent_manifest, activation)
        block, manifest = candidate(genesis=int(REGTEST_GENESIS, 16), native_parent=int(parent, 16),
            height=height, ntime=gbt["curtime"], pool=self.pool, secret=FIXTURE_SECRET,
            payout_script=self.payout_script, shares=shares, parent_manifest=parent_manifest,
            witness="default_witness_commitment" in gbt)
        block.nVersion, block.nBits = gbt["version"] & 0x7fffffff, int(gbt["bits"], 16)
        block.rehash()
        template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize(), (),
            manifest.envelope.root.to_bytes(32, "little"), gbt["weightlimit"], gbt["sizelimit"])
        raw = block.serialize()
        if template.block() != raw:
            raise ValueError("Sia wrapper changes the completed native block")
        authorization = self.gate.authorize(raw)
        if not self.gate.ready_for_dispatch(authorization):
            raise ValueError("native job is stale before initial dispatch")
        with self.lock:
            if self.current and template.job_id == self.current.template.job_id:
                return True
            clean = self.current is None or parent != self.current.authorization.native_parent
            active = NativeActiveJob(template, manifest, authorization, time.monotonic(), clean)
            self.store.job(template.job_id, {"job_id": template.job_id, "gbt": gbt,
                "header": template.header_bytes.hex(), "coinbase": template.coinbase.hex(),
                "block": raw.hex(), "manifest": manifest.serialize().hex(),
                "commitment": f"{manifest.envelope.root:064x}", "native_parent": parent,
                "height": height, "included_proofs": [f"{s.proof_id:064x}" for s in shares],
                "payouts": [{"script": bytes(o.scriptPubKey).hex(), "satoshis": o.nValue}
                            for o in parse_coinbase(block.vtx[0])[1]],
                "native_proposal_result": None, "native_gate_authorized": True,
                "receipt_sequence": authorization.receipt_sequence,
                "assigned_target": f"{self.share_target:064x}"})
            self.jobs[template.job_id], self.current = active, active
        self.last_tip, self.last_manifest = parent, parent_manifest
        return True

    def _enqueue(self, kind, payload):
        if self.stop.is_set():
            raise RuntimeError("native hardware capture is stopping")
        request = Request(kind, payload)
        try:
            self.requests.put_nowait(request)
        except queue.Full:
            raise RuntimeError("native owner-thread request queue is full") from None
        if not request.done.wait(30):
            request.cancelled.set()
            raise RuntimeError("native owner-thread request timed out")
        if request.error is not None:
            raise request.error
        return request.result

    def prepare_dispatch(self, active):
        # Called by the inherited Stratum handler immediately before notify.
        try:
            return self._enqueue("dispatch", active)
        except RuntimeError:
            return False

    def submit(self, prefix, params, authorized_user):
        if (type(params) is not list or len(params) != 5 or
                any(type(v) is not str or len(v) > 256 for v in params) or params[0] != authorized_user):
            raise ValueError("invalid authenticated share parameters")
        return self._enqueue("submit", (prefix, list(params)))

    def _process_proof(self, prefix, params):
        self._owner()
        if self.stats["accepted"] >= MAX_CAPTURE_PROOFS:
            raise ValueError("native proof capture limit")
        active = self.jobs.get(params[1])
        if active is None or time.monotonic() - active.issued > 180:
            raise ValueError("unknown or expired native hardware job")
        proof = proof_from_sia(active.template, prefix, bytes.fromhex(params[2]), params[3], params[4])
        native_candidate = proof.hash_int <= uint256_from_compact(active.template.header.nBits)
        assigned = proof.hash_int <= self.share_target
        if not assigned and not native_candidate:
            raise ValueError("insufficient assigned or native candidate work")
        if proof.hash_int > self.native_share_target:
            raise ValueError("insufficient native share work")
        if self.store.has_proof(proof.display_hash):
            raise ValueError("duplicate native hardware proof")
        share = Share(proof.header, active.manifest.envelope, active.manifest.owner_signature)
        if active.authorization.block_for_header(proof.header) != proof.block:
            raise ValueError("hardware proof changed the authorized block")
        # This can return False after a previous archive write failed. The
        # same native receipt remains valid; finish its missing artifact.
        self.gate.receive(share.serialize())
        self._admitting = True
        native_response = self.native_responses.get(proof.display_hash)
        if native_response is None or native_response.get("valid") is not True:
            raise ValueError("missing native share acceptance evidence")
        parent_current = self._rpc("getbestblockhash") == active.authorization.native_parent
        row = {"hash": proof.display_hash, "job_id": active.template.job_id,
               "header": proof.header.hex(), "block": proof.block.hex(), "work_header": proof.work.hex(),
               "share_wire": share.serialize().hex(), "prefix": prefix.hex(),
               "extranonce2": params[2], "ntime": params[3], "nonce": params[4],
               "native_share_response": native_response, "native_share_bits": f"{SHARE_BITS:08x}",
               "native_expected_work": (1 << 256) // (self.native_share_target + 1),
               "assigned_target": f"{self.share_target:064x}", "meets_assigned_target": assigned,
               "native_target_solution": native_candidate, "parent_current_at_admission": parent_current}
        candidate_data = {"hash": proof.display_hash, "job_id": active.template.job_id,
                          "block": proof.block.hex()} if native_candidate and parent_current else None
        self.store.persist_native_proof(proof.display_hash, active.template.job_id, row, candidate_data)
        self.known[proof.display_hash] = share
        self.stats["accepted"] += 1
        self.stats["assigned_difficulty_shares"] += int(assigned)
        self.stats["block_candidates"] += int(native_candidate)
        self.stats["old_parent_shares"] += int(not parent_current)
        if native_candidate and parent_current:
            # Recheck after durable archival. Never submit an old-parent block
            # and describe its storage as acceptance onto the best chain.
            if self._rpc("getbestblockhash") != active.authorization.native_parent:
                raise RuntimeError("native tip changed before candidate submission")
            result = self._rpc("submitblock", proof.block.hex())
            self.store.event("native_block_submission", {"hash": proof.display_hash, "result": result})
            if result is not None:
                raise RuntimeError("native node rejected the hardware block candidate")
            header = self._rpc("getblockheader", proof.display_hash)
            if (header.get("hash") != proof.display_hash or header.get("height") != share.envelope.height or
                    self._rpc("getbestblockhash") != proof.display_hash):
                raise RuntimeError("native candidate did not become the verified best block")
            self.last_tip, self.last_manifest = proof.display_hash, active.manifest
            self.accepted_blocks[proof.display_hash] = {
                "parent": active.authorization.native_parent,
                "proofs": {f"{s.proof_id:064x}" for s in active.manifest.shares}}
            self.stats["native_blocks_accepted"] += 1
            self.store.event("native_block_accepted", {"hash": proof.display_hash,
                "height": header["height"], "commitment": f"{active.manifest.envelope.root:064x}",
                "included_proofs": [f"{s.proof_id:064x}" for s in active.manifest.shares]})
        elif native_candidate:
            self.store.event("native_old_parent_proof", {"hash": proof.display_hash, "submitted": False})
        self.refresh()  # Every newly known eligible proof must be in the next job.
        self.stats["durable_acknowledgments_ready"] += 1
        self._admitting = False
        return True

    def _handle(self, request):
        if request.cancelled.is_set() or self.stop.is_set():
            request.error = RuntimeError("native hardware request cancelled")
            request.done.set()
            return
        self._inflight = request
        try:
            if request.kind == "submit":
                request.result = self._process_proof(*request.payload)
            else:
                active = request.payload
                with self.lock:
                    current = self.current
                request.result = active is current and self.gate.ready_for_dispatch(active.authorization)
                if active is current and not request.result:
                    self.refresh()
        except ValueError as error:
            request.error = error
            if self._admitting:
                self.failure = "post_receipt_validation_failure"
                self.stop.set()
        except RuntimeError as error:
            self.failure = "native_processing_failure"
            request.error = error
            self.stop.set()
        except Exception as error:
            self.failure = type(error).__name__
            request.error = RuntimeError("native hardware processing failed: " + self.failure)
            self.stop.set()
        except BaseException:
            self.failure = "owner_thread_interrupted"
            request.error = RuntimeError("native hardware owner thread interrupted")
            self.stop.set()
            raise
        finally:
            request.done.set()
            self._inflight = None

    def _cancel_pending(self):
        while True:
            try:
                request = self.requests.get_nowait()
            except queue.Empty:
                return
            request.error = RuntimeError("native hardware capture closed")
            request.done.set()

    def start(self):
        self._owner()
        return super().start()

    def run(self, seconds=90):
        self._owner()
        if type(seconds) not in (int, float) or not 0 < seconds <= 180:
            raise ValueError("hardware test duration must be at most 180 seconds")
        until, next_check = time.monotonic() + seconds, time.monotonic() + 1
        try:
            while time.monotonic() < until and not self.stop.is_set():
                try:
                    request = self.requests.get(timeout=min(0.25, max(0, until - time.monotonic())))
                except queue.Empty:
                    request = None
                if request is not None:
                    self._handle(request)
                if time.monotonic() >= next_check and not self.stop.is_set():
                    if self.gate.needs_refresh(self.current.authorization):
                        self.refresh()
                    next_check = time.monotonic() + 1
        finally:
            self.stop.set()
            self._cancel_pending()
        if self.failure is not None:
            raise RuntimeError("native hardware capture failed: " + self.failure)
        return dict(self.stats)

    def close(self):
        self._owner()
        self.stop.set()
        self._cancel_pending()
        super().close()
        if not self._gate_closed:
            self.gate.close()
            self._gate_closed = True

    def report(self):
        self._owner()
        result = self.store.report()
        # Nullifiers expire after four origin heights; historical payments do
        # not. Walk the captured canonical parent chain and union settlements.
        paid, cursor = set(), self.last_tip
        while cursor in self.accepted_blocks:
            entry = self.accepted_blocks[cursor]
            paid.update(entry["proofs"])
            cursor = entry["parent"]
        result.update({"stats": dict(self.stats), "failure": self.failure,
            "stop_reason": self.stop_reason or "duration_or_caller_stop", "last_native_tip": self.last_tip,
            "fixture_key": "public regtest-only scalar 1", "pool": f"{self.pool:064x}",
            "payout_script": self.payout_script.hex(), "difficulty": self.difficulty,
            "pending_proofs": sorted(set(self.known) - paid),
            "pending_explanation": "The winning proof is created after its immutable commitment and is eligible for a later block; the final winner normally remains pending.",
            "scope": "Physical ASIC input capture with native SPN1 regtest validation; no public-network activation."})
        return result
