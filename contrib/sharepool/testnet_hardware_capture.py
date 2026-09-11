#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded testnet4-only physical Sia/Goldshell commitment capture.

This is a hardware integration test, not pool consensus or a public pool daemon.
It preserves full GBT transactions, verifies native reconstructed PoW, commits
previously captured work, and fsyncs SQLite acceptance before acknowledging it.
An external guarded runner owns temporary pool configuration and restoration.
"""
import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time

from base_chain_settlement import NativeRPCError, SettlementCommitment
from live_protocol import canonical, decode_coinbase
from precommit_demo import uint256_from_compact
from settlement_sim import merkle_root
from testnet_template import build_template, sia_notify, proof_from_sia


TESTNET4_GENESIS = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
MAX_LINE = 8192
MAX_SHARES = 4096


class NodeRPC:
    def __init__(self, cli, datadir, timeout=20):
        self.args = [str(cli), "-datadir=" + str(datadir), "-chain=testnet4"]
        self.timeout = timeout

    def __call__(self, method, *params):
        allowed = {"getblockchaininfo", "getblockhash", "getbestblockhash", "getnetworkinfo", "getblocktemplate",
                   "getblockheader", "getblock", "submitblock"}
        if method not in allowed:
            raise ValueError("RPC outside hardware test scope")
        raw = "\n".join(p if isinstance(p, str) else json.dumps(p, separators=(",", ":"))
                        for p in params)
        result = subprocess.run(self.args + ["-stdin", method], input=raw + "\n" if params else "",
                                text=True, capture_output=True, timeout=self.timeout)
        if result.returncode:
            code = re.search(r"error code:\s*(-?\d+)", result.stderr)
            if code:
                number = int(code.group(1))
                message = "testnet RPC rejected " + method
                # Preserve only these fixed native availability descriptions;
                # arbitrary RPC text can include sensitive request information.
                unavailable = re.search(r"error message:\s*(Block not available \((?:pruned data|not fully downloaded)\))\s*$",
                                        result.stderr)
                if number == -1 and method == "getblock" and unavailable:
                    message = unavailable.group(1)
                raise NativeRPCError(number, message)
            raise RuntimeError("testnet RPC failed: " + method + ": " + result.stderr.strip()[:500])
        try:
            return json.loads(result.stdout)
        except ValueError:
            return result.stdout.strip() or None

    def check_testnet(self):
        info = self("getblockchaininfo")
        if info.get("chain") != "testnet4" or self("getblockhash", 0) != TESTNET4_GENESIS:
            raise ValueError("hardware runner requires exact testnet4 network and genesis")
        if info.get("initialblockdownload"):
            raise ValueError("testnet node is still synchronizing")
        return info


class CaptureStore:
    def __init__(self, path):
        self.path = Path(path)
        # A test run cannot accidentally resume or overwrite another capture.
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE jobs(id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE shares(hash TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES jobs(id), data TEXT NOT NULL);
            CREATE TABLE sessions(id INTEGER PRIMARY KEY AUTOINCREMENT);
            CREATE TABLE candidates(hash TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL);
        """)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.commit()
        self.lock = threading.RLock()

    def prefix(self):
        with self.lock, self.db:
            value = self.db.execute("INSERT INTO sessions DEFAULT VALUES").lastrowid
            return value.to_bytes(4, "little")

    def job(self, identity, data):
        with self.lock, self.db:
            self.db.execute("INSERT INTO jobs VALUES (?, ?)", (identity, canonical(data).decode()))

    def share(self, identity, job, data):
        self.record_proof(identity, job, share=data)

    def record_proof(self, identity, job, *, share=None, candidate=None):
        """Commit all proof artifacts together before acknowledging acceptance."""
        if share is None and candidate is None:
            raise ValueError("proof admission requires a share or candidate")
        share_json = canonical(share).decode() if share is not None else None
        candidate_json = canonical(candidate).decode() if candidate is not None else None
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT 1 FROM jobs WHERE id=?", (job,)).fetchone() is None:
                raise ValueError("missing job for proof admission")
            if share is not None and self.db.execute("SELECT count(*) FROM shares").fetchone()[0] >= MAX_SHARES:
                raise ValueError("bounded capture share limit")
            if candidate is not None and self.db.execute("SELECT count(*) FROM candidates").fetchone()[0] >= 64:
                raise ValueError("bounded capture candidate limit")
            try:
                if share is not None:
                    self.db.execute("INSERT INTO shares VALUES (?, ?, ?)", (identity, job, share_json))
                if candidate is not None:
                    self.db.execute("INSERT INTO candidates VALUES (?, ?)", (identity, candidate_json))
            except sqlite3.IntegrityError as error:
                raise ValueError("duplicate share/candidate or rejected proof insert") from error

    def event(self, kind, data):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events(kind,data) VALUES (?,?)", (kind, canonical(data).decode()))

    def candidate(self, identity, data):
        try:
            job = data["proof"]["job_id"]
        except (KeyError, TypeError) as error:
            raise ValueError("candidate must reference its saved job") from error
        self.record_proof(identity, job, candidate=data)

    def snapshot(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT data FROM shares ORDER BY hash")]

    def report(self):
        with self.lock:
            return {"format": 1, "network": "testnet4", "genesis": TESTNET4_GENESIS,
                    "jobs": [json.loads(r[0]) for r in self.db.execute("SELECT data FROM jobs ORDER BY rowid")],
                    "shares": self.snapshot(),
                    "candidates": [json.loads(r[0]) for r in self.db.execute("SELECT data FROM candidates ORDER BY hash")],
                    "events": [{"kind": r[0], "data": json.loads(r[1])}
                               for r in self.db.execute("SELECT kind,data FROM events ORDER BY id")]}

    def close(self):
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.close()


@dataclass(frozen=True)
class ActiveJob:
    template: object
    envelope: object
    issued: float
    clean: bool


class HardwareCapture:
    def __init__(self, rpc, store, *, bind, miner_ip, difficulty=4096,
                 payout_script, submit_blocks=False):
        if type(difficulty) is not int or difficulty < 1 or difficulty > (1 << 24) or difficulty & (difficulty - 1):
            raise ValueError("test difficulty must be a bounded positive power of two")
        if not ipaddress.ip_address(bind[0]).is_private or not ipaddress.ip_address(miner_ip).is_private:
            raise ValueError("hardware capture requires private test interfaces")
        rpc.check_testnet()
        self.rpc, self.store, self.bind, self.miner_ip = rpc, store, bind, miner_ip
        self.difficulty = difficulty
        self.share_target = ((1 << 224) - 1) // difficulty
        self.work = (1 << 256) // (self.share_target + 1)
        self.payout_script, self.submit_blocks = payout_script, submit_blocks
        self.lock, self.rpc_lock = threading.RLock(), threading.RLock()
        self.jobs, self.current = {}, None
        self.stop = threading.Event()
        self.failure = None
        self.stats = {"accepted": 0, "rejected": 0, "connections": 0, "block_candidates": 0,
                      "subscriptions": 0, "authorizations": 0, "notifications": 0, "submissions": 0}
        self.rules = {"format": "sharepool-hardware-capture-v1", "genesis": TESTNET4_GENESIS,
                      "share_target": f"{self.share_target:064x}", "payout_script": payout_script.hex(),
                      "snapshot_basis": "previously-native-hash-verified-captured-shares"}
        self.rules_root = hashlib.sha256(canonical(self.rules)).hexdigest()
        self.refresh()

    def refresh(self):
        with self.rpc_lock:
            self.rpc.check_testnet()
            gbt = self.rpc("getblocktemplate", {"rules": ["segwit", "blake2b"]})
        snapshot = self.store.snapshot()
        snapshot_root = merkle_root([canonical(row) for row in snapshot])
        outputs = [(self.payout_script.hex(), gbt["coinbasevalue"])]
        if gbt.get("default_witness_commitment"):
            outputs.append((gbt["default_witness_commitment"], 0))
        envelope = SettlementCommitment.create(network_genesis=TESTNET4_GENESIS, pool_id=b"sharepool-testnet",
                    rules_root=self.rules_root, snapshot_root=snapshot_root.hex(),
                    base_parent=gbt["previousblockhash"], payouts=outputs)
        template = build_template(gbt, [(self.payout_script, gbt["coinbasevalue"])],
                                  envelope.root, b"SharepoolGoldshellTest", chain="testnet4")
        actual = [(bytes(o.scriptPubKey).hex(), o.nValue) for o in decode_coinbase(template.coinbase).vout]
        if actual != outputs:
            raise ValueError("native template payout/witness outputs differ from commitment")
        with self.rpc_lock:
            proposal = self.rpc("getblocktemplate", {"mode": "proposal", "rules": ["segwit", "blake2b"],
                                                    "data": template.block(template.header.serialize()).hex()})
        if proposal is not None:
            raise ValueError("native node rejected hardware template proposal: " + str(proposal))
        with self.lock:
            if self.current and template.job_id == self.current.template.job_id:
                return
            if len(self.jobs) >= 32:
                raise ValueError("bounded hardware job limit")
            clean = self.current is None or gbt["previousblockhash"] != self.current.envelope.base_parent
            active = ActiveJob(template, envelope, time.monotonic(), clean)
            self.store.job(template.job_id, {"job_id": template.job_id, "gbt": gbt,
                "header": template.header.serialize().hex(), "coinbase": template.coinbase.hex(),
                "envelope": envelope.to_object(), "snapshot": snapshot, "rules": self.rules,
                "commitment": envelope.root.hex(), "proposal_result": proposal,
                "share_target": f"{self.share_target:064x}"})
            self.jobs[template.job_id], self.current = active, active

    def submit(self, prefix, params, authorized_user):
        if (type(params) is not list or len(params) != 5 or
                any(type(v) is not str or len(v) > 256 for v in params) or params[0] != authorized_user):
            raise ValueError("invalid authenticated share parameters")
        with self.lock:
            active = self.jobs.get(params[1])
            current = self.current
        if active is None or time.monotonic() - active.issued > 180:
            raise ValueError("unknown or expired hardware job")
        proof = proof_from_sia(active.template, prefix, bytes.fromhex(params[2]), params[3], params[4])
        candidate = proof.hash_int <= uint256_from_compact(active.template.header.nBits)
        if proof.hash_int > self.share_target and not candidate:
            raise ValueError("insufficient hardware share work")
        if active.envelope.base_parent != current.envelope.base_parent and not candidate:
            raise ValueError("ordinary share for an old native parent")
        row = {"hash": proof.display_hash, "header": proof.header.hex(), "work_header": proof.work.hex(),
               "job_id": active.template.job_id, "prefix": prefix.hex(), "extranonce2": params[2],
               "ntime": params[3], "nonce": params[4], "weight": self.work,
               "share_target": f"{self.share_target:064x}", "candidate": candidate}
        # A base target can be easier than our share target on testnet. Preserve
        # that candidate but do not claim harder share work it has not proven.
        qualifies_share = proof.hash_int <= self.share_target
        candidate_data = {"proof": row, "block": proof.block.hex(),
                "envelope": active.envelope.to_object(), "commitment": active.envelope.root.hex(),
                "credited_as_share": qualifies_share} if candidate else None
        self.store.record_proof(proof.display_hash, active.template.job_id,
                                share=row if qualifies_share else None, candidate=candidate_data)
        with self.lock:
            if qualifies_share:
                self.stats["accepted"] += 1
            if candidate:
                self.stats["block_candidates"] += 1
        if candidate:
            result = "submission-disabled"
            if self.submit_blocks:
                try:
                    with self.rpc_lock:
                        self.rpc.check_testnet()
                        result = self.rpc("submitblock", proof.block.hex())
                except Exception as problem:
                    # The full candidate is durable already. A node outage
                    # cannot revoke a share acknowledgment. Explicit replay
                    # of the candidate archive is required after a failed RPC.
                    result = {"rpc_failure": type(problem).__name__}
            self.store.event("block_candidate", {"hash": proof.display_hash, "result": result,
                                                 "job_id": active.template.job_id})
        return True

    def prepare_dispatch(self, active):
        """Optional final dispatch fence; native subclasses may use an owner thread."""
        return True

    def start(self):
        capture = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if self.client_address[0] != capture.miner_ip:
                    return
                with capture.lock:
                    capture.stats["connections"] += 1
                prefix = capture.store.prefix()
                self.request.settimeout(2)
                pending, subscribed, user, sent = b"", False, None, None
                opened = time.monotonic()

                def send(value):
                    self.request.sendall(canonical(value) + b"\n")

                try:
                    while not capture.stop.is_set() and time.monotonic() - opened < 300:
                        with capture.lock:
                            active = capture.current
                        if subscribed and user and sent != active.template.job_id:
                            if not capture.prepare_dispatch(active):
                                continue
                            send({"id": None, "method": "mining.set_difficulty", "params": [capture.difficulty]})
                            send({"id": None, "method": "mining.notify", "params": sia_notify(active.template, prefix, clean=active.clean)})
                            with capture.lock:
                                capture.stats["notifications"] += 1
                            sent = active.template.job_id
                        ready, _, _ = select.select([self.request], [], [], 0.5)
                        if not ready:
                            continue
                        chunk = self.request.recv(4096)
                        if not chunk:
                            return
                        pending += chunk
                        if len(pending) > MAX_LINE:
                            return
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            req = json.loads(line)
                            if type(req) is not dict or type(req.get("params", [])) is not list:
                                return
                            identity, method, params = req.get("id"), req.get("method"), req.get("params", [])
                            response, error = True, None
                            if method == "mining.subscribe":
                                subscribed = True
                                with capture.lock:
                                    capture.stats["subscriptions"] += 1
                                response = [[["mining.set_difficulty", "sharepool-difficulty"],
                                             ["mining.notify", "sharepool-notify"]], prefix.hex(), 8]
                            elif method == "mining.authorize":
                                if not params or params[0] != "sharepool.hardware":
                                    response = False
                                else:
                                    user = params[0]
                                    with capture.lock:
                                        capture.stats["authorizations"] += 1
                            elif method == "mining.configure":
                                response = {"version-rolling": False}
                            elif method in ("mining.extranonce.subscribe", "mining.suggest_difficulty"):
                                pass
                            elif method == "mining.submit":
                                with capture.lock:
                                    capture.stats["submissions"] += 1
                                try:
                                    if not subscribed or not user:
                                        raise ValueError("session is not authorized")
                                    response = capture.submit(prefix, params, user)
                                except (ValueError, RuntimeError) as problem:
                                    with capture.lock:
                                        capture.stats["rejected"] += 1
                                    response, error = False, [23, str(problem)[:200], None]
                                    capture.store.event("rejected", {"reason": str(problem)[:200]})
                            else:
                                response, error = False, [20, "unsupported test method", None]
                            send({"id": identity, "result": response, "error": error})
                except (OSError, ValueError):
                    return

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False
            block_on_close = True
            request_queue_size = 4

            def __init__(self, *args, **kwargs):
                self.slots = threading.BoundedSemaphore(4)
                super().__init__(*args, **kwargs)

            def verify_request(self, request, address):
                return address[0] == capture.miner_ip

            def process_request(self, request, address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except BaseException:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self.slots.release()

        self.server = Server(self.bind, Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def run(self, seconds=90):
        if not 10 <= seconds <= 180:
            raise ValueError("hardware test duration must be 10..180 seconds")
        until, next_refresh = time.monotonic() + seconds, time.monotonic() + 15
        while time.monotonic() < until and not self.stop.wait(1):
            if time.monotonic() >= next_refresh:
                self.refresh()
                next_refresh = time.monotonic() + 15
        with self.lock:
            return dict(self.stats)

    def close(self):
        self.stop.set()
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-cli", required=True)
    parser.add_argument("--datadir", required=True)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=3335)
    parser.add_argument("--miner-ip", required=True)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--difficulty", type=int, default=4096)
    parser.add_argument("--payout-script", required=True)
    parser.add_argument("--capture-db", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--submit-blocks", action="store_true")
    args = parser.parse_args()
    rpc = NodeRPC(args.bitcoin_cli, args.datadir)
    store = CaptureStore(args.capture_db)
    capture = None
    try:
        capture = HardwareCapture(rpc, store, bind=(args.bind, args.port), miner_ip=args.miner_ip,
                                  difficulty=args.difficulty, payout_script=bytes.fromhex(args.payout_script),
                                  submit_blocks=args.submit_blocks)
        capture.start()
        result = capture.run(args.seconds)
        print(json.dumps(result))
    finally:
        if capture:
            capture.close()
        Path(args.report).write_bytes(canonical(store.report()) + b"\n")
        store.close()


if __name__ == "__main__":
    main()
