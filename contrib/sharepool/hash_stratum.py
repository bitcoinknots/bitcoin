#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded loopback Sia Stratum transport for the v7 regtest mining gate.

The constructing thread exclusively owns the gate and scheduler. Network threads
enqueue requests; a separate, bounded-timeout RPC connection watches the native
tip. A transport watchdog withdraws sockets on a changed tip, observer failure or
expired observation even while the owner is constructing a job. This is a test
integration, not an authenticated remote service or production ASIC deployment.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
import ipaddress
import json
import math
import os
import queue
import secrets
import select
import socket
import socketserver
import threading
import time

from hash_job_scheduler import HashJobScheduler
from hash_snapshot import MAX_SHARE_AGE, Share, Snapshot, share_target
from native_mining_gate import REGTEST_GENESIS, parse_block
from testnet_template import TestnetTemplate, proof_from_sia, sia_notify
from test_framework.messages import CBlockHeader, uint256_from_compact


@dataclass
class _Request:
    kind: str
    payload: object
    done: object = field(default_factory=threading.Event)
    cancelled: object = field(default_factory=threading.Event)
    result: object = None
    error: object = None


@dataclass(frozen=True)
class Work:
    authorization: object
    template: object
    snapshot: object
    target: int
    generation: int


class TipLatch:
    """Thread-safe, fail-closed transport context; never touches a mining gate."""
    def __init__(self, *, observation_timeout=2.0, clock=time.monotonic):
        if (type(observation_timeout) not in (int, float) or
                not math.isfinite(observation_timeout) or not 0.1 <= observation_timeout <= 30 or not callable(clock)):
            raise ValueError("bounded native observation timeout required")
        self.lock = threading.RLock()
        self.timeout, self.clock = observation_timeout, clock
        self.parent = self.seen = None
        self.generation = 0
        self.failure = "native tip not yet observed"
        self.sockets = set()
        self.last_withdrawal = None

    def _clock_value(self):
        try:
            value = self.clock()
        except Exception:
            raise ValueError("native freshness clock unavailable") from None
        try:
            finite = type(value) in (int, float) and math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite or value < 0:
            raise ValueError("native freshness clock must be finite and nonnegative")
        return value

    def _withdraw(self, reason, *, at=None):
        self.generation += 1
        self.failure = reason
        # Diagnostics must not call a possibly failed clock before socket
        # retirement. A missing timestamp cannot prevent fail-closed behavior.
        self.last_withdrawal = at
        for client in tuple(self.sockets):
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.sockets.clear()

    def observe(self, parent):
        if type(parent) is not str or len(parent) != 64 or any(c not in "0123456789abcdef" for c in parent):
            self.fail("malformed native tip")
            raise ValueError("malformed native tip")
        with self.lock:
            try:
                now = self._clock_value()
            except ValueError:
                self._withdraw("native freshness clock failed")
                self.seen = None
                raise
            if self.parent is not None and parent != self.parent:
                self._withdraw("native tip changed", at=now)
            self.parent, self.seen, self.failure = parent, now, None

    def fail(self, reason):
        with self.lock:
            self._withdraw(reason)
            self.seen = None

    def _fresh(self):
        try:
            now = self._clock_value()
        except ValueError:
            self._withdraw("native freshness clock failed")
            self.seen = None
            return False
        if self.seen is None or now < self.seen or now - self.seen >= self.timeout:
            if self.failure is None:
                self._withdraw("native observation deadline expired", at=now)
            return False
        return self.failure is None

    def check(self, parent=None, generation=None):
        with self.lock:
            return (self._fresh() and (parent is None or parent == self.parent) and
                    (generation is None or generation == self.generation))


class HashStratumService:
    """One v7 gateway, up to four local synthetic Sia clients, finite queues.

    observer_rpc MUST use its own connection and finite network timeouts. It
    must not call the gate or share a non-thread-safe RPC client with gate.rpc.
    Call service_once() frequently on the gate's owner thread. A True submit
    response follows gate.receive()'s durable ACK, not native block admission.
    Snapshot availability is established via the gate before work is handed off.
    """
    MAX_JOBS = 32
    MAX_JOB_BYTES = 64 * 1024 * 1024
    MAX_LINE = 4096

    def __init__(self, gate, *, sign_owner, observer_rpc, bind=("127.0.0.1", 0),
                 work_update_seconds=40, observe_seconds=0.25,
                 observation_timeout=2.0, clock=time.monotonic):
        if (gate.profile_version != 7 or not callable(observer_rpc) or
                not ipaddress.ip_address(bind[0]).is_loopback or
                type(observe_seconds) not in (int, float) or
                not math.isfinite(observe_seconds) or not 0.02 <= observe_seconds < observation_timeout):
            raise ValueError("v7, loopback bind and bounded independent observer required")
        self.owner = os.getpid(), threading.get_ident()
        self.gate, self.observer_rpc = gate, observer_rpc
        self.observer_policy = gate.mode, f"{gate.rules:064x}", gate.activation_height
        self.observe_seconds = observe_seconds
        self.latch = TipLatch(observation_timeout=observation_timeout)
        self.stop = threading.Event()
        self.requests = queue.Queue(maxsize=16)
        self.jobs, self.current = OrderedDict(), None
        self.stats = {"published": 0, "acknowledged": 0, "duplicate": 0, "rejected": 0,
                      "submitted_candidates": 0, "accepted_candidates": 0,
                      "candidate_rpc_failures": 0, "candidate_rejections": 0}
        self._closed = self._servicing = False
        self._server = self._server_thread = self._observer_thread = None
        self.bind = bind
        self.scheduler = HashJobScheduler(gate, sign_owner=sign_owner,
            publish=self._publish, withdraw=self.withdraw,
            work_update_seconds=work_update_seconds, clock=clock)

    def _owner(self):
        if self.owner != (os.getpid(), threading.get_ident()):
            raise RuntimeError("Stratum gate operations require their original owner")

    def _observe(self):
        rpc = self.observer_rpc
        info, network = rpc("getblockchaininfo"), rpc("getnetworkinfo")
        status = rpc("getsharepoolhashstatus", None, 1)
        if (info.get("chain") != "regtest" or rpc("getblockhash", 0) != REGTEST_GENESIS or
                network.get("networkactive") is not False or network.get("connections") != 0 or
                (status.get("mode"), status.get("rules"), status.get("activation_height", 1)) != self.observer_policy):
            raise ValueError("tip observer requires the same isolated v7 regtest profile")
        # The final read supplies the observation; startup flags alone are not a
        # continuing native-context check. Gate approval remains authoritative.
        self.latch.observe(rpc("getbestblockhash"))

    def _watch(self):
        while not self.stop.is_set():
            try:
                self._observe()
            except Exception:
                self.latch.fail("native observer failed")
            self.stop.wait(self.observe_seconds)

    def withdraw(self):
        # Called by the scheduler on its owner; shutdown() is nonblocking and
        # socket handlers never hold the latch while waiting for owner work.
        with self.latch.lock:
            self.current = None
            self.latch._withdraw("mining work withdrawn")

    def _publish(self, authorization):
        self._owner()
        block = parse_block(authorization.block_bytes)
        snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
        template = TestnetTemplate(CBlockHeader(block).serialize(), block.vtx[0].serialize_with_witness(),
            tuple(tx.serialize_with_witness() for tx in block.vtx[1:]),
            block.m_mm_rhs.to_bytes(32, "little"), 4_000_000, 4_000_000)
        if (template.block() != authorization.block_bytes or snapshot.envelope.version != 7 or
                block.m_mm_rhs != snapshot.hash):
            raise ValueError("Stratum wrapper changes the exact v7 authorized work")
        self.gate.register_snapshot(authorization.snapshot_bytes)
        self.gate.register_template(authorization.block_bytes)
        # Registration can expose a new receipt/context. This adapter performs
        # another strict fence immediately before its transport handoff.
        if not self.gate.ready_for_dispatch(authorization):
            raise ValueError("Stratum publication failed the final dispatch fence")
        with self.latch.lock:
            if not self.latch.check(authorization.native_parent):
                raise ValueError("native observer refuses stale or unobserved work")
            for key, old in tuple(self.jobs.items()):
                if block.m_height - old.snapshot.envelope.height > MAX_SHARE_AGE:
                    del self.jobs[key]
            charge = len(authorization.block_bytes) + len(authorization.snapshot_bytes)
            total = sum(len(w.authorization.block_bytes) + len(w.authorization.snapshot_bytes) for w in self.jobs.values())
            if template.job_id not in self.jobs and (len(self.jobs) >= self.MAX_JOBS or total + charge > self.MAX_JOB_BYTES):
                raise ValueError("unexpired Stratum work retention budget reached")
            work = Work(authorization, template, snapshot, share_target(block.nBits, 7), self.latch.generation)
            self.jobs[template.job_id] = self.current = work
            self.stats["published"] += 1
            return True

    def _enqueue(self, kind, payload):
        request = _Request(kind, payload)
        if self.stop.is_set():
            raise RuntimeError("Stratum service is stopping")
        try:
            self.requests.put_nowait(request)
        except queue.Full:
            raise RuntimeError("Stratum owner request queue is full") from None
        deadline = time.monotonic() + 5
        while not request.done.wait(0.05):
            if self.stop.is_set() or time.monotonic() >= deadline:
                request.cancelled.set()
                raise RuntimeError("Stratum owner request cancelled or timed out")
        if request.error is not None:
            raise request.error
        return request.result

    def _submit(self, prefix, params):
        if (type(params) is not list or len(params) != 5 or params[0] != "sharepool.regtest" or
                any(type(item) is not str or len(item) > 256 for item in params)):
            raise ValueError("invalid authorized submission")
        work = self.jobs.get(params[1])
        if work is None:
            raise ValueError("unknown or expired issued job")
        proof = proof_from_sia(work.template, prefix, bytes.fromhex(params[2]), params[3], params[4])
        if proof.hash_int > work.target:
            raise ValueError("insufficient native share work")
        if work.authorization.block_for_header(proof.header) != proof.block:
            raise ValueError("proof changes its immutable authorized block")
        share = Share(proof.header, work.snapshot.envelope, work.snapshot.owner_signature)
        accepted = self.gate.receive(share)
        self.stats["acknowledged" if accepted else "duplicate"] += 1
        # The exact old candidate is not rewritten. Native submitblock decides
        # validity/branch placement, including a candidate on an older parent.
        # A later block RPC failure cannot revoke an already durable ACK.
        if proof.hash_int <= uint256_from_compact(work.template.header.nBits):
            self.stats["submitted_candidates"] += 1
            try:
                result = self.gate.rpc("submitblock", proof.block.hex())
                if result is None:
                    self.stats["accepted_candidates"] += 1
                else:
                    self.stats["candidate_rejections"] += 1
            except Exception:
                # gate.receive retained the proof and exact origin for explicit
                # retry/recovery; this counter is not a claim of best-chain work.
                self.stats["candidate_rpc_failures"] += 1
        return True

    def service_once(self, *, max_requests=4):
        self._owner()
        if self._closed or self._servicing or type(max_requests) is not int or not 1 <= max_requests <= 16:
            raise RuntimeError("closed, reentrant or unbounded Stratum owner service")
        self._servicing = True
        try:
            if self.current is not None and not self.latch.check(
                    self.current.authorization.native_parent, self.current.generation):
                self.scheduler.invalidate()
            for _ in range(max_requests):
                try:
                    request = self.requests.get_nowait()
                except queue.Empty:
                    break
                try:
                    if request.cancelled.is_set():
                        raise RuntimeError("request cancelled before admission")
                    if request.kind == "dispatch":
                        work = request.payload
                        request.result = (work is self.current and
                            self.gate.ready_for_dispatch(work.authorization) and
                            self.latch.check(work.authorization.native_parent, work.generation))
                        # Successful owner approval is the per-client handoff
                        # boundary. Later ACKs belong to a subsequent job even
                        # if the socket thread has not written this notify yet.
                        # Native generation is checked again at the actual send.
                    else:
                        request.result = self._submit(*request.payload)
                except Exception as error:
                    request.error = error
                    self.stats["rejected"] += 1
                    # Invalid client work is a per-request rejection. The normal
                    # scheduler context/seal fence below independently retires
                    # all work if native or journal state itself became unsafe.
                finally:
                    request.done.set()
            if not self.latch.check():
                return None
            return self.scheduler.poll()
        finally:
            self._servicing = False

    @property
    def address(self):
        return None if self._server is None else self._server.server_address

    def start(self):
        self._owner()
        if self._closed or self._server is not None:
            raise RuntimeError("Stratum service already started or closed")
        self._observe()  # No listener before the isolated native guards pass.
        service = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client = self.request
                client.settimeout(0.2)
                prefix, pending = secrets.token_bytes(4), b""
                subscribed = authorized = False
                sent = None
                with service.latch.lock:
                    if not service.latch.check():
                        return
                    service.latch.sockets.add(client)

                def send(value):
                    raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
                    client.sendall(raw)

                try:
                    while not service.stop.is_set():
                        with service.latch.lock:
                            work = service.current
                        if subscribed and authorized and work is not None and sent != work.template.job_id:
                            if service._enqueue("dispatch", work):
                                with service.latch.lock:
                                    if work is not service.current or not service.latch.check(work.authorization.native_parent, work.generation):
                                        return
                                    difficulty = math.nextafter(((1 << 224) - 1) / (work.target + 1), 0.0)
                                    send({"id": None, "method": "mining.set_difficulty", "params": [difficulty]})
                                    send({"id": None, "method": "mining.notify", "params": sia_notify(work.template, prefix, clean=True)})
                                    sent = work.template.job_id
                        if not service.latch.check():
                            return
                        if not select.select([client], [], [], 0.05)[0]:
                            continue
                        chunk = client.recv(4096)
                        if not chunk:
                            return
                        pending += chunk
                        if len(pending) > service.MAX_LINE:
                            return
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            req = json.loads(line)
                            if type(req) is not dict or type(req.get("params", [])) is not list:
                                return
                            method, params, result = req.get("method"), req.get("params", []), True
                            if method == "mining.subscribe":
                                subscribed = True
                                result = [[["mining.notify", "sharepool-v7"]], prefix.hex(), 8]
                            elif method == "mining.authorize":
                                authorized = bool(params and params[0] == "sharepool.regtest")
                                result = authorized
                            elif method == "mining.configure":
                                result = {"version-rolling": False}
                            elif method == "mining.submit":
                                if not subscribed or not authorized:
                                    raise ValueError("unauthorized submission")
                                result = service._enqueue("submit", (prefix, params))
                            elif method not in ("mining.extranonce.subscribe", "mining.suggest_difficulty"):
                                raise ValueError("unsupported regtest method")
                            send({"id": req.get("id"), "result": result, "error": None})
                except (OSError, ValueError, RuntimeError):
                    return
                finally:
                    with service.latch.lock:
                        service.latch.sockets.discard(client)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            request_queue_size = 4

            def __init__(self, *args):
                self.slots = threading.BoundedSemaphore(4)
                super().__init__(*args)

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

            def service_actions(self):
                # This watchdog does not depend on a returning observer RPC.
                service.latch.check()

        self._server = Server(self.bind, Handler)
        self._server_thread = threading.Thread(target=lambda: self._server.serve_forever(poll_interval=0.05), daemon=True)
        self._observer_thread = threading.Thread(target=self._watch, daemon=True)
        self._server_thread.start()
        self._observer_thread.start()

    def close(self):
        self._owner()
        self.stop.set()
        self._closed = True
        self.scheduler.close()
        self.withdraw()
        while True:
            try:
                request = self.requests.get_nowait()
            except queue.Empty:
                break
            request.error = RuntimeError("Stratum service closed")
            request.done.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server_thread.join(timeout=1)
        if self._observer_thread is not None:
            self._observer_thread.join(timeout=1)
        # The caller owns gate.close() and observer RPC lifecycle. A hung RPC
        # remains a daemon observer, cannot publish, and never owns gate state.
