#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded, permissionless SPN1 evidence exchange for local regtest testing.

The transport carries public templates and proofs, never signing keys or RPC
credentials. Each recipient independently uses its native mining gate. Peer
inventory is neither a consensus checkpoint nor an inclusion guarantee.
Listeners and outbound destinations are numeric loopback only in this version.
The gate factory and its bounded local RPC transport run on one owning thread.
"""
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import queue
import re
import socket
import socketserver
import threading
import time
from urllib.parse import parse_qs, urlsplit

from native_enforcement import RULES_HASH
from native_mining_gate import REGTEST_GENESIS, RecoveryRequired, parse_block, parse_share, template_id
from test_framework.authproxy import JSONRPCException

MAX_HEADERS = 8192
MAX_JSON = 65536
MAX_ITEMS = 256
PAGE_SIZE = 32
MAX_OBJECT = 4_000_000
MAX_SYNC_BYTES = 16_000_000
MAX_SYNC_OBJECTS = 32
MAX_PEERS = 8
IO_SECONDS = 5
OPERATION_SECONDS = 8
HEX = re.compile(r"[0-9a-f]{64}\Z")


class PeerError(RuntimeError):
    """Untrusted peer data or a bounded transport failure."""


class PeerUnavailable(PeerError):
    pass


class LocalGateError(PeerError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(test, message):
    if not test:
        raise PeerError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(unused):
        raise PeerError("nonfinite JSON value")
    def integer(value):
        require(len(value) <= 20, "JSON integer byte bound")
        return int(value)
    def floating(unused):
        raise PeerError("floating-point inventory fields are forbidden")
    require(type(raw) is bytes and len(raw) <= MAX_JSON, "JSON byte bound")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant,
                          parse_int=integer, parse_float=floating)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PeerError("invalid peer JSON") from None


def _endpoint(url):
    try:
        parsed = urlsplit(url)
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port
        require(parsed.scheme == "http" and address.is_loopback and
                parsed.username is None and parsed.password is None and
                parsed.path in ("", "/") and not parsed.query and not parsed.fragment and
                type(port) is int and 1 <= port <= 65535, "numeric loopback HTTP peer required")
        return str(address), port
    except (TypeError, ValueError):
        raise PeerError("numeric loopback HTTP peer required") from None


def _recv(sock, count, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PeerUnavailable("peer deadline exceeded")
    sock.settimeout(remaining)
    raw = sock.recv(count)
    if not raw:
        raise PeerUnavailable("peer closed an incomplete message")
    return raw


def _headers(sock, deadline):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        raw.extend(_recv(sock, 2048, deadline))
        require(len(raw) <= MAX_HEADERS + 2048, "HTTP header byte bound")
    head, body = bytes(raw).split(b"\r\n\r\n", 1)
    require(len(head) <= MAX_HEADERS, "HTTP header byte bound")
    lines = head.split(b"\r\n")
    require(len(lines) <= 33 and len(lines[0]) <= 2048, "HTTP header count bound")
    fields = {}
    for line in lines[1:]:
        require(b":" in line and len(line) <= 1024 and line[:1] not in (b" ", b"\t"),
                "invalid HTTP header")
        key, value = line.split(b":", 1)
        key = key.lower()
        require(re.fullmatch(rb"[a-z0-9-]+", key) and key not in fields,
                "duplicate or invalid HTTP header")
        fields[key] = value.strip()
    require(b"transfer-encoding" not in fields and b"content-encoding" not in fields,
            "encoded HTTP messages are not supported")
    return lines[0], fields, body


class PeerClient:
    def __init__(self, url):
        self.host, self.port = _endpoint(url)

    def get(self, path, maximum):
        require(type(path) is str and path.startswith("/spn1/") and
                re.fullmatch(r"[a-zA-Z0-9/_?=&.-]+", path), "invalid evidence route")
        require(_integer(maximum, 1, MAX_OBJECT), "response bound")
        deadline = time.monotonic() + IO_SECONDS
        host = "[{}]".format(self.host) if ":" in self.host else self.host
        try:
            with socket.create_connection((self.host, self.port), timeout=IO_SECONDS) as sock:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + host + ":" +
                              str(self.port) + "\r\nConnection: close\r\n\r\n").encode("ascii"))
                first, headers, body = _headers(sock, deadline)
                match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [^\r\n]*", first)
                require(match is not None, "invalid HTTP status")
                if int(match[1]) in (409, 410, 429, 503):
                    raise PeerUnavailable("peer evidence temporarily unavailable")
                require(match[1] == b"200", "peer rejected evidence request")
                length = headers.get(b"content-length", b"")
                require(re.fullmatch(rb"0|[1-9][0-9]{0,7}", length), "HTTP length required")
                length = int(length)
                require(length <= maximum and len(body) <= length, "HTTP response byte bound")
                result = bytearray(body)
                while len(result) < length:
                    result.extend(_recv(sock, min(65536, length - len(result)), deadline))
                return bytes(result)
        except (OSError, TimeoutError):
            raise PeerUnavailable("peer transport failed") from None

    def inventory(self, pool):
        status = _json(self.get("/spn1/status", MAX_JSON))
        required = {"protocol", "genesis", "rules", "pool", "tip", "height", "anchor_height",
                    "anchor_hash", "revision", "pruned_through", "root", "count"}
        require(type(status) is dict and set(status) == required, "invalid inventory status")
        require(status["protocol"] == 1 and type(status["protocol"]) is int and
                status["genesis"] == REGTEST_GENESIS and status["rules"] == f"{RULES_HASH:064x}" and
                status["pool"] == f"{pool:064x}" and _hex(status["tip"]) and _hex(status["root"]) and
                _hex(status["anchor_hash"]) and _integer(status["height"], 0, 0x7ffffffe) and
                _integer(status["anchor_height"], 0, status["height"]) and
                _integer(status["revision"], 0, (1 << 63) - 1) and
                _integer(status["pruned_through"], 0, status["revision"]) and
                _integer(status["count"], 0, MAX_ITEMS), "wrong peer profile or inventory bounds")
        items = []
        while len(items) < status["count"]:
            offset = len(items)
            page = _json(self.get("/spn1/inventory?root={}&offset={}&limit={}".format(
                status["root"], offset, PAGE_SIZE), MAX_JSON))
            require(type(page) is dict and set(page) == {"root", "offset", "items"} and
                    page["root"] == status["root"] and type(page["offset"]) is int and
                    page["offset"] == offset and type(page["items"]) is list and
                    len(page["items"]) == min(PAGE_SIZE, status["count"] - offset),
                    "incomplete or inconsistent inventory page")
            items.extend(page["items"])
        for item in items:
            require(type(item) is dict and set(item) == {"kind", "id", "sha256", "bytes",
                    "origin_height", "origin_parent"} and item["kind"] in ("template", "receipt") and
                    _hex(item["id"]) and _hex(item["sha256"]) and _hex(item["origin_parent"]) and
                    _integer(item["bytes"], 1, MAX_OBJECT if item["kind"] == "template" else 1024) and
                    _integer(item["origin_height"], max(1, status["height"] - 2), status["height"] + 1),
                    "invalid object descriptor")
        order = [(item["kind"], item["id"]) for item in items]
        require(order == sorted(set(order)), "duplicate or unordered peer inventory")
        require(sum(item["kind"] == "template" for item in items) <= 128 and
                sum(item["kind"] == "receipt" for item in items) <= 128, "active object count bound")
        body = {k: v for k, v in status.items() if k not in ("root", "count")}
        body["items"] = items
        require(digest(canonical(body)) == status["root"], "inventory commitment mismatch")
        return status, items

    def object(self, item):
        raw = self.get("/spn1/object/{}/{}".format(item["kind"], item["id"]), item["bytes"])
        require(len(raw) == item["bytes"] and digest(raw) == item["sha256"], "object digest mismatch")
        if item["kind"] == "template":
            header = parse_block(raw)
            identity = template_id(header)
            height, parent = header.m_height, header.hashPrevBlock
        else:
            share = parse_share(raw)
            identity = f"{share.proof_id:064x}"
            height, parent = share.envelope.height, share.header.hashPrevBlock
        require(identity == item["id"] and height == item["origin_height"] and
                f"{parent:064x}" == item["origin_parent"], "object identity or context mismatch")
        return raw


@dataclass
class _Call:
    operation: str
    args: tuple
    event: object = field(default_factory=threading.Event)
    cancelled: object = field(default_factory=threading.Event)
    result: object = None
    error: object = None


class _Budget:
    def __init__(self):
        self.lock = threading.Lock()
        self.at, self.requests, self.bytes = time.monotonic(), 32.0, 8_000_000.0

    def take(self, requests, size):
        with self.lock:
            now = time.monotonic()
            elapsed, self.at = now - self.at, now
            self.requests = min(32, self.requests + elapsed * 16)
            self.bytes = min(8_000_000, self.bytes + elapsed * 1_000_000)
            if self.requests < requests or self.bytes < size:
                return False
            self.requests -= requests
            self.bytes -= size
            return True


class NativePeerService:
    """A read-only network surface; gate mutations are explicit local calls.

    The trusted factory must finish within ten seconds and create a local RPC
    client bounded to five seconds per call. The actor additionally checks an
    eight-second operation deadline before and after each RPC. One in-flight
    RPC can overrun that deadline by its five-second limit. No worker touches SQLite.
    A timed-out call never acknowledges an uncommitted mutation. A mutation
    already in flight may finish durably; its exact retry remains idempotent.
    """
    OPERATIONS = frozenset({"register_template", "receive", "authorize", "maintenance", "active_inventory"})

    def __init__(self, gate_factory, bind=("127.0.0.1", 0)):
        require(ipaddress.ip_address(bind[0]).is_loopback and _integer(bind[1], 0, 65535),
                "peer listener requires numeric loopback")
        self.calls, self.stopping = queue.Queue(maxsize=8), threading.Event()
        self.ready, self.failure = threading.Event(), None
        self.operation_deadline, self.inflight = 0, None
        self.gate_factory, self.snapshot, self.snapshot_at = gate_factory, None, 0
        self.budget = _Budget()
        self.owner = threading.Thread(target=self._run, name="sharepool-gate-owner")
        self.owner.start()
        if not self.ready.wait(10) or self.failure is not None:
            self.stopping.set()
            self.owner.join(10)
            raise PeerUnavailable("native peer gate startup failed")
        service = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                code, data, content = 400, b'{"error":"invalid_request"}', "application/json"
                try:
                    require(service.budget.take(1, 0), "request budget")
                    first, fields, body = _headers(self.request, time.monotonic() + IO_SECONDS)
                    require(not body and fields.get(b"content-length", b"0") == b"0", "GET body is forbidden")
                    match = re.fullmatch(rb"GET ([!-~]{1,2048}) HTTP/1\.[01]", first)
                    require(match is not None, "only evidence GET is supported")
                    code, data, content = service._call("http", match[1].decode("ascii"))
                    if not service.budget.take(0, len(data)):
                        code, data, content = 429, b'{"error":"rate_limited"}', "application/json"
                except PeerUnavailable:
                    code, data = 503, b'{"error":"unavailable"}'
                except (PeerError, ValueError, OSError):
                    pass
                self.request.settimeout(IO_SECONDS)
                try:
                    self.request.sendall(("HTTP/1.1 {} Evidence\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n".format(code, len(data), content)).encode() + data)
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False
            block_on_close = True
            request_queue_size = 4
            address_family = socket.AF_INET6 if ":" in bind[0] else socket.AF_INET

            def __init__(self):
                self.slots = threading.BoundedSemaphore(4)
                super().__init__(bind, Handler)

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

        try:
            self.server = Server()
            self.listener = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1},
                                             name="sharepool-peer-listener")
            self.listener.start()
        except BaseException:
            self.close()
            raise

    @property
    def url(self):
        host, port = self.server.server_address[:2]
        return "http://{}:{}".format("[{}]".format(host) if ":" in host else host, port)

    def _snapshot(self, gate):
        if self.snapshot is None or time.monotonic() - self.snapshot_at >= 1:
            inventory = gate.active_inventory()
            inventory["items"] = sorted(inventory["items"], key=lambda item: (item["kind"], item["id"]))
            require(len(inventory["items"]) <= MAX_ITEMS, "active inventory bound")
            inventory.update({"protocol": 1, "genesis": REGTEST_GENESIS,
                              "rules": f"{RULES_HASH:064x}", "pool": f"{gate.pool:064x}"})
            self.snapshot, self.snapshot_at = inventory, time.monotonic()
        return self.snapshot

    def _route(self, gate, route):
        parsed = urlsplit(route)
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment and "%" not in route,
                "invalid evidence path")
        inventory = self._snapshot(gate)
        root = digest(canonical(inventory))
        if parsed.path == "/spn1/status" and not parsed.query:
            status = {k: v for k, v in inventory.items() if k != "items"}
            status.update({"root": root, "count": len(inventory["items"])})
            return 200, canonical(status), "application/json"
        if parsed.path == "/spn1/inventory":
            fields = parse_qs(parsed.query, strict_parsing=True, max_num_fields=3)
            require(set(fields) == {"root", "offset", "limit"} and
                    all(len(v) == 1 for v in fields.values()) and _hex(fields["root"][0]) and
                    re.fullmatch(r"0|[1-9][0-9]{0,2}", fields["offset"][0]) and
                    re.fullmatch(r"[1-9][0-9]?", fields["limit"][0]), "invalid inventory query")
            offset, limit = int(fields["offset"][0]), int(fields["limit"][0])
            require(offset <= len(inventory["items"]) and limit <= PAGE_SIZE, "inventory page bound")
            if fields["root"][0] != root:
                return 409, b'{"error":"inventory_changed"}', "application/json"
            return 200, canonical({"root": root, "offset": offset,
                                   "items": inventory["items"][offset:offset + limit]}), "application/json"
        match = re.fullmatch(r"/spn1/object/(template|receipt)/([0-9a-f]{64})", parsed.path)
        if match and not parsed.query:
            kind, identity = match.groups()
            item = next((i for i in inventory["items"] if (i["kind"], i["id"]) == (kind, identity)), None)
            if item is None:
                return 410, b'{"error":"object_not_active"}', "application/json"
            raw = gate.template_bytes(identity) if kind == "template" else gate.receipt_bytes(identity)
            require(len(raw) == item["bytes"] and digest(raw) == item["sha256"], "stored object changed")
            return 200, raw, "application/octet-stream"
        return 404, b'{"error":"unknown_route"}', "application/json"

    def _run(self):
        gate = None
        try:
            gate = self.gate_factory()
            if hasattr(gate, "rpc"):
                original_rpc = gate.rpc
                def bounded_rpc(*args):
                    def check():
                        if (self.stopping.is_set() or time.monotonic() >= self.operation_deadline or
                                (self.inflight is not None and self.inflight.cancelled.is_set())):
                            raise PeerUnavailable("native evidence operation deadline exceeded")
                    check()
                    result = original_rpc(*args)
                    check()
                    return result
                gate.rpc = bounded_rpc
            self.operation_deadline = time.monotonic() + OPERATION_SECONDS
            gate.base_template()
            self.ready.set()
            while not self.stopping.is_set():
                try:
                    call = self.calls.get(timeout=0.1)
                except queue.Empty:
                    continue
                if call.cancelled.is_set():
                    call.error = PeerUnavailable("cancelled peer request")
                    call.event.set()
                    continue
                try:
                    self.inflight = call
                    self.operation_deadline = time.monotonic() + OPERATION_SECONDS
                    if call.operation == "http":
                        call.result = self._route(gate, call.args[0])
                    else:
                        call.result = getattr(gate, call.operation)(*call.args)
                        self.snapshot = None
                except Exception as error:
                    call.error = error
                    self.snapshot = None
                finally:
                    self.inflight = None
                    call.event.set()
        except BaseException as error:
            self.failure = type(error).__name__
            self.stopping.set()
            self.ready.set()
        finally:
            while True:
                try:
                    call = self.calls.get_nowait()
                except queue.Empty:
                    break
                call.error = PeerUnavailable("peer service stopped")
                call.event.set()
            if gate is not None:
                gate.close()

    def _call(self, operation, *args):
        if self.stopping.is_set():
            raise PeerUnavailable("peer service stopped")
        call = _Call(operation, args)
        try:
            self.calls.put_nowait(call)
        except queue.Full:
            raise PeerUnavailable("peer owner queue full") from None
        if not call.event.wait(20):
            call.cancelled.set()
            raise PeerUnavailable("peer owner deadline exceeded")
        if call.error is not None:
            if operation == "http":
                if isinstance(call.error, PeerError):
                    raise call.error
                raise PeerUnavailable("native evidence unavailable") from None
            raise call.error
        return call.result

    def local(self, operation, *args):
        require(operation in self.OPERATIONS, "local gate operation is not exposed")
        return self._call(operation, *args)

    def close(self):
        if hasattr(self, "listener"):
            self.server.shutdown()
            self.server.server_close()
            self.listener.join(10)
            del self.listener
        self.stopping.set()
        self.owner.join(20)
        if self.owner.is_alive():
            raise PeerUnavailable("bounded local RPC did not stop in time")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def sync_peer(service, url, pool):
    """Pull one bounded round; native validation alone admits received objects.

    Origins are validated before their shares. A peer may withhold data or change
    inventory at any point; partial durable progress survives an exact retry.
    Missing data affects local mining admission, never native block validity.
    """
    client = PeerClient(url)
    status, items = client.inventory(pool)
    try:
        local = service.local("active_inventory")
    except RecoveryRequired:
        raise
    except Exception:
        raise LocalGateError("local gate evidence inventory is unavailable") from None
    if (local["tip"], local["height"]) != (status["tip"], status["height"]):
        raise PeerUnavailable("native chains differ; synchronize native blocks first")
    known = {(item["kind"], item["id"]) for item in local["items"]}
    missing = [item for item in items if (item["kind"], item["id"]) not in known]
    missing.sort(key=lambda item: (item["kind"] != "template", item["origin_height"], item["id"]))
    result = {"templates": 0, "receipts": 0, "duplicate_receipts": 0,
              "downloaded_bytes": 0, "deferred_objects": 0}
    count, origins_deferred = 0, False
    for item in missing:
        if (count >= MAX_SYNC_OBJECTS or result["downloaded_bytes"] + item["bytes"] > MAX_SYNC_BYTES or
                (item["kind"] == "receipt" and origins_deferred)):
            result["deferred_objects"] += 1
            origins_deferred |= item["kind"] == "template"
            continue
        raw = client.object(item)
        operation = "register_template" if item["kind"] == "template" else "receive"
        try:
            admitted = service.local(operation, raw)
        except JSONRPCException:
            raise PeerError("local native validation did not admit peer evidence") from None
        if item["kind"] == "template":
            result["templates"] += 1
        else:
            result["receipts" if admitted else "duplicate_receipts"] += 1
        result["downloaded_bytes"] += len(raw)
        count += 1
    return result


class PeerReplicator:
    """Caller-driven round-robin polling, with bounded failure backoff."""
    def __init__(self, service, pool, peers):
        require(type(peers) in (list, tuple) and 1 <= len(peers) <= MAX_PEERS and
                len(set(peers)) == len(peers), "one to eight distinct peers required")
        for url in peers:
            _endpoint(url)
        self.service, self.pool = service, pool
        self.peers, self.cursor, self.recovery_required = list(peers), 0, False
        self.schedule = {url: {"failures": 0, "next": 0} for url in peers}

    def poll(self):
        if self.recovery_required:
            return {"status": "recovery_required"}
        now = time.monotonic()
        for unused in self.peers:
            url = self.peers[self.cursor]
            self.cursor = (self.cursor + 1) % len(self.peers)
            state = self.schedule[url]
            if state["next"] > now:
                continue
            try:
                result = sync_peer(self.service, url, self.pool)
            except RecoveryRequired:
                self.recovery_required = True
                return {"status": "recovery_required"}
            except LocalGateError:
                return {"status": "local_error"}
            except (PeerError, ValueError, OSError):
                state["failures"] = min(6, state["failures"] + 1)
                state["next"] = time.monotonic() + min(60, 2 ** state["failures"])
                return {"peer": url, "status": "retry", "retry_seconds": min(60, 2 ** state["failures"])}
            state.update({"failures": 0, "next": time.monotonic() + 1})
            return {"peer": url, "status": "progress", **result}
        return {"status": "backoff"}
