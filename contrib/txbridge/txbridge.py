#!/usr/bin/env python3
"""knots-txbridge: carry transactions announced on the legacy SHA256d network into a Bitcoin Knots node.

The bridge peers with SHA256d nodes, the legacy chain, as a light client (no services, no blocks),
asks for every transaction they announce, and forwards the raw bytes to a Knots
node. The node's own consensus and policy rules decide what is accepted.
Nothing is sent back to the SHA256d peers.

Modes:
  count   connect and count what the peers announce; no node needed
  test    run every transaction through testmempoolaccept over RPC, submit nothing
  submit  hand each transaction to the node as an ordinary P2P peer

Every SHA256d peer is treated as hostile: per-message parsing errors, oversized
or malformed data, undelivered requests and floods cost the peer strikes, and a
peer over the limit is dropped and its address banned for an hour.
"""
import argparse
import asyncio
import base64
import collections
import hashlib
import ipaddress
import json
import logging
import random
import socket
import struct
import sys
import time
import urllib.request

NETWORKS = {
    "mainnet": (bytes.fromhex("f9beb4d9"), 8333),
    "testnet4": (bytes.fromhex("1c163f28"), 48333),
    "signet": (bytes.fromhex("0a03cf40"), 38333),
    "regtest": (bytes.fromhex("fabfb5da"), 18444),
}
PROTOCOL_VERSION = 70016
USER_AGENT = b"/knots-txbridge:0.3/"
NODE_BLAKE2B = 1 << 28
MSG_TX = 1
MSG_WITNESS_TX = 1 | (1 << 30)
MSG_WTX = 5                      # BIP339: announced by wtxid once wtxidrelay is negotiated
DNS_SEEDS = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
    "seed.mainnet.achownodes.xyz",
    "seed.bitcoin.sprovoost.nl",
    "seed.bitcoin.jonasschnelli.ch",
]

MAX_MSG_LEN = 4_000_000          # protocol maximum; larger headers drop the peer
MAX_TX_BYTES = 400_000           # nothing above the standard weight limit can be accepted anyway
MAX_INV_PER_MSG = 50_000         # Core's MAX_INV_SZ
MAX_PENDING_PER_PEER = 500
MAX_PENDING_TOTAL = 5_000
PENDING_TIMEOUT = 45
MAX_WTXIDS_PER_TXID = 3          # a bogus witness must not stop the honest one from being fetched
TXID_MEMORY = 3600
SEEN_LIMIT = 250_000
TX_RATE_PER_SEC = 200            # per peer, token bucket
TX_BURST = 1_000
STRIKE_LIMIT = 100
BAN_SECONDS = 3600
STRIKE_DECAY = 600               # host strikes halve every ten minutes of quiet
FLAP_PENALTY = 10                # a reconnect after a strike-bearing session costs this much
IDLE_TIMEOUT = 180
PING_INTERVAL = 60
RPC_CONCURRENCY = 4
NODE_QUEUE = 10_000

log = logging.getLogger("txbridge")


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_varint(b: bytes, i: int):
    x = b[i]
    if x < 0xFD:
        return x, i + 1
    if x == 0xFD:
        return struct.unpack_from("<H", b, i + 1)[0], i + 3
    if x == 0xFE:
        return struct.unpack_from("<I", b, i + 1)[0], i + 5
    return struct.unpack_from("<Q", b, i + 1)[0], i + 9


def net_addr(services: int, ip: str = "::", port: int = 0) -> bytes:
    return struct.pack("<Q", services) + socket.inet_pton(socket.AF_INET6, ip) + struct.pack(">H", port)


def version_payload(relay: bool) -> bytes:
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time()))
        + net_addr(0)
        + net_addr(0)
        + struct.pack("<Q", random.getrandbits(64))
        + varint(len(USER_AGENT)) + USER_AGENT
        + struct.pack("<i", 0)
        + (b"\x01" if relay else b"\x00")
    )


def txid_of(raw: bytes) -> str:
    """txid (hash of the non-witness serialization) of a raw transaction; raises on a malformed one."""
    i = 4
    witness = raw[4] == 0 and raw[5] == 1
    if witness:
        i = 6
    stripped = bytearray(raw[:4])
    n_inputs, i = read_varint(raw, i)
    if n_inputs == 0 or n_inputs > len(raw):
        raise ValueError("input count")
    start = i
    for _ in range(n_inputs):
        i += 36
        sl, i = read_varint(raw, i)
        if sl > len(raw):
            raise ValueError("script length")
        i += sl + 4
    n_outputs, i = read_varint(raw, i)
    if n_outputs == 0 or n_outputs > len(raw):
        raise ValueError("output count")
    for _ in range(n_outputs):
        i += 8
        sl, i = read_varint(raw, i)
        if sl > len(raw):
            raise ValueError("script length")
        i += sl
    if i > len(raw):
        raise ValueError("truncated")
    stripped += varint(n_inputs) + raw[start:i]
    if witness:
        for _ in range(n_inputs):
            n, i = read_varint(raw, i)
            if n > len(raw):
                raise ValueError("witness count")
            for _ in range(n):
                l, i = read_varint(raw, i)
                if l > len(raw):
                    raise ValueError("witness item")
                i += l
    stripped += raw[i:i + 4]
    if i + 4 != len(raw):
        raise ValueError("trailing bytes")
    return sha256d(bytes(stripped))[::-1].hex()


def clean_text(b: bytes, limit: int = 80) -> str:
    return "".join(chr(c) if 0x20 <= c <= 0x7E else "?" for c in b[:limit])


def host_group(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 4:
        return str(ipaddress.ip_network(f"{host}/16", strict=False))
    return str(ipaddress.ip_network(f"{host}/32", strict=False))


class Rpc:
    def __init__(self, url: str, cookie: str, user: str, password: str):
        self.url = url
        if cookie:
            with open(cookie, encoding="utf8") as f:
                cred = f.read().strip()
        else:
            cred = f"{user}:{password}"
        self.auth = "Basic " + base64.b64encode(cred.encode()).decode()

    def call(self, method: str, params: list):
        body = json.dumps({"jsonrpc": "1.0", "id": "txbridge", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read())
        if resp.get("error"):
            raise RuntimeError(f"{resp['error'].get('code')}: {resp['error'].get('message')}")
        return resp["result"]


class Stats:
    def __init__(self):
        self.started = time.time()
        self.peers = 0
        self.blake2b_peers = 0
        self.connect_failures = 0
        self.announced = 0
        self.requested = 0
        self.received = 0
        self.malformed = 0
        self.oversized = 0
        self.rate_dropped = 0
        self.strikes = 0
        self.dropped_peers = 0
        self.banned = 0
        self.submitted = 0
        self.accepted = 0
        self.known = 0
        self.rejected = collections.Counter()
        self.rpc_errors = 0
        self.node_queue_drops = 0
        self.undelivered = 0
        self.notfound = 0
        self.bytes_in = 0
        self.node_link = "n/a"

    def line(self) -> str:
        up = int(time.time() - self.started)
        rej = ", ".join(f"{k}={v}" for k, v in self.rejected.most_common(5))
        return (f"up {up}s in {self.bytes_in / 1e6:.1f} MB peers {self.peers} (BLAKE2b peers skipped {self.blake2b_peers}, connect failures {self.connect_failures}, "
                f"dropped {self.dropped_peers}, banned {self.banned}, strikes {self.strikes}) "
                f"announced {self.announced} requested {self.requested} received {self.received} "
                f"malformed {self.malformed} oversized {self.oversized} rate-dropped {self.rate_dropped} undelivered {self.undelivered} notfound {self.notfound} | "
                f"node {self.node_link} submitted {self.submitted} accepted {self.accepted} already-known {self.known} "
                f"rpc-errors {self.rpc_errors} queue-drops {self.node_queue_drops} rejected {sum(self.rejected.values())}"
                + (f" [{rej}]" if rej else ""))


class Conn:
    """One P2P connection, with framing, timeouts and strike accounting."""

    def __init__(self, bridge, host: str, port: int, name: str):
        self.bridge = bridge
        self.host = host
        self.port = port
        self.name = name
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.strikes = 0
        self.ready = False
        self.blake2b: bool | None = None   # set by the peer's version message
        self.last_msg = time.time()
        self.tokens = float(TX_BURST)
        self.token_time = time.time()
        self.pending: dict[str, float] = {}       # announced hash -> time requested, this connection

    async def connect(self):
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=10)
        self.last_msg = time.time()

    async def send(self, cmd: bytes, payload: bytes):
        assert self.writer is not None
        self.writer.write(self.bridge.magic + cmd.ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload)
        await self.writer.drain()

    def strike(self, n: int, why: str) -> bool:
        self.strikes += n
        self.bridge.stats.strikes += n
        hs = self.bridge.host_strikes.setdefault(self.host, [0, time.time()])
        hs[0] += n
        hs[1] = time.time()
        if self.strikes >= STRIKE_LIMIT or hs[0] >= STRIKE_LIMIT:
            log.info("%s: dropped (%s)", self.name, why)
            return True
        return False

    def take_token(self) -> bool:
        now = time.time()
        self.tokens = min(TX_BURST, self.tokens + (now - self.token_time) * TX_RATE_PER_SEC)
        self.token_time = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True

    async def read_message(self):
        """Returns (cmd, payload) or (cmd, None) for a message that was drained without buffering."""
        assert self.reader is not None
        hdr = await asyncio.wait_for(self.reader.readexactly(24), timeout=IDLE_TIMEOUT)
        if hdr[:4] != self.bridge.magic:
            raise ValueError("bad magic")
        cmd = hdr[4:16].rstrip(b"\0")
        length = struct.unpack("<I", hdr[16:20])[0]
        if length > MAX_MSG_LEN:
            raise ValueError(f"oversized {clean_text(cmd)} ({length})")
        self.bridge.stats.bytes_in += 24 + length
        if cmd not in (b"version", b"verack", b"ping", b"pong", b"inv", b"tx", b"notfound", b"getdata", b"wtxidrelay") or (cmd == b"tx" and length > MAX_TX_BYTES):
            # Not something we act on: drain in chunks rather than hold it in memory.
            left = length
            while left:
                chunk = await asyncio.wait_for(self.reader.read(min(left, 65536)), timeout=60)
                if not chunk:
                    raise ConnectionError("closed mid-message")
                left -= len(chunk)
            self.last_msg = time.time()
            if cmd == b"tx":
                self.bridge.stats.oversized += 1
                if self.strike(10, "oversized tx"):
                    raise ValueError("strikes")
            return cmd, None
        payload = await asyncio.wait_for(self.reader.readexactly(length), timeout=60)
        if sha256d(payload)[:4] != hdr[20:24]:
            raise ValueError(f"bad checksum on {clean_text(cmd)}")
        self.last_msg = time.time()
        return cmd, payload

    def close(self):
        if self.writer:
            self.writer.close()


class Bridge:
    def __init__(self, args):
        self.args = args
        self.magic, self.default_port = NETWORKS[args.network]
        self.stats = Stats()
        self.seen: collections.OrderedDict[bytes, float] = collections.OrderedDict()        # wtxid (hash of the bytes) -> time
        self.delivered: collections.OrderedDict[str, list] = collections.OrderedDict()      # txid -> [time, distinct wtxids delivered]
        self.pending: dict[str, float] = {}           # announced hash -> time requested (any peer)
        self.banned: dict[str, float] = {}            # host -> until
        self.host_strikes: dict[str, list] = {}       # host -> [strikes carried across connections, last update]
        self.blake2b_hosts: dict[str, float] = {}        # host -> until; BLAKE2b peers met on the SHA256d seeds, skipped
        self.groups: collections.Counter = collections.Counter()   # /16 (v4) or /32 (v6) -> live connections
        self.rpc = None
        self.rpc_sem = asyncio.Semaphore(RPC_CONCURRENCY)
        if args.mode == "test":
            self.rpc = Rpc(args.rpc_url, args.rpc_cookie, args.rpc_user, args.rpc_password)
        self.node_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=NODE_QUEUE)
        self.loop = asyncio.get_event_loop()

    # ---- bookkeeping -------------------------------------------------------------
    def prune(self):
        now = time.time()
        for txid, t in list(self.pending.items()):
            if now - t > PENDING_TIMEOUT:
                del self.pending[txid]
        while self.delivered and now - next(iter(self.delivered.values()))[0] > TXID_MEMORY:
            self.delivered.popitem(last=False)
        for host, until in list(self.banned.items()):
            if until < now:
                del self.banned[host]
        for host, hs in list(self.host_strikes.items()):
            if now - hs[1] > STRIKE_DECAY:
                hs[0] //= 2
                hs[1] = now
                if hs[0] == 0:
                    del self.host_strikes[host]

    def remember_seen(self, wtxid: bytes):
        self.seen[wtxid] = time.time()
        if len(self.seen) > SEEN_LIMIT:
            for _ in range(SEEN_LIMIT // 10):
                self.seen.popitem(last=False)

    def want(self, key: str, by_wtxid: bool) -> bool:
        """key is the announced hash: a wtxid from a wtxidrelay peer, else a txid."""
        if by_wtxid:
            if bytes.fromhex(key)[::-1] in self.seen:
                return False
        else:
            if key in self.delivered:
                return False
        t = self.pending.get(key)
        if t and time.time() - t < PENDING_TIMEOUT:
            return False
        return len(self.pending) < MAX_PENDING_TOTAL

    # ---- transactions ------------------------------------------------------------
    async def handle_tx(self, raw: bytes, conn):
        self.stats.received += 1
        if len(raw) > MAX_TX_BYTES:
            self.stats.oversized += 1
            return conn.strike(10, "oversized tx") if conn else False
        wtxid = sha256d(raw)
        if wtxid in self.seen:
            return False
        try:
            txid = txid_of(raw)
        except Exception:
            self.stats.malformed += 1
            return conn.strike(5, "malformed tx") if conn else False
        self.remember_seen(wtxid)
        wkey = wtxid[::-1].hex()
        for key in (txid, wkey):
            self.pending.pop(key, None)
            if conn:
                conn.pending.pop(key, None)
        d = self.delivered.get(txid)
        if d:
            d[1] += 1
            if d[1] > MAX_WTXIDS_PER_TXID:
                # Another witness for a txid we already forwarded several times: a variant flood.
                return conn.strike(5, "witness variants") if conn else False
        else:
            self.delivered[txid] = [time.time(), 1]
        if self.args.mode == "count":
            return False
        if self.args.mode == "submit":
            try:
                self.node_queue.put_nowait(raw)
            except asyncio.QueueFull:
                self.stats.node_queue_drops += 1
            return False
        await self.rpc_test(raw, txid)
        return False

    async def rpc_test(self, raw: bytes, txid: str):
        """test mode: ask the node what it would do, submit nothing. Two read-only calls."""
        hexraw = raw.hex()
        async with self.rpc_sem:
            try:
                try:
                    await self.loop.run_in_executor(None, self.rpc.call, "getmempoolentry", [txid])
                    self.stats.known += 1          # the node already holds it; not a bridge result
                    return
                except RuntimeError as e:
                    if not str(e).startswith("-5"):
                        raise
                res = await self.loop.run_in_executor(None, self.rpc.call, "testmempoolaccept", [[hexraw]])
                r = res[0]
                if r.get("allowed"):
                    self.stats.accepted += 1
                    log.info("would accept %s", txid)
                else:
                    reason = r.get("reject-reason", "?")
                    if reason in ("txn-already-in-mempool", "txn-already-known"):
                        self.stats.known += 1
                    else:
                        self.stats.rejected[reason[:60]] += 1
                        log.info("would reject %s: %s", txid, reason)
            except Exception as e:
                self.stats.rpc_errors += 1
                log.warning("rpc failure for %s: %s", txid, e)

    # ---- SHA256d peers -----------------------------------------------------------
    async def peer_session(self, host: str, port: int):
        conn = Conn(self, host, port, f"{host}:{port}")
        group = host_group(host)
        try:
            await conn.connect()
        except Exception as e:
            self.stats.connect_failures += 1
            log.debug("connect %s failed: %s", conn.name, e.__class__.__name__)
            return
        self.stats.peers += 1
        self.groups[group] += 1
        ping_task = None
        try:
            if self.host_strikes.get(host, [0])[0] > 0:
                if conn.strike(FLAP_PENALTY, "reconnected after misbehaving"):
                    self.ban(host)
                    return
            await conn.send(b"version", version_payload(relay=True))
            ping_task = asyncio.ensure_future(self.pinger(conn))
            while True:
                cmd, payload = await conn.read_message()
                if payload is None:
                    continue
                try:
                    drop = await self.peer_message(conn, cmd, payload)
                except (IndexError, struct.error, ValueError, UnicodeDecodeError) as e:
                    self.stats.malformed += 1
                    drop = conn.strike(20, f"malformed {clean_text(cmd)}: {e.__class__.__name__}")
                if drop:
                    self.ban(host)
                    break
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError) as e:
            log.debug("%s: closed (%s)", conn.name, e.__class__.__name__)
        except ValueError as e:
            log.info("%s: dropped (%s)", conn.name, e)
            self.ban(host)
        finally:
            if ping_task:
                ping_task.cancel()
            self.stats.peers -= 1
            self.groups[group] -= 1
            for txid in conn.pending:
                self.pending.pop(txid, None)
            conn.close()

    def ban(self, host: str):
        self.stats.dropped_peers += 1
        self.stats.banned += 1
        self.banned[host] = time.time() + BAN_SECONDS

    async def pinger(self, conn):
        """Keeps the peer honest on a timer: a peer that stops talking after announcing must still answer for what it never delivered."""
        while True:
            await asyncio.sleep(PING_INTERVAL)
            if self.prune_peer(conn):
                self.ban(conn.host)
                conn.close()
                return
            try:
                await conn.send(b"ping", struct.pack("<Q", random.getrandbits(64)))
            except Exception:
                return

    async def peer_message(self, conn, cmd: bytes, payload: bytes) -> bool:
        """Returns True when the peer should be dropped."""
        if cmd == b"version":
            if conn.ready or conn.blake2b is not None:
                return conn.strike(50, "duplicate version")
            ver, services = struct.unpack_from("<iQ", payload, 0)
            ualen, i = read_varint(payload, 80)
            ua = clean_text(payload[i:i + ualen])
            conn.blake2b = bool(services & NODE_BLAKE2B)
            if conn.blake2b:
                # A BLAKE2b peer, one of our own network. It can only hand us what our node already sees; free the slot, no ban.
                self.stats.blake2b_peers += 1
                self.blake2b_hosts[conn.host] = time.time() + BAN_SECONDS
                log.info("%s: %s advertises BLAKE2B, a peer of our own network; releasing the slot", conn.name, ua)
                raise ConnectionError("blake2b peer")
            log.info("%s: %s protocol %d services %#x", conn.name, ua, ver, services)
            if ver >= 70016:
                await conn.send(b"wtxidrelay", b"")
            await conn.send(b"verack", b"")
        elif cmd == b"verack":
            conn.ready = True
        elif cmd == b"ping":
            await conn.send(b"pong", payload)
        elif cmd == b"inv" and conn.ready:
            n, i = read_varint(payload, 0)
            if n > MAX_INV_PER_MSG or i + n * 36 != len(payload):
                return conn.strike(20, "bad inv")
            if self.prune_peer(conn):
                return True
            want: list[tuple[int, bytes]] = []
            for _ in range(n):
                typ = struct.unpack_from("<I", payload, i)[0]
                h = payload[i + 4:i + 36]
                i += 36
                if typ not in (MSG_TX, MSG_WTX):
                    continue
                self.stats.announced += 1
                key = h[::-1].hex()
                if len(conn.pending) + len(want) >= MAX_PENDING_PER_PEER:
                    continue
                if self.want(key, typ == MSG_WTX):
                    want.append((typ, h))
                    self.pending[key] = conn.pending[key] = time.time()
            if want:
                self.stats.requested += len(want)
                await conn.send(b"getdata", varint(len(want)) + b"".join(struct.pack("<I", MSG_WTX if typ == MSG_WTX else MSG_WITNESS_TX) + h for typ, h in want))
        elif cmd == b"notfound" and conn.ready:
            n, i = read_varint(payload, 0)
            if n > MAX_INV_PER_MSG or i + n * 36 != len(payload):
                return conn.strike(20, "bad notfound")
            for _ in range(n):
                txid = payload[i + 4:i + 36][::-1].hex()
                i += 36
                self.stats.notfound += 1
                conn.pending.pop(txid, None)
                self.pending.pop(txid, None)
        elif cmd == b"tx" and conn.ready:
            if not conn.take_token():
                self.stats.rate_dropped += 1
                return conn.strike(1, "tx flood")
            return await self.handle_tx(payload, conn)
        elif cmd == b"tx":
            return conn.strike(20, "tx before handshake")
        return False

    def prune_peer(self, conn) -> bool:
        """Requests this peer never answered cost it strikes. Returns True when it is over the limit."""
        now = time.time()
        expired = [t for t, when in conn.pending.items() if now - when > PENDING_TIMEOUT]
        for t in expired:
            del conn.pending[t]
            self.stats.undelivered += 1
            log.debug("%s: never delivered %s", conn.name, t)
        if expired:
            return conn.strike(len(expired), "undelivered requests")
        return False

    # ---- the Knots node (P2P injection) ------------------------------------------
    async def node_link(self):
        host, port = self.args.node
        backoff = 5
        while True:
            conn = Conn(self, host, port, f"node {host}:{port}")
            try:
                await conn.connect()
                await conn.send(b"version", version_payload(relay=False))
                self.stats.node_link = "handshake"
                reader_task = asyncio.ensure_future(self.node_reader(conn))
                while not conn.ready:
                    await asyncio.sleep(0.2)
                    if reader_task.done():
                        raise ConnectionError("node closed during handshake")
                self.stats.node_link = "up"
                backoff = 5
                while not reader_task.done():
                    try:
                        raw = await asyncio.wait_for(self.node_queue.get(), timeout=1)
                    except asyncio.TimeoutError:
                        continue
                    await conn.send(b"tx", raw)
                    self.stats.submitted += 1
                raise ConnectionError("node link closed")
            except Exception as e:
                self.stats.node_link = "down"
                log.warning("node link: %s; retrying in %ds", e, backoff)
                conn.close()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)

    async def node_reader(self, conn):
        try:
            while True:
                cmd, payload = await conn.read_message()
                if cmd == b"version" and payload is not None:
                    await conn.send(b"verack", b"")
                elif cmd == b"verack":
                    conn.ready = True
                elif cmd == b"ping" and payload is not None:
                    await conn.send(b"pong", payload)
                # the node's inv/headers/getheaders/getdata are ignored; we announce nothing
        except Exception as e:
            log.debug("node reader: %s", e.__class__.__name__)

    # ---- peer supply -------------------------------------------------------------
    async def resolve_seeds(self):
        addrs = []
        for seed in self.args.dns_seed:
            try:
                infos = await self.loop.run_in_executor(None, socket.getaddrinfo, f"x9.{seed}", self.default_port, 0, socket.SOCK_STREAM)
                got = sorted({(ai[4][0], self.default_port) for ai in infos})
                log.info("seed %s: %d addresses", seed, len(got))
                addrs += got
            except Exception as e:
                log.warning("seed %s failed: %s", seed, e.__class__.__name__)
        return addrs

    def parse_peer(self, a: str):
        if a.startswith("["):
            h, p = a[1:].split("]:") if "]:" in a else (a[1:-1], self.default_port)
            return h, int(p)
        if a.count(":") == 1:
            h, p = a.split(":")
            return h, int(p)
        return a, self.default_port

    async def run(self):
        addrs = [self.parse_peer(a) for a in self.args.peer]
        if not self.args.no_dns:
            addrs += await self.resolve_seeds()
        random.shuffle(addrs)
        if not addrs:
            log.error("no peer addresses; give --peer or allow DNS")
            return
        log.info("%d candidate peers, keeping %d connections, mode %s", len(addrs), self.args.connections, self.args.mode)
        queue = collections.deque(addrs)
        tasks = set()
        if self.args.mode == "submit":
            tasks.add(asyncio.ensure_future(self.node_link()))
        deadline = time.time() + self.args.run_seconds if self.args.run_seconds else None
        next_stats = time.time() + self.args.stats_interval
        while True:
            self.prune()
            peers = sum(1 for t in tasks if getattr(t, "_is_peer", False) and not t.done())
            tried = 0
            while peers < self.args.connections and queue and tried < len(queue):
                host, port = queue.popleft()
                queue.append((host, port))
                tried += 1
                if self.banned.get(host, 0) > time.time() or self.blake2b_hosts.get(host, 0) > time.time() or self.groups[host_group(host)] >= 1:
                    continue
                t = asyncio.ensure_future(self.peer_session(host, port))
                t._is_peer = True
                tasks.add(t)
                t.add_done_callback(tasks.discard)
                peers += 1
            await asyncio.sleep(1)
            if time.time() >= next_stats:
                log.info(self.stats.line())
                next_stats = time.time() + self.args.stats_interval
            if deadline and time.time() >= deadline:
                for t in tasks:
                    t.cancel()
                log.info("final: %s", self.stats.line())
                return


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["count", "test", "submit"], default="count")
    ap.add_argument("--network", choices=list(NETWORKS), default="mainnet")
    ap.add_argument("--node", default=None, help="the Knots node's P2P address for submit mode (default 127.0.0.1:<network port>)")
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332", help="test mode only")
    ap.add_argument("--rpc-cookie", help="test mode only: path to the node's .cookie file (a whitelisted rpcauth user is better)")
    ap.add_argument("--rpc-user")
    ap.add_argument("--rpc-password")
    ap.add_argument("--peer", action="append", default=[], help="host[:port] to use (repeatable)")
    ap.add_argument("--dns-seed", action="append", default=None, help="DNS seed to query with the x9 filter (repeatable; default: the Bitcoin Core seeds)")
    ap.add_argument("--no-dns", action="store_true", help="only use --peer addresses")
    ap.add_argument("--connections", type=int, default=8)
    ap.add_argument("--stats-interval", type=int, default=60)
    ap.add_argument("--run-seconds", type=int, default=0, help="stop after this long (0 = run until interrupted)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if args.dns_seed is None:
        args.dns_seed = DNS_SEEDS
    if args.mode == "test" and not (args.rpc_cookie or (args.rpc_user and args.rpc_password)):
        ap.error("test mode needs --rpc-cookie or --rpc-user/--rpc-password")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    bridge = Bridge(args)
    if args.node:
        bridge.args.node = bridge.parse_peer(args.node)
    else:
        bridge.args.node = ("127.0.0.1", bridge.default_port)
    try:
        loop.run_until_complete(bridge.run())
    except KeyboardInterrupt:
        log.info("final: %s", bridge.stats.line())


if __name__ == "__main__":
    main()
