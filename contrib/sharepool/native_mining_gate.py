#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable miner job admission for the opt-in native regtest profile.

Native RPC verifies signatures, PoW, chain context and complete proposed blocks.
Python only parses wire data and enforces the miner's own payout/inclusion policy.
No signing keys, devices, networking listeners or mainnet activation live here.
The caller must check ready_for_dispatch() immediately before initial dispatch.
Later received work requests a new job; it never rewrites work already running.
"""
from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

try:
    import fcntl
except ImportError:  # A process lock is mandatory; never silently omit it.
    fcntl = None

from native_enforcement import (MAX_MANIFEST, MAX_SHARE_AGE, MAX_SHARES, RULES_HASH,
                                SHARE_BITS, Reader, Share, parse_coinbase)
from test_framework.messages import CBlock, CBlockHeader


REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
MAX_RECEIPTS = 128
MAX_JOBS = 64
MAX_TEMPLATES = 128
RETENTION_BLOCKS = 144
MAX_ARCHIVE_RECEIPTS = MAX_RECEIPTS * (RETENTION_BLOCKS + MAX_SHARE_AGE + 1)
MAX_ARCHIVE_TEMPLATES = MAX_TEMPLATES * (RETENTION_BLOCKS + MAX_SHARE_AGE + 1)
MAX_TEMPLATE_BYTES = 256 * 1024 * 1024
SCHEMA_VERSION = 2
MAX_REVISION = (1 << 63) - 1


class RecoveryRequired(ValueError):
    """The retained native anchor was lost; archive recovery is mandatory."""



def parse_share(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 1024:
        raise ValueError("share encoding exceeds bound")
    reader = Reader(raw)
    share = Share.read(reader)
    if reader.stream.read() or share.serialize() != raw:
        raise ValueError("noncanonical share encoding")
    return share


class _BlockReader:
    """Allocation-free canonical structural preflight for untrusted blocks."""
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    @property
    def remaining(self):
        return len(self.raw) - self.offset

    def skip(self, size):
        if not 0 <= size <= self.remaining:
            raise ValueError("truncated candidate block")
        self.offset += size

    def uint(self, size):
        start = self.offset
        self.skip(size)
        return int.from_bytes(self.raw[start:self.offset], "little")

    def count(self, minimum_bytes=1):
        prefix = self.uint(1)
        value = prefix if prefix < 253 else self.uint({253: 2, 254: 4, 255: 8}[prefix])
        if ((prefix >= 253 and value < {253: 253, 254: 65536, 255: 1 << 32}[prefix]) or
                value > self.remaining // minimum_bytes):
            raise ValueError("noncanonical or unbounded candidate vector")
        return value

    def variable(self):
        self.skip(self.count())


def _preflight_block(raw):
    reader = _BlockReader(raw)
    version = reader.uint(4)
    reader.skip((164 if version & 0x80000000 else 80) - 4)
    transactions = reader.count(60)  # A nonempty legacy transaction is >=60B.
    if not transactions:
        raise ValueError("empty candidate block")
    for unused in range(transactions):
        reader.skip(4)
        inputs, witness = reader.count(41), False
        if not inputs:
            if reader.uint(1) != 1:
                raise ValueError("empty inputs or unsupported witness flags")
            witness = True
            inputs = reader.count(41)
            if not inputs:
                raise ValueError("empty candidate transaction inputs")
        for unused_input in range(inputs):
            reader.skip(36)
            reader.variable()
            reader.skip(4)
        outputs = reader.count(9)
        if not outputs:
            raise ValueError("empty candidate transaction outputs")
        for unused_output in range(outputs):
            reader.skip(8)
            reader.variable()
        if witness:
            present = False
            for unused_input in range(inputs):
                count = reader.count()
                present |= bool(count)
                for unused_item in range(count):
                    reader.variable()
            if not present:
                raise ValueError("superfluous candidate witness encoding")
        reader.skip(4)
    if reader.remaining:
        raise ValueError("trailing candidate block data")


class _ExactBytesIO(BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.limit = len(raw)

    def read(self, size=-1):
        if size != -1 and not 0 <= size <= self.limit - self.tell():
            raise ValueError("truncated candidate block")
        return super().read(size)


def parse_block(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 4_000_000:
        raise ValueError("block encoding exceeds bound")
    # The test framework reader otherwise trusts CompactSize counts and turns
    # fixed-length EOF reads into zeros. Preflight bounds every loop by bytes
    # actually present, before any transaction/witness objects are allocated.
    _preflight_block(raw)
    stream, block = _ExactBytesIO(raw), CBlock()
    block.deserialize(stream)
    if stream.read() or block.serialize() != raw or not block.vtx:
        raise ValueError("noncanonical or empty candidate block")
    return block


class JobOmission(ValueError):
    def __init__(self, proof_ids):
        self.proof_ids = tuple(sorted(proof_ids))
        super().__init__("job omits known eligible unpaid work")


def immutable_header(header):
    header = CBlockHeader(header)
    for name in ("nNonce", "m_nonce2", "m_nonce3", "m_extranonce", "m_time_offset"):
        setattr(header, name, 0)
    return header.serialize()


def template_id(header):
    return hashlib.sha256(immutable_header(header)).hexdigest()


@dataclass(frozen=True)
class MiningAuthorization:
    block_bytes: bytes
    native_parent: str
    commitment: str
    receipt_sequence: int

    @property
    def job_id(self):
        return hashlib.sha256(self.block_bytes).hexdigest()

    def block_for_header(self, header_bytes):
        """Apply only the physical nonce/extranonce/search-time fields."""
        if type(header_bytes) is not bytes or len(header_bytes) != 164:
            raise ValueError("native v2 header required")
        header, stream = CBlockHeader(), BytesIO(header_bytes)
        header.deserialize(stream)
        block = parse_block(self.block_bytes)
        if (header.serialize() != header_bytes or
                immutable_header(header) != immutable_header(block)):
            raise ValueError("work changes the authorized template or settlement")
        for name in ("nNonce", "m_nonce2", "m_nonce3", "m_extranonce", "m_time_offset"):
            setattr(block, name, getattr(header, name))
        return block.serialize()


class NativeMiningGate:
    def __init__(self, path, *, rpc, pool, public_key, payout_script):
        if (type(pool) is not int or not 0 < pool < 1 << 256 or
                type(public_key) is not bytes or len(public_key) != 32 or
                type(payout_script) is not bytes or not 1 <= len(payout_script) <= 34):
            raise ValueError("explicit miner pool/key/payout binding required")
        self.rpc, self.pool = rpc, pool
        self.public_key, self.payout_script = public_key, payout_script
        self._check_network()
        self.path = Path(path)
        self.db, self._lock_fd = None, None
        if fcntl is None:
            raise ValueError("gate store requires a supported exclusive process lock")
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("gate store must be a regular file")
        finally:
            os.close(descriptor)
        # A separate persistent lock inode avoids interfering with SQLite's own
        # platform-specific database locks (notably on macOS). Never unlink it.
        lock_path = self.path.with_name(self.path.name + ".owner.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("gate process lock must be a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("gate store already has an owning process") from None
            self._lock_fd = descriptor
        except BaseException:
            os.close(descriptor)
            raise
        try:
            self.db = sqlite3.connect(str(self.path))
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ValueError("gate store requires WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self._initialize_store()
            self._validate_store()
            self.maintenance()
        except BaseException:
            self.close()
            raise

    def _config(self, version):
        return json.dumps({"version": version, "genesis": REGTEST_GENESIS, "pool": self.pool,
                           "public_key": self.public_key.hex(), "script": self.payout_script.hex()}, sort_keys=True)

    def _initialize_store(self):
        tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE config (value TEXT NOT NULL)")
                self.db.execute("INSERT INTO config VALUES (?)", (self._config(1),))
                self.db.execute("CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, proof_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
                self.db.execute("CREATE TABLE jobs (sequence INTEGER PRIMARY KEY, job_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
                self.db.execute("CREATE TABLE templates (job_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, data BLOB NOT NULL)")
            tables = {"config", "receipts", "jobs", "templates"}
        # Refuse extra tables/triggers/views or altered columns, including stores
        # newer than this implementation. Never infer safety from a version alone.
        if (tables not in ({"config", "receipts", "jobs", "templates"},
                           {"config", "receipts", "jobs", "templates", "state"}) or
                self.db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()):
            raise ValueError("gate store has an unsupported schema")
        saved = self.db.execute("SELECT value FROM config LIMIT 2").fetchall()
        version = 1 if saved == [(self._config(1),)] else SCHEMA_VERSION
        if saved != [(self._config(version),)]:
            raise ValueError("gate store belongs to another miner, pool or network")
        columns = {"config": ["value"], "jobs": ["sequence", "job_id", "data"],
                   "receipts": ["sequence", "proof_id", "data"],
                   "templates": ["job_id", "body_hash", "data"]}
        if version == SCHEMA_VERSION:
            columns["receipts"] += ["data_hash", "origin_height", "origin_parent"]
            columns["templates"] += ["origin_height", "origin_parent"]
            columns["state"] = ["singleton", "revision", "anchor_height", "anchor_hash", "pruned_through", "recovery"]
        if set(columns) != tables or any(
                [row[1] for row in self.db.execute("PRAGMA table_info(" + name + ")")] != wanted
                for name, wanted in columns.items()):
            raise ValueError("gate store has an unsupported schema")
        integer_columns = {"sequence", "origin_height", "singleton", "revision", "anchor_height", "pruned_through", "recovery"}
        primary_keys = {"config": None, "receipts": "sequence", "jobs": "sequence",
                        "templates": "job_id", "state": "singleton"}
        for table in columns:
            for unused_cid, name, sql_type, unused_null, default, primary in self.db.execute("PRAGMA table_info(" + table + ")"):
                wanted_type = "INTEGER" if name in integer_columns else "BLOB" if name == "data" else "TEXT"
                if sql_type != wanted_type or primary != int(name == primary_keys[table]) or default is not None:
                    raise ValueError("gate store has an unsupported schema")
        for table, identity in (("receipts", "proof_id"), ("jobs", "job_id")):
            indexes = self.db.execute("PRAGMA index_list(" + table + ")").fetchall()
            if not any(unique and not partial and
                       [row[2] for row in self.db.execute("PRAGMA index_info('" + name.replace("'", "''") + "')")] == [identity]
                       for unused_seq, name, unique, unused_origin, partial in indexes):
                raise ValueError("gate store lacks unique evidence identities")
        if version == 1:
            if self.db.execute("PRAGMA user_version").fetchone()[0] != 0:
                raise ValueError("gate store schema version mismatch")
            # v1 never pruned receipts. Validate its complete bounded archive
            # before migration, then initialize the permanent revision from it.
            self._validate_store(legacy=True)
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("ALTER TABLE receipts ADD COLUMN data_hash TEXT")
                self.db.execute("ALTER TABLE receipts ADD COLUMN origin_height INTEGER")
                self.db.execute("ALTER TABLE receipts ADD COLUMN origin_parent TEXT")
                self.db.execute("ALTER TABLE templates ADD COLUMN origin_height INTEGER")
                self.db.execute("ALTER TABLE templates ADD COLUMN origin_parent TEXT")
                for serial, data in self.db.execute("SELECT sequence,data FROM receipts"):
                    body = bytes(data)
                    origin = parse_share(body).envelope
                    self.db.execute("UPDATE receipts SET data_hash=?,origin_height=?,origin_parent=? WHERE sequence=?",
                                    (hashlib.sha256(body).hexdigest(), origin.height, f"{origin.native_parent:064x}", serial))
                for identity, data in self.db.execute("SELECT job_id,data FROM templates"):
                    envelope = parse_coinbase(parse_block(bytes(data)).vtx[0])[0].envelope
                    self.db.execute("UPDATE templates SET origin_height=?,origin_parent=? WHERE job_id=?",
                                    (envelope.height, f"{envelope.native_parent:064x}", identity))
                revision = self.db.execute("SELECT COALESCE(max(sequence),0) FROM receipts").fetchone()[0]
                self.db.execute("CREATE TABLE state (singleton INTEGER PRIMARY KEY, revision INTEGER NOT NULL, anchor_height INTEGER NOT NULL, anchor_hash TEXT NOT NULL, pruned_through INTEGER NOT NULL, recovery INTEGER NOT NULL)")
                self.db.execute("INSERT INTO state VALUES (1,?,0,?,0,0)", (revision, REGTEST_GENESIS))
                self.db.execute("UPDATE config SET value=?", (self._config(SCHEMA_VERSION),))
                self.db.execute("PRAGMA user_version=2")
        elif self.db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise ValueError("gate store schema version mismatch")

    def _bounded_table(self, table, limit, max_bytes, total_bytes=None):
        count, oversized, size = self.db.execute(
            "SELECT count(*), COALESCE(max(length(data)),0), COALESCE(sum(length(data)),0) FROM " + table).fetchone()
        if count > limit or oversized > max_bytes or (total_bytes is not None and size > total_bytes):
            raise ValueError("gate store exceeds persisted archive bounds")

    def _receipt(self, identity, raw):
        share = parse_share(raw)
        origin, header = share.envelope, share.header
        if (identity != f"{share.proof_id:064x}" or origin.pool != self.pool or
                origin.genesis != int(REGTEST_GENESIS, 16) or origin.rules != RULES_HASH or
                origin.version != 1 or origin.height < 1 or header.m_mm_rhs != origin.root or
                header.hashPrevBlock != origin.native_parent or header.m_height != origin.height):
            raise ValueError("persisted receipt failed identity validation")
        return share

    def _validate_store(self, legacy=False):
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("gate store failed SQLite integrity validation")
        self._bounded_table("receipts", MAX_RECEIPTS if legacy else MAX_ARCHIVE_RECEIPTS, 1024)
        self._bounded_table("templates", MAX_TEMPLATES if legacy else MAX_ARCHIVE_TEMPLATES,
                            4_000_000, MAX_TEMPLATE_BYTES)
        self._bounded_table("jobs", MAX_JOBS, 4_000_000)
        origin_headers = {}
        for identity, body_hash, data in self.db.execute("SELECT job_id,body_hash,data FROM templates"):
            raw = bytes(data)
            block = parse_block(raw)
            origin = parse_coinbase(block.vtx[0])[0].envelope
            if (hashlib.sha256(raw).hexdigest() != body_hash or template_id(block) != identity or
                    origin.pool != self.pool or origin.genesis != int(REGTEST_GENESIS, 16) or
                    origin.rules != RULES_HASH or origin.version != 1 or origin.height < 1 or
                    origin.height != block.m_height or origin.native_parent != block.hashPrevBlock or
                    origin.root != block.m_mm_rhs):
                raise ValueError("persisted origin template failed integrity validation")
            if not legacy and self.db.execute("SELECT origin_height,origin_parent FROM templates WHERE job_id=?", (identity,)).fetchone() != (origin.height, f"{origin.native_parent:064x}"):
                raise ValueError("persisted template height failed integrity validation")
            origin_headers[identity] = immutable_header(block)
        last_sequence = 0
        for sequence, identity, data in self.db.execute("SELECT sequence,proof_id,data FROM receipts ORDER BY sequence"):
            if type(sequence) is not int or not last_sequence < sequence <= MAX_REVISION:
                raise ValueError("persisted receipt revision is invalid")
            last_sequence = sequence
            raw = bytes(data)
            share = self._receipt(identity, raw)
            if origin_headers.get(template_id(share.header)) != immutable_header(share.header):
                raise ValueError("persisted receipt has no intact validated origin template")
            if not legacy and self.db.execute("SELECT data_hash,origin_height,origin_parent FROM receipts WHERE sequence=?", (sequence,)).fetchone() != (hashlib.sha256(raw).hexdigest(), share.envelope.height, f"{share.envelope.native_parent:064x}"):
                raise ValueError("persisted receipt hash or height failed integrity validation")
        for sequence, identity, data in self.db.execute("SELECT sequence,job_id,data FROM jobs"):
            raw = bytes(data)
            origin = parse_coinbase(parse_block(raw).vtx[0])[0].envelope
            if (type(sequence) is not int or sequence < 1 or hashlib.sha256(raw).hexdigest() != identity or
                    (origin.pool, origin.public_key, origin.payout_script) !=
                    (self.pool, self.public_key, self.payout_script)):
                raise ValueError("persisted job failed integrity validation")
        if not legacy:
            rows = self.db.execute("SELECT singleton,revision,anchor_height,anchor_hash,pruned_through,recovery FROM state LIMIT 2").fetchall()
            if len(rows) != 1:
                raise ValueError("gate recovery metadata is invalid")
            singleton, revision, height, identity, pruned, recovery = rows[0]
            if (singleton != 1 or type(revision) is not int or not last_sequence <= revision <= MAX_REVISION or
                    type(height) is not int or height < 0 or not self._hash(identity) or
                    type(pruned) is not int or not 0 <= pruned <= revision or recovery not in (0, 1)):
                raise ValueError("gate recovery metadata is invalid")
            if height == 0 and identity != REGTEST_GENESIS:
                raise ValueError("gate recovery anchor is invalid")

    @staticmethod
    def _hash(value):
        return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

    def _chain_snapshot(self):
        self._check_network()
        info = self.rpc("getblockchaininfo")
        height, tip = info.get("blocks"), self.rpc("getbestblockhash")
        if (type(height) is not int or height < 0 or not self._hash(tip) or
                self.rpc("getblockhash", height) != tip):
            raise ValueError("native tip changed during archive maintenance")
        return height, tip

    def maintenance(self):
        """Prune expired evidence only behind a durable 144-block native anchor.

        No paid-state shortcut is used: a permitted reorg may undo settlement.
        Losing the anchor permanently latches recovery, even if the tip later
        returns. Restore a complete older evidence archive; never clear the latch.
        """
        height, tip = self._chain_snapshot()
        revision, anchor_height, anchor_hash, pruned, recovery = self.db.execute(
            "SELECT revision,anchor_height,anchor_hash,pruned_through,recovery FROM state WHERE singleton=1").fetchone()
        if recovery:
            raise RecoveryRequired("gate requires complete archive recovery after a deep native reorganization")
        if height < anchor_height or self.rpc("getblockhash", anchor_height) != anchor_hash:
            with self.db:
                self.db.execute("UPDATE state SET recovery=1 WHERE singleton=1")
            raise RecoveryRequired("native chain lost the retained anchor; complete archive recovery required")
        new_anchor = max(anchor_height, height - RETENTION_BLOCKS)
        new_hash = self.rpc("getblockhash", new_anchor)
        if self.rpc("getbestblockhash") != tip:
            raise ValueError("native tip changed during archive maintenance")
        cutoff = new_anchor - MAX_SHARE_AGE
        # Validate would-be deletions before relying on height metadata. This
        # catches accidental live-store corruption without rehashing the entire
        # archive each time. Each retiring full body is read once, even when many
        # receipts share it.
        retiring_origins = {}
        for identity, in self.db.execute("SELECT job_id FROM templates WHERE origin_height<=?", (cutoff,)):
            retiring_origins[identity] = immutable_header(parse_block(self._template_bytes(identity)))
        for identity, in self.db.execute("SELECT proof_id FROM receipts WHERE origin_height<=?", (cutoff,)):
            self._receipt_bytes(identity, origins=retiring_origins)
        if self.rpc("getbestblockhash") != tip:
            raise ValueError("native tip changed during archive maintenance")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            dropped = self.db.execute("SELECT COALESCE(max(sequence),0) FROM receipts WHERE origin_height<=?", (cutoff,)).fetchone()[0]
            self.db.execute("DELETE FROM receipts WHERE origin_height<=?", (cutoff,))
            # Every retained receipt has origin_height > cutoff. Old jobs are
            # audit records and are not an admission route or evidence source.
            self.db.execute("DELETE FROM templates WHERE origin_height<=?", (cutoff,))
            self.db.execute("UPDATE state SET anchor_height=?,anchor_hash=?,pruned_through=? WHERE singleton=1",
                            (new_anchor, new_hash, max(pruned, dropped)))
        return {"tip": tip, "height": height, "anchor_height": new_anchor,
                "anchor_hash": new_hash, "revision": revision,
                "pruned_through": max(pruned, dropped)}

    def _check_network(self):
        if (self.rpc("getblockchaininfo").get("chain") != "regtest" or
                self.rpc("getblockhash", 0) != REGTEST_GENESIS):
            raise ValueError("native mining gate is restricted to regtest")

    def base_template(self):
        """Get an explicitly incomplete template; this never authorizes mining."""
        self.maintenance()
        result = self.rpc("getblocktemplate", {
            "rules": ["segwit", "blake2b", "sharepool"],
            "capabilities": ["skip_validity_test"],
            "blockreservedsize": 90_000, "blockreservedweight": 360_000,
        })
        expected = {"version": 1, "genesis": REGTEST_GENESIS,
                    "rules_root": f"{RULES_HASH:064x}", "share_bits": f"{SHARE_BITS:08x}",
                    "max_share_age": MAX_SHARE_AGE, "max_shares": MAX_SHARES,
                    "max_manifest_bytes": MAX_MANIFEST, "requires_completion": True}
        profile = result.get("sharepool", {})
        if (any(profile.get(key) != value for key, value in expected.items()) or
                "!sharepool" not in result.get("rules", []) or
                type(profile.get("activation_height")) is not int or
                not 1 <= profile["activation_height"] <= result.get("height", 0)):
            raise ValueError("native node does not advertise the required active settlement profile")
        return result

    def receive(self, raw):
        """Validate through native libsecp/PoW, then durably acknowledge once."""
        self.maintenance()
        share = parse_share(raw)
        if share.envelope.pool != self.pool:
            raise ValueError("share belongs to another pool")
        self._require_origin(share)
        result = self.rpc("validatesharepoolshare", raw.hex())
        identity = f"{share.proof_id:064x}"
        expected = {"valid": True, "proof_id": identity, "pool": f"{self.pool:064x}",
                    "origin_height": share.envelope.height,
                    "owner": share.envelope.public_key.hex(),
                    "payout_script": share.envelope.payout_script.hex(),
                    "share_bits": f"{SHARE_BITS:08x}"}
        if any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native share response does not match received work")
        self.maintenance()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            return self._record_receipt(share)

    def _require_origin(self, share):
        identity = template_id(share.header)
        saved = self.db.execute("SELECT body_hash,length(data) FROM templates WHERE job_id=?", (identity,)).fetchone()
        if saved is None:
            raise ValueError("share origin template has not been validated locally")
        if not 1 <= saved[1] <= 4_000_000:
            raise ValueError("persisted origin template exceeds bound")
        body = bytes(self.db.execute("SELECT data FROM templates WHERE job_id=?", (identity,)).fetchone()[0])
        if (hashlib.sha256(body).hexdigest() != saved[0] or
                immutable_header(parse_block(body)) != immutable_header(share.header)):
            raise ValueError("persisted origin template failed integrity validation")
    def _record_receipt(self, share):
        """Caller has completed native proof validation and owns a transaction."""
        identity = f"{share.proof_id:064x}"
        if self.db.execute("SELECT 1 FROM receipts WHERE proof_id=?", (identity,)).fetchone():
            if self._receipt_bytes(identity) != share.serialize():
                raise ValueError("persisted receipt differs from received proof")
            return False
        active_floor = self.rpc("getblockchaininfo")["blocks"] + 1 - MAX_SHARE_AGE
        if (self.db.execute("SELECT count(*) FROM receipts WHERE origin_height>=?", (active_floor,)).fetchone()[0] >= MAX_RECEIPTS or
                self.db.execute("SELECT count(*) FROM receipts").fetchone()[0] >= MAX_ARCHIVE_RECEIPTS):
            raise ValueError("receipt archive is full; no work was acknowledged")
        revision = self.db.execute("SELECT revision FROM state WHERE singleton=1").fetchone()[0]
        if revision >= MAX_REVISION:
            raise ValueError("receipt revision exhausted; complete archive recovery required")
        raw = share.serialize()
        self.db.execute("INSERT INTO receipts(sequence,proof_id,data,data_hash,origin_height,origin_parent) VALUES (?,?,?,?,?,?)",
                        (revision + 1, identity, raw, hashlib.sha256(raw).hexdigest(), share.envelope.height,
                         f"{share.envelope.native_parent:064x}"))
        self.db.execute("UPDATE state SET revision=? WHERE singleton=1", (revision + 1,))
        return True

    def _validate_template(self, raw):
        profile = self.base_template()  # An inactive peer's proposal acceptance is insufficient.
        block = parse_block(raw)
        manifest, unused_payouts = parse_coinbase(block.vtx[0])
        if manifest.envelope.pool != self.pool or manifest.envelope.height != profile["height"]:
            raise ValueError("template pool or native height mismatch")
        parent = f"{block.hashPrevBlock:064x}"
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("job no longer extends the native tip")
        proposal = self.rpc("getblocktemplate", {"mode": "proposal",
            "rules": ["segwit", "blake2b", "sharepool"], "data": raw.hex()})
        if proposal is not None:
            raise ValueError("native node rejected completed settlement job: " + str(proposal))
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("native tip changed during job validation")
        self.maintenance()
        return block, manifest

    def _cache_template(self, raw, block):
        identity = template_id(block)
        saved = self.db.execute("SELECT 1 FROM templates WHERE job_id=?", (identity,)).fetchone()
        if not saved:
            active_floor = self.rpc("getblockchaininfo")["blocks"] + 1 - MAX_SHARE_AGE
            if (self.db.execute("SELECT count(*) FROM templates WHERE origin_height>=?", (active_floor,)).fetchone()[0] >= MAX_TEMPLATES or
                    self.db.execute("SELECT count(*) FROM templates").fetchone()[0] >= MAX_ARCHIVE_TEMPLATES or
                    self.db.execute("SELECT COALESCE(sum(length(data)),0) FROM templates").fetchone()[0] + len(raw) > MAX_TEMPLATE_BYTES):
                raise ValueError("validated template archive is full")
            self.db.execute("INSERT INTO templates VALUES (?,?,?,?,?)",
                            (identity, hashlib.sha256(raw).hexdigest(), raw, block.m_height,
                             f"{block.hashPrevBlock:064x}"))
        return identity

    def register_template(self, raw):
        """Validate a full current or still-eligible historical origin block.

        Native RPC rewinds a temporary UTXO cache by at most three active-chain
        blocks; it never rewinds the live node. Unknown/expired/orphaned origins
        fail closed. This verifies evidence and never authorizes hash power.
        """
        profile = self.base_template()
        block = parse_block(raw)
        manifest, unused = parse_coinbase(block.vtx[0])
        origin = manifest.envelope
        if (origin.pool != self.pool or
                not max(profile["sharepool"]["activation_height"], profile["height"] - MAX_SHARE_AGE)
                <= origin.height <= profile["height"]):
            raise ValueError("template pool or eligible native height mismatch")
        tip = self.rpc("getbestblockhash")
        result = self.rpc("validatesharepooltemplate", raw.hex())
        expected = {"valid": True, "native_tip": tip,
                    "native_parent": f"{block.hashPrevBlock:064x}",
                    "origin_height": origin.height, "commitment": f"{block.m_mm_rhs:064x}"}
        if any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native template response does not match complete origin")
        if self.rpc("getbestblockhash") != tip:
            raise ValueError("native tip changed during origin validation")
        self.maintenance()
        with self.db:
            return self._cache_template(raw, block)

    def authorize(self, raw):
        block, manifest = self._validate_template(raw)
        origin = manifest.envelope
        if (origin.pool, origin.public_key, origin.payout_script) != (
                self.pool, self.public_key, self.payout_script):
            raise ValueError("job does not bind this miner's registered key and payout")
        parent = f"{block.hashPrevBlock:064x}"
        # A coordinator may introduce proofs directly in a job. Those proofs
        # need the same full-origin verification as gossip-received work.
        for share in manifest.shares:
            self._require_origin(share)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            for share in manifest.shares:
                self._record_receipt(share)
        # Only now is the parent's paid-state opening authenticated by native
        # consensus. Unseen work is not a Bitcoin block-validity condition.
        paid = {entry.proof_id for entry in manifest.parent_state}
        included = {share.proof_id for share in manifest.shares}
        missing, sequence, ancestors = [], 0, {}
        for serial, identity, data in self.db.execute("SELECT sequence,proof_id,data FROM receipts ORDER BY sequence"):
            sequence = serial
            share = self._receipt(identity, bytes(data))
            if self.db.execute("SELECT data_hash FROM receipts WHERE proof_id=?", (identity,)).fetchone()[0] != hashlib.sha256(bytes(data)).hexdigest():
                raise ValueError("persisted receipt hash failed integrity validation")
            height = share.envelope.height
            if not max(1, origin.height - MAX_SHARE_AGE) <= height <= origin.height:
                continue
            if height not in ancestors:
                ancestors[height] = self.rpc("getblockhash", height - 1)
            if ancestors[height] != f"{share.header.hashPrevBlock:064x}":
                continue
            if share.proof_id not in paid and share.proof_id not in included:
                missing.append(identity)
        if missing:
            raise JobOmission(missing)
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("native tip changed during job validation")
        sequence = self.db.execute("SELECT revision FROM state WHERE singleton=1").fetchone()[0]
        authorization = MiningAuthorization(raw, parent, f"{origin.root:064x}", sequence)
        with self.db:
            self._cache_template(raw, block)
            self.db.execute("INSERT OR IGNORE INTO jobs(job_id,data) VALUES (?,?)", (authorization.job_id, raw))
            self.db.execute("DELETE FROM jobs WHERE sequence NOT IN (SELECT sequence FROM jobs ORDER BY sequence DESC LIMIT ?)", (MAX_JOBS,))
        return authorization

    def template_bytes(self, identity):
        """Read a retained, validated origin body by normalized template ID."""
        self.maintenance()
        return self._template_bytes(identity)

    def _template_bytes(self, identity):
        if not self._hash(identity):
            raise ValueError("invalid template identity")
        saved = self.db.execute("SELECT body_hash,length(data),origin_height,origin_parent FROM templates WHERE job_id=?", (identity,)).fetchone()
        if saved is None or not 1 <= saved[1] <= 4_000_000:
            raise ValueError("unknown or oversized retained template")
        raw = bytes(self.db.execute("SELECT data FROM templates WHERE job_id=?", (identity,)).fetchone()[0])
        block = parse_block(raw)
        if (hashlib.sha256(raw).hexdigest() != saved[0] or template_id(block) != identity or
                (block.m_height, f"{block.hashPrevBlock:064x}") != saved[2:]):
            raise ValueError("persisted origin template failed integrity validation")
        return raw

    def receipt_bytes(self, identity):
        """Read a retained proof without giving it another acknowledgment."""
        self.maintenance()
        return self._receipt_bytes(identity)

    def _receipt_bytes(self, identity, *, origins=None):
        if not self._hash(identity):
            raise ValueError("invalid proof identity")
        saved = self.db.execute("SELECT data_hash,length(data),origin_height,origin_parent FROM receipts WHERE proof_id=?", (identity,)).fetchone()
        if saved is None or not 1 <= saved[1] <= 1024:
            raise ValueError("unknown or oversized retained receipt")
        raw = bytes(self.db.execute("SELECT data FROM receipts WHERE proof_id=?", (identity,)).fetchone()[0])
        if hashlib.sha256(raw).hexdigest() != saved[0]:
            raise ValueError("persisted receipt hash failed integrity validation")
        share = self._receipt(identity, raw)
        if (share.envelope.height, f"{share.envelope.native_parent:064x}") != saved[2:]:
            raise ValueError("persisted receipt height or parent failed integrity validation")
        if origins is None:
            self._require_origin(share)
        elif origins.get(template_id(share.header)) != immutable_header(share.header):
            raise ValueError("retiring receipt has no intact validated origin template")
        return raw

    def active_inventory(self):
        """Bounded canonical next-block evidence; never exports history by default.

        The revision is a permanent receipt high-water mark, not an assertion
        that this active inventory contains every previously acknowledged proof.
        Callers must preserve item hashes and recheck the tip around transfers.
        """
        snapshot = self.maintenance()
        floor, ceiling = max(1, snapshot["height"] + 1 - MAX_SHARE_AGE), snapshot["height"] + 1
        items, ancestors = [], {}
        # Inventory reads only bounded scalar metadata, never repeatedly hashes
        # up to256MiB of bodies. Startup validates metadata against all retained
        # bodies; the byte-read APIs independently hash/check each actual object.
        for kind, table, identity_column, hash_column, maximum, max_size in (
                ("template", "templates", "job_id", "body_hash", MAX_TEMPLATES, 4_000_000),
                ("receipt", "receipts", "proof_id", "data_hash", MAX_RECEIPTS, 1024)):
            rows = self.db.execute("SELECT " + identity_column + "," + hash_column +
                                   ",length(data),origin_height,origin_parent FROM " + table +
                                   " WHERE origin_height BETWEEN ? AND ? ORDER BY " + identity_column,
                                   (floor, ceiling))
            seen = 0
            for identity, digest, size, height, parent in rows:
                seen += 1
                if (seen > maximum or not self._hash(identity) or not self._hash(digest) or
                        not self._hash(parent) or type(size) is not int or not 1 <= size <= max_size or
                        type(height) is not int):
                    raise ValueError("active evidence exceeds archive bounds or has invalid metadata")
                if height not in ancestors:
                    ancestors[height] = self.rpc("getblockhash", height - 1)
                if parent != ancestors[height]:
                    continue
                items.append({"kind": kind, "id": identity, "sha256": digest,
                              "bytes": size, "origin_height": height, "origin_parent": parent})
        if self.rpc("getbestblockhash") != snapshot["tip"]:
            raise ValueError("native tip changed during evidence inventory")
        return dict(snapshot, items=items)

    def is_current(self, authorization):
        return self.maintenance()["tip"] == authorization.native_parent

    def needs_refresh(self, authorization):
        snapshot = self.maintenance()
        return snapshot["revision"] > authorization.receipt_sequence or snapshot["tip"] != authorization.native_parent

    def ready_for_dispatch(self, authorization):
        """Fence new dispatch on the current profile, native tip and receipts.

        A tip or receipt can still change after this call. The caller must keep
        observing refresh signals while hashing; solved jobs remain immutable.
        """
        self.base_template()
        return not self.needs_refresh(authorization)

    def close(self):
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
