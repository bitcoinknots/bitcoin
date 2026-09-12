#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable local mining policy for hash-only regtest snapshots.

The append-only journal retains every acknowledged origin and proof. Its finite
quota stops admission before acknowledgment; it never evicts evidence. Native
RPC, not a local inventory or successful snapshot storage, establishes validity.
One owner thread/process must use a gate. No RPC runs inside a write transaction.
"""
from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct

import native_archive
from hash_snapshot import (Snapshot, TemplateRecord, Share, RULES_HASH, MAX_SNAPSHOT_BYTES,
    MAX_TEMPLATE_BYTES, MAX_SHARE_AGE, parse_share, candidate, normalize_template)
from native_mining_gate import (MiningAuthorization, JobOmission, parse_block, immutable_header,
    template_id, _process_lock, fcntl, REGTEST_GENESIS)
from native_enforcement import is_payout_script
from test_framework.messages import CBlockHeader

SNAPSHOT, TEMPLATE, PROOF = 0, 1, 2
RECORD_OVERHEAD = 149
LIMITS = (MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, 1024)


class TemplateOmission(ValueError):
    def __init__(self, template_ids):
        self.template_ids = tuple(sorted(template_ids))
        super().__init__("job omits known eligible origin templates")


@dataclass(frozen=True)
class HashMiningAuthorization(MiningAuthorization):
    snapshot_bytes: bytes
    evidence_sequence: int


class HashMiningGate:
    def __init__(self, path, *, rpc, pool, public_key, payout_script,
                 quota=native_archive.DEFAULT_QUOTA, trusted_head_path=None):
        if (type(pool) is not int or not 0 < pool < 1 << 256 or type(public_key) is not bytes or
                len(public_key) != 32 or type(payout_script) is not bytes or not is_payout_script(payout_script) or
                type(quota) is not int or not 4096 <= quota <= native_archive.MAX_QUOTA):
            raise ValueError("invalid explicit gate policy or journal quota")
        if fcntl is None:
            raise ValueError("exclusive process locks are required")
        self.rpc, self.pool, self.public_key, self.payout_script = rpc, pool, public_key, payout_script
        self.path, self.quota = Path(path), quota
        self.head_path = Path(trusted_head_path) if trusted_head_path is not None else Path(str(self.path) + ".archive-head.json")
        if self.head_path.absolute() == self.path.absolute():
            raise ValueError("protected head must be separate from database")
        self.db, self._lock_fd, self._head_lock_fd, self._sealed_head = None, None, None, None
        self._context()
        self.config = native_archive.canonical({"schema": 1, "profile": "hash-only-v2", "genesis": REGTEST_GENESIS,
            "rules": f"{RULES_HASH:064x}", "pool": f"{pool:064x}", "public_key": public_key.hex(), "script": payout_script.hex()})
        self.binding = hashlib.sha256(self.config).hexdigest()
        self._lock_fd = _process_lock(Path(str(self.path) + ".owner.lock"))
        try:
            self._head_lock_fd = _process_lock(Path(str(self.head_path) + ".owner.lock"))
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("gate database must be a regular file")
            finally:
                os.close(descriptor)
            self.db = sqlite3.connect(str(self.path))
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ValueError("gate requires SQLite WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            pages = (quota + 128 * 1024 * 1024) // self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute("PRAGMA max_page_count=" + str(pages))
            self._initialize()
            self._head()  # Bound checkpoint fields before materializing initialized.
            initialized = self.db.execute("SELECT initialized FROM journal_meta").fetchone()[0]
            prefix = native_archive.read_head(self.head_path) if initialized else native_archive.initial_head(self.binding)
            if not initialized and (self.head_path.exists() or self.head_path.is_symlink()):
                prefix = native_archive.read_head(self.head_path)
            self._verify_store(prefix)
            self._sealed_head = prefix
            self._seal(initial=not initialized)
        except BaseException:
            self.close()
            raise

    def _context(self):
        info = self.rpc("getblockchaininfo")
        profile = self.rpc("getsharepoolhashstatus")
        tip = self.rpc("getbestblockhash")
        height = info.get("blocks") if isinstance(info, dict) else None
        if (not isinstance(info, dict) or info.get("chain") != "regtest" or type(height) is not int or height < 0 or
                self.rpc("getblockhash", 0) != REGTEST_GENESIS or not native_archive.is_hash(tip) or
                self.rpc("getblockhash", height) != tip or not isinstance(profile, dict) or
                profile.get("mode") != "hash-only-v2" or profile.get("rules") != f"{RULES_HASH:064x}" or
                profile.get("max_snapshot_bytes") != MAX_SNAPSHOT_BYTES):
            raise ValueError("active native regtest hash-only v2 profile required")
        return height, tip

    def _stable(self, tip):
        if self.rpc("getbestblockhash") != tip:
            raise ValueError("native tip changed during gate validation")

    def _initialize(self):
        objects = self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if not objects:
            if self.head_path.exists() or self.head_path.is_symlink():
                raise ValueError("empty database cannot replace a sealed journal")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE config (value BLOB NOT NULL)")
                self.db.execute("INSERT INTO config VALUES (?)", (self.config,))
                self.db.execute("CREATE TABLE journal (sequence INTEGER PRIMARY KEY, kind INTEGER NOT NULL, identity TEXT NOT NULL, digest TEXT NOT NULL, data BLOB NOT NULL, previous TEXT NOT NULL, root TEXT NOT NULL, revision INTEGER NOT NULL, height INTEGER NOT NULL, parent TEXT NOT NULL, UNIQUE(kind,identity))")
                self.db.execute("CREATE INDEX journal_context ON journal(kind,height)")
                self.db.execute("CREATE TABLE journal_meta (value TEXT NOT NULL, initialized INTEGER NOT NULL)")
                self.db.execute("INSERT INTO journal_meta VALUES (?,0)", (native_archive.canonical(native_archive.initial_head(self.binding)).decode(),))
        elif set(objects) != {("table", "config"), ("table", "journal"), ("table", "journal_meta"), ("index", "journal_context")}:
            raise ValueError("unsupported gate database schema; no implicit legacy migration")
        columns = {"config": ["value"], "journal": ["sequence", "kind", "identity", "digest", "data", "previous", "root", "revision", "height", "parent"], "journal_meta": ["value", "initialized"]}
        for table, expected in columns.items():
            if [row[1] for row in self.db.execute("PRAGMA table_info(" + table + ")")] != expected:
                raise ValueError("invalid journal schema")
        if self.db.execute("SELECT typeof(value),length(value) FROM config LIMIT 2").fetchall() != [("blob", len(self.config))]:
            raise ValueError("journal configuration exceeds its exact bound")
        if self.db.execute("SELECT value FROM config LIMIT 2").fetchall() != [(self.config,)]:
            raise ValueError("journal belongs to another profile or miner")

    def _head(self):
        bounded = self.db.execute("SELECT typeof(value),length(value),typeof(initialized) FROM journal_meta LIMIT 2").fetchall()
        if (len(bounded) != 1 or bounded[0][0] != "text" or bounded[0][2] != "integer" or
                type(bounded[0][1]) is not int or not 1 <= bounded[0][1] <= 4096):
            raise ValueError("journal checkpoint metadata exceeds its bound")
        rows = self.db.execute("SELECT value,initialized FROM journal_meta LIMIT 2").fetchall()
        if len(rows) != 1 or type(rows[0][0]) is not str or len(rows[0][0]) > 4096 or rows[0][1] not in (0, 1):
            raise ValueError("invalid journal checkpoint metadata")
        result = native_archive.check_head(json.loads(rows[0][0]))
        if result["binding"] != self.binding or native_archive.canonical(result).decode() != rows[0][0] or result["bytes"] > self.quota:
            raise ValueError("journal binding or quota mismatch")
        return result

    @staticmethod
    def _describe(kind, raw):
        if kind == SNAPSHOT:
            value = Snapshot.deserialize(raw)
            return value.hash_hex, value.envelope.height, f"{value.envelope.native_parent:064x}"
        if kind == TEMPLATE:
            value = TemplateRecord.from_block(raw)
            value.serialize()
            if value.data != raw:
                raise ValueError("stored template is not normalized")
            block = parse_block(raw)
            return f"{value.template_id:064x}", block.m_height, f"{block.hashPrevBlock:064x}"
        if kind == PROOF:
            value = parse_share(raw)
            return f"{value.proof_id:064x}", value.envelope.height, f"{value.envelope.native_parent:064x}"
        raise ValueError("unknown journal event kind")

    def _next(self, head, kind, identity, raw):
        if (type(kind) is not int or kind not in (SNAPSHOT, TEMPLATE, PROOF) or
                not native_archive.is_hash(identity) or type(raw) is not bytes or not 1 <= len(raw) <= LIMITS[kind]):
            raise ValueError("invalid bounded journal event")
        sequence, revision = head["events"] + 1, head["receipt_revision"] + int(kind == PROOF)
        digest = hashlib.sha256(raw).hexdigest()
        root = hashlib.sha256(b"SharePool/hash-gate/event/v2\0" + bytes.fromhex(head["root"]) +
            struct.pack("<QBQI", sequence, kind, revision, len(raw)) + bytes.fromhex(identity) + bytes.fromhex(digest)).hexdigest()
        result = dict(head, events=sequence, root=root, receipt_revision=revision, bytes=head["bytes"] + RECORD_OVERHEAD + len(raw))
        if result["bytes"] > self.quota or sequence > native_archive.MAX_EVENTS:
            raise ValueError("journal quota exhausted; no work acknowledged")
        return result, digest

    def _verify_store(self, prefix):
        head = self._head()
        if prefix["binding"] != self.binding or prefix["events"] > head["events"]:
            raise ValueError("journal is behind protected high-water")
        count, size, bad = self.db.execute("SELECT count(*),COALESCE(sum(length(data)+?),0),COALESCE(sum(kind NOT IN (0,1,2) OR typeof(data)!='blob' OR length(data)<1 OR length(data)>CASE kind WHEN 0 THEN ? WHEN 1 THEN ? ELSE 1024 END),0) FROM journal", (RECORD_OVERHEAD, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES)).fetchone()
        if count != head["events"] or size != head["bytes"] or count > native_archive.MAX_EVENTS or bad:
            raise ValueError("journal count or data length failed integrity")
        invalid_scalars = self.db.execute("SELECT 1 FROM journal WHERE typeof(sequence)!='integer' OR sequence<1 OR typeof(kind)!='integer' OR typeof(revision)!='integer' OR revision<0 OR typeof(height)!='integer' OR height<1 OR height>4294967295 OR typeof(identity)!='text' OR length(identity)!=64 OR typeof(digest)!='text' OR length(digest)!=64 OR typeof(previous)!='text' OR length(previous)!=64 OR typeof(root)!='text' OR length(root)!=64 OR typeof(parent)!='text' OR length(parent)!=64 LIMIT 1").fetchone()
        if invalid_scalars is not None:
            raise ValueError("journal scalar metadata exceeds its bound")
        current = native_archive.initial_head(self.binding)
        matched = current == prefix
        for sequence, kind, identity, digest, raw, previous, root, revision, height, parent in self.db.execute("SELECT * FROM journal ORDER BY sequence"):
            expected, expected_digest = self._next(current, kind, identity, raw)
            if (sequence != expected["events"] or digest != expected_digest or previous != current["root"] or
                    root != expected["root"] or revision != expected["receipt_revision"] or
                    self._describe(kind, raw) != (identity, height, parent)):
                raise ValueError("journal contains missing or corrupt acknowledged evidence")
            current = expected
            if sequence == prefix["events"]:
                matched = current == prefix
        if current != head or not matched:
            raise ValueError("journal diverges from protected high-water")
        # Every acknowledged proof retains its complete normalized origin body.
        for identity, in self.db.execute("SELECT identity FROM journal WHERE kind=2"):
            self._require_origin(parse_share(self._read(PROOF, identity)))

    def _check_seal(self):
        if native_archive.read_head(self.head_path) != self._sealed_head:
            raise ValueError("protected checkpoint changed while gate was open")
        if self._head() != self._sealed_head:
            raise ValueError("unsealed journal commit requires a verified restart")

    def _seal(self, *, initial=False):
        head = self._head()
        if not initial and native_archive.read_head(self.head_path) != self._sealed_head:
            raise ValueError("protected checkpoint changed before acknowledgment")
        if not initial and head == self._sealed_head:
            return
        native_archive.write_head(self.head_path, head, exclusive=initial and not self.head_path.exists())
        with self.db:
            self.db.execute("UPDATE journal_meta SET initialized=1")
        self._sealed_head = head

    def _append(self, kind, raw):
        identity, height, parent = self._describe(kind, raw)
        saved = self.db.execute("SELECT 1 FROM journal WHERE kind=? AND identity=?", (kind, identity)).fetchone()
        if saved is not None:
            if self._read(kind, identity) != raw:
                raise ValueError("acknowledged evidence identity has conflicting bytes")
            return False
        previous = self._head()
        current, digest = self._next(previous, kind, identity, raw)
        self.db.execute("INSERT INTO journal VALUES (?,?,?,?,?,?,?,?,?,?)", (current["events"], kind, identity, digest,
            raw, previous["root"], current["root"], current["receipt_revision"], height, parent))
        self.db.execute("UPDATE journal_meta SET value=?", (native_archive.canonical(current).decode(),))
        return True

    def _persist(self, items):
        self._check_seal()
        if not items:
            return []
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            changed = [self._append(kind, raw) for kind, raw in items]
        self._seal()
        return changed

    def _read(self, kind, identity):
        if not native_archive.is_hash(identity):
            raise ValueError("canonical evidence hash required")
        saved = self.db.execute("SELECT digest,length(data),height,parent FROM journal WHERE kind=? AND identity=? AND typeof(data)='blob' AND length(data) BETWEEN 1 AND ? AND typeof(digest)='text' AND length(digest)=64 AND typeof(height)='integer' AND height BETWEEN 1 AND 4294967295 AND typeof(parent)='text' AND length(parent)=64", (kind, identity, LIMITS[kind])).fetchone()
        if saved is None:
            if self.db.execute("SELECT 1 FROM journal WHERE kind=? AND identity=?", (kind, identity)).fetchone():
                raise ValueError("stored evidence metadata exceeds its bound")
            raise KeyError(identity)
        if type(saved[1]) is not int or not 1 <= saved[1] <= LIMITS[kind]:
            raise ValueError("stored evidence exceeds byte bound")
        raw = self.db.execute("SELECT data FROM journal WHERE kind=? AND identity=?", (kind, identity)).fetchone()[0]
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != saved[0] or self._describe(kind, raw) != (identity, saved[2], saved[3]):
            raise ValueError("stored evidence failed read-time integrity")
        return raw

    def archive_head(self):
        self._check_seal()
        return dict(self._sealed_head)

    def snapshot_bytes(self, identity):
        return self._read(SNAPSHOT, f"{identity:064x}" if type(identity) is int else identity)

    def _snapshot(self, identity):
        identity = f"{identity:064x}" if type(identity) is int else identity
        try:
            raw = self.snapshot_bytes(identity)
        except KeyError:
            result = self.rpc("getsharepoolhashsnapshot", identity)
            if not isinstance(result, dict) or result.get("hash") != identity:
                raise ValueError("native snapshot lookup returned another commitment")
            encoded = result.get("data")
            if type(encoded) is not str or not 1 <= len(encoded) <= MAX_SNAPSHOT_BYTES * 2:
                raise ValueError("native snapshot lookup exceeds byte bound")
            raw = bytes.fromhex(encoded)
            if Snapshot.deserialize(raw).hash_hex != identity:
                raise ValueError("native snapshot bytes do not match commitment")
            self.register_snapshot(raw)
        return Snapshot.deserialize(raw)

    def register_snapshot(self, raw):
        """Store canonical content. Native 'stored' is never a validity assertion."""
        self._check_seal()
        snapshot = Snapshot.deserialize(raw)
        result = self.rpc("submitsharepoolhashsnapshot", raw.hex())
        if (not isinstance(result, dict) or result.get("hash") != snapshot.hash_hex or
                result.get("status") not in ("stored", "present") or type(result.get("missing")) is not list or
                any(not native_archive.is_hash(value) for value in result["missing"])):
            raise ValueError("native snapshot storage response failed binding")
        self._persist([(SNAPSHOT, raw)])
        return snapshot.hash_hex

    def _native_template(self, raw, tip):
        block = parse_block(raw)
        result = self.rpc("validatesharepoolhashtemplate", raw.hex())
        expected = {"valid": True, "native_tip": tip, "native_parent": f"{block.hashPrevBlock:064x}",
                    "origin_height": block.m_height, "commitment": f"{block.m_mm_rhs:064x}"}
        if not isinstance(result, dict) or result.get("valid") is not True or any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native template validation response failed binding")
        self._stable(tip)
        return block

    def register_template(self, raw):
        self._check_seal()
        height, tip = self._context()
        record = TemplateRecord.from_block(raw)
        record.serialize()
        block = parse_block(record.data)
        opening = self._snapshot(block.m_mm_rhs)
        if (opening.envelope.pool != self.pool or opening.envelope.genesis != int(REGTEST_GENESIS, 16) or
                opening.envelope.height != block.m_height or opening.envelope.native_parent != block.hashPrevBlock or
                not self._eligible(block.m_height, f"{block.hashPrevBlock:064x}", height)):
            raise ValueError("template is outside this pool or eligible native ancestry")
        self._native_template(record.data, tip)
        self._persist([(TEMPLATE, record.data)])
        return f"{record.template_id:064x}"

    def _require_origin(self, share):
        identity = template_id(share.header)
        try:
            raw = self._read(TEMPLATE, identity)
            opening = Snapshot.deserialize(self.snapshot_bytes(share.header.m_mm_rhs))
        except KeyError:
            raise ValueError("proof requires its durably validated full origin and snapshot") from None
        if (immutable_header(parse_block(raw)) != immutable_header(share.header) or
                share.envelope.serialize() != opening.envelope.serialize()):
            raise ValueError("proof does not bind its full origin snapshot")

    def _native_share(self, share, tip):
        self._require_origin(share)
        # Reestablish the original full-body validation after native restart or
        # a branch change; a local archived admission is not a native cache hit.
        self._native_template(self._read(TEMPLATE, template_id(share.header)), tip)
        result = self.rpc("validatesharepoolhashshare", share.serialize().hex())
        expected = {"valid": True, "native_tip": tip, "proof_id": f"{share.proof_id:064x}",
                    "payout_script": share.envelope.payout_script.hex(), "pool": f"{self.pool:064x}",
                    "origin_height": share.envelope.height, "native_parent": f"{share.envelope.native_parent:064x}"}
        if not isinstance(result, dict) or result.get("valid") is not True or any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native proof validation response failed binding")
        self._stable(tip)

    def receive(self, share):
        self._check_seal()
        share = parse_share(share if type(share) is bytes else share.serialize())
        height, tip = self._context()
        if share.envelope.pool != self.pool or not self._eligible(share.envelope.height, f"{share.envelope.native_parent:064x}", height):
            raise ValueError("proof is outside this pool or eligible native ancestry")
        self._native_share(share, tip)
        return self._persist([(PROOF, share.serialize())])[0]

    def _eligible(self, height, parent, tip_height):
        return max(1, tip_height + 1 - MAX_SHARE_AGE) <= height <= tip_height + 1 and self.rpc("getblockhash", height - 1) == parent

    def _active(self, kind, height):
        # Fetch only scalar metadata before any RPC or full evidence read.
        rows = self.db.execute("SELECT identity,height,parent FROM journal WHERE kind=? AND height BETWEEN ? AND ?",
            (kind, max(1, height + 1 - MAX_SHARE_AGE), height + 1)).fetchall()
        return [(identity, self._read(kind, identity)) for identity, origin, parent in rows if self._eligible(origin, parent, height)]

    def active_templates(self):
        self._check_seal()
        height, tip = self._context()
        result = tuple(TemplateRecord.from_block(raw) for unused, raw in self._active(TEMPLATE, height))
        self._stable(tip)
        return tuple(sorted(result, key=lambda record: record.template_id.to_bytes(32, "little")))

    def _parent_snapshot(self, height, tip):
        if height == 0:
            return None
        encoded = self.rpc("getblockheader", tip, False)
        if type(encoded) is not str or len(encoded) not in (160, 328):
            raise ValueError("invalid native parent header encoding")
        raw = bytes.fromhex(encoded)
        header = CBlockHeader()
        stream = BytesIO(raw)
        header.deserialize(stream)
        if stream.read() or header.serialize() != raw or f"{header.rehash():064x}" != tip or not header.m_header_v2:
            raise ValueError("native parent header failed binding")
        opening = self._snapshot(header.m_mm_rhs)
        if opening.envelope.height != height or opening.envelope.native_parent != header.hashPrevBlock:
            raise ValueError("native parent snapshot has wrong ancestry")
        self._stable(tip)
        return opening

    def eligible_shares(self):
        self._check_seal()
        height, tip = self._context()
        parent = self._parent_snapshot(height, tip)
        paid = set() if parent is None else {entry.proof_id for entry in parent.post_state}
        result = tuple(parse_share(raw) for unused, raw in self._active(PROOF, height))
        self._stable(tip)
        return tuple(sorted((share for share in result if share.proof_id not in paid), key=lambda share: share.proof_id))

    def make(self, *, ntime, sign_owner, fees=0, transactions=(), witness=False):
        height, tip = self._context()
        result = candidate(genesis=int(REGTEST_GENESIS, 16), native_parent=int(tip, 16), height=height + 1,
            ntime=ntime, pool=self.pool, payout_script=self.payout_script, public_key=self.public_key,
            sign_owner=sign_owner, templates=self.active_templates(), shares=self.eligible_shares(),
            parent_snapshot=self._parent_snapshot(height, tip), fees=fees, transactions=transactions, witness=witness)
        self._stable(tip)
        return result

    def authorize(self, raw, snapshot_raw=None):
        self._check_seal()
        height, tip = self._context()
        block = parse_block(raw)
        if block.hashPrevBlock != int(tip, 16) or block.m_height != height + 1:
            raise ValueError("new mining jobs require the current native parent")
        if snapshot_raw is not None:
            if Snapshot.deserialize(snapshot_raw).hash != block.m_mm_rhs:
                raise ValueError("job and supplied snapshot commitments differ")
            self.register_snapshot(snapshot_raw)
        snapshot = self._snapshot(block.m_mm_rhs)
        envelope = snapshot.envelope
        if (envelope.pool, envelope.public_key, envelope.payout_script) != (self.pool, self.public_key, self.payout_script):
            raise ValueError("job violates this miner's pool/key/payout policy")
        # Introduced templates receive exactly the same full native validation.
        for record in snapshot.templates:
            self.register_template(record.data)
        self._native_template(raw, tip)
        for share in snapshot.shares:
            self._native_share(share, tip)
        self._persist([(PROOF, share.serialize()) for share in snapshot.shares])
        parent = self._parent_snapshot(height, tip)
        paid = set() if parent is None else {entry.proof_id for entry in parent.post_state}
        included = {share.proof_id for share in snapshot.shares}
        missing = [identity for identity, body in self._active(PROOF, height)
                   if parse_share(body).proof_id not in paid | included]
        if missing:
            raise JobOmission(missing)
        own_id = template_id(block)
        required = {identity for identity, body in self._active(TEMPLATE, height) if identity != own_id}
        supplied = {f"{record.template_id:064x}" for record in snapshot.templates}
        if required != supplied:
            raise TemplateOmission(required - supplied)
        self._stable(tip)
        self._persist([(TEMPLATE, normalize_template(raw))])
        head = self.archive_head()
        return HashMiningAuthorization(raw, tip, snapshot.hash_hex, head["receipt_revision"],
                                       snapshot.serialize(), head["events"])

    def needs_refresh(self, authorization):
        self._check_seal()
        unused, tip = self._context()
        return tip != authorization.native_parent or self._head()["events"] != authorization.evidence_sequence

    def ready_for_dispatch(self, authorization):
        return not self.needs_refresh(authorization)

    def close(self):
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            for name in ("_head_lock_fd", "_lock_fd"):
                descriptor = getattr(self, name, None)
                if descriptor is not None:
                    os.close(descriptor)
                    setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
