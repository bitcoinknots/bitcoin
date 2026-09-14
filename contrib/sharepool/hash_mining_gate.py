#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable local mining policy for hash-only regtest snapshots.

The journal retains every acknowledged origin and proof. An explicitly selected
archive directory lets verified immutable segments back older bodies; finite
resident or physical capacity stops admission before acknowledgment. Native
RPC, not a local inventory or successful snapshot storage, establishes validity.
One owner thread/process must use a gate. No RPC runs inside a write transaction.
"""
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from io import BytesIO
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import tempfile

import native_archive
import hash_gate_archive
import hash_gate_batch
from hash_gate_cache import SnapshotDecodeCache
from hash_gate_origin_cache import OriginFactsCache
from hash_state_cache import CompactStateCache
from hash_signature_cache import SignatureVerifyCache
from hash_snapshot import (Snapshot, TemplateRecord, CompactTemplateRecord, Share, MAX_SNAPSHOT_BYTES,
    MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_BYTES, MAX_COMPACT_SHARES, MAX_SHARE_AGE, MAX_EXPANDED_TEMPLATE_BYTES,
    MAX_TEMPLATE_TX_REFERENCES, SHARE_BITS, parse_share, candidate, normalize_template, build_snapshot,
    job_hash, work_outputs, credit_outputs, rules_hash, profile_snapshot_hash, LEDGER_VERSION, TIDES_VERSION, COMPACT_TIDES_VERSION,
    VARIABLE_TIDES_VERSION, is_tides_profile, is_compact_tides_profile, materialize_compact_state)
from hash_vardiff import work_bits
from native_mining_gate import (MiningAuthorization, JobOmission, parse_block,
    template_id, _process_lock, fcntl, REGTEST_GENESIS)
from native_enforcement import compact_size, is_payout_script, verify_schnorr
from test_framework.messages import CBlockHeader

SNAPSHOT, TEMPLATE, PROOF = 0, 1, 2
RECORD_OVERHEAD = hash_gate_archive.RECORD.size
LIMITS = (MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, 1024)
RECEIPT_HISTORY_SNAPSHOTS = 64
RECEIPT_HISTORY_BYTES = 64 * 1024 * 1024
DESCRIPTION_CACHE_ENTRIES = 4096


class TemplateOmission(ValueError):
    def __init__(self, template_ids):
        self.template_ids = tuple(sorted(template_ids))
        super().__init__("job template set differs from the selected proof origins")


@dataclass(frozen=True)
class HashMiningAuthorization(MiningAuthorization):
    snapshot_bytes: bytes
    evidence_sequence: int
    native_height: int = 0
    policy_binding: str = ""
    dispatch_seal: bytes = field(default=b"", repr=False)


class HashMiningGate:
    def __init__(self, path, *, rpc, pool, public_key, payout_script,
                 quota=native_archive.DEFAULT_QUOTA, trusted_head_path=None, archive_directory=None,
                 snapshot_budget=MAX_SNAPSHOT_BYTES, profile_version=4, activation_height=1, share_work_bits=None):
        if (type(activation_height) is not int or not 1 <= activation_height <= 0x7fffffff or
                type(profile_version) is not int or profile_version not in (4, LEDGER_VERSION, TIDES_VERSION, COMPACT_TIDES_VERSION, VARIABLE_TIDES_VERSION) or
                type(pool) is not int or not 0 < pool < 1 << 256 or type(public_key) is not bytes or
                len(public_key) != 32 or type(payout_script) is not bytes or not is_payout_script(payout_script) or
                type(quota) is not int or not 4096 <= quota <= native_archive.MAX_QUOTA or
                type(snapshot_budget) is not int or not 1024 <= snapshot_budget <= MAX_SNAPSHOT_BYTES):
            raise ValueError("invalid explicit gate policy or journal quota")
        if profile_version == VARIABLE_TIDES_VERSION:
            work_bits(share_work_bits)
        elif share_work_bits is not None:
            raise ValueError("assigned share work requires the v8 profile")
        self._share_work_bits = share_work_bits
        if fcntl is None:
            raise ValueError("exclusive process locks are required")
        self.rpc, self.pool, self.public_key, self.payout_script = rpc, pool, public_key, payout_script
        self.path, self.quota = Path(path), quota
        self.snapshot_budget = snapshot_budget
        self.profile_version, self.rules = profile_version, rules_hash(profile_version)
        self.activation_height = activation_height
        self.mode = {4: "hash-only-v4", LEDGER_VERSION: "hash-only-v5-confirmed-ledger",
                     TIDES_VERSION: "hash-only-v6-tides", COMPACT_TIDES_VERSION: "hash-only-v7-compact-tides",
                     VARIABLE_TIDES_VERSION: "hash-only-v8-vardiff-tides"}[profile_version]
        self.archive_directory = None if archive_directory is None else Path(archive_directory).absolute()
        if self.archive_directory is not None:
            self.archive_directory.mkdir(mode=0o700, exist_ok=True)
            archive_status = self.archive_directory.lstat()
            if (not stat.S_ISDIR(archive_status.st_mode) or archive_status.st_uid != os.geteuid() or
                    archive_status.st_mode & 0o077):
                raise ValueError("archive directory must be an owned private directory")
        self.head_path = Path(trusted_head_path) if trusted_head_path is not None else Path(str(self.path) + ".archive-head.json")
        if self.head_path.absolute() == self.path.absolute():
            raise ValueError("protected head must be separate from database")
        self.db, self._lock_fd, self._head_lock_fd, self._sealed_head = None, None, None, None
        self._description_cache = OrderedDict()
        self._snapshot_decode_cache = SnapshotDecodeCache()
        self._origin_facts_cache = OriginFactsCache()
        self._compact_state_cache = CompactStateCache()
        self._signature_cache = SignatureVerifyCache()
        self._snapshot_observer = None  # Sole-owner bounded inventory ingestion only.
        # Dispatch capabilities belong to this open instance, never to the
        # persisted journal. Recovered evidence requires fresh native approval.
        self._dispatch_key, self._dispatch_pid = None, os.getpid()
        self._context()
        config = {"schema": 2, "profile": self.mode, "genesis": REGTEST_GENESIS,
            "rules": f"{self.rules:064x}", "pool": f"{pool:064x}", "public_key": public_key.hex(), "script": payout_script.hex(),
            "batch_policy": "oldest-origin-receipt-v2" if is_tides_profile(profile_version) else "oldest-origin-proof-v1",
            "snapshot_budget": snapshot_budget}
        if activation_height != 1:
            config["activation_height"] = activation_height
        self.config = native_archive.canonical(config)
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
            # The resident-body quota is independent of lifetime metadata and
            # cold history. Physical disk exhaustion still stops before ACK.
            self.db.execute("PRAGMA max_page_count=2147483646")
            self._initialize()
            self._head()  # Bound checkpoint fields before materializing initialized.
            initialized = self.db.execute("SELECT initialized FROM journal_meta").fetchone()[0]
            prefix = hash_gate_archive.read_head(self.head_path) if initialized else native_archive.initial_head(self.binding)
            if not initialized and (self.head_path.exists() or self.head_path.is_symlink()):
                prefix = hash_gate_archive.read_head(self.head_path)
            self._verify_store(prefix)
            self._sealed_head = prefix
            self._seal(initial=not initialized)
            self._dispatch_key = os.urandom(32)
        except BaseException:
            self.close()
            raise

    @property
    def share_work_bits(self):
        """Assignment for the next v8 job; issued jobs retain their own bits."""
        return self._share_work_bits

    def set_share_work_bits(self, value):
        if self.profile_version != VARIABLE_TIDES_VERSION:
            raise ValueError("assigned share work requires the v8 profile")
        work_bits(value)
        self._check_seal()
        self._share_work_bits = value

    def _context(self):
        required = f"active native regtest hash-only v{self.profile_version} profile at activation height {self.activation_height} required"
        # Separate RPC responses are not one chain snapshot. A block arriving
        # between the height and hash reads requires a fresh capture, not a
        # false profile failure. Profile/genesis failures never authorize retry.
        for _ in range(3):
            before = self.rpc("getbestblockhash")
            info = self.rpc("getblockchaininfo")
            profile = self.rpc("getsharepoolhashstatus", None, 1)
            height = info.get("blocks") if isinstance(info, dict) else None
            if (not native_archive.is_hash(before) or not isinstance(info, dict) or
                    info.get("chain") != "regtest" or type(height) is not int or height < 0 or
                    not isinstance(profile, dict) or profile.get("mode") != self.mode or
                    profile.get("rules") != f"{self.rules:064x}" or
                    type(profile.get("activation_height", 1)) is not int or
                    profile.get("activation_height", 1) != self.activation_height or
                    profile.get("max_snapshot_bytes") != MAX_SNAPSHOT_BYTES or
                    self.rpc("getblockhash", 0) != REGTEST_GENESIS):
                raise ValueError(required)
            try:
                at_height = self.rpc("getblockhash", height)
            except Exception:
                # A shorter reorg can remove the height just read. Only an
                # actually observed new tip permits retry; other RPC failures
                # retain their original failure and cannot supply a context.
                after = self.rpc("getbestblockhash")
                if native_archive.is_hash(after) and after != before:
                    continue
                raise
            after = self.rpc("getbestblockhash")
            if not native_archive.is_hash(after):
                raise ValueError(required)
            if before != after:
                continue
            if at_height != after:
                raise ValueError(required)
            return height, after
        raise ValueError("native tip changed during context capture")

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
                self.db.execute("CREATE TABLE journal (sequence INTEGER PRIMARY KEY, kind INTEGER NOT NULL, identity TEXT NOT NULL, digest TEXT NOT NULL, data BLOB NOT NULL, previous TEXT NOT NULL, root TEXT NOT NULL, revision INTEGER NOT NULL, height INTEGER NOT NULL, parent TEXT NOT NULL, size INTEGER NOT NULL, segment INTEGER NOT NULL, offset INTEGER NOT NULL, UNIQUE(kind,identity))")
                self.db.execute("CREATE INDEX journal_context ON journal(kind,height)")
                self.db.execute("CREATE INDEX journal_segment ON journal(segment)")
                self.db.execute("CREATE TABLE segments (id INTEGER PRIMARY KEY, path TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL)")
                self.db.execute("CREATE TABLE journal_meta (value TEXT NOT NULL, initialized INTEGER NOT NULL, resident INTEGER NOT NULL)")
                self.db.execute("INSERT INTO journal_meta VALUES (?,0,0)", (native_archive.canonical(native_archive.initial_head(self.binding)).decode(),))
        elif set(objects) != {("table", "config"), ("table", "journal"), ("table", "journal_meta"), ("table", "segments"), ("index", "journal_context"), ("index", "journal_segment")}:
            raise ValueError("unsupported gate database schema; no implicit legacy migration")
        columns = {"config": ["value"], "journal": ["sequence", "kind", "identity", "digest", "data", "previous", "root", "revision", "height", "parent", "size", "segment", "offset"],
                   "journal_meta": ["value", "initialized", "resident"], "segments": ["id", "path", "start", "end"]}
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
        result = hash_gate_archive.check_head(json.loads(rows[0][0]))
        if result["binding"] != self.binding or native_archive.canonical(result).decode() != rows[0][0]:
            raise ValueError("journal binding or quota mismatch")
        return result

    def resident_bytes(self):
        rows = self.db.execute("SELECT typeof(resident),resident FROM journal_meta LIMIT 2").fetchall()
        if len(rows) != 1 or rows[0][0] != "integer" or not 0 <= rows[0][1] <= self.quota:
            raise ValueError("resident journal byte accounting exceeds quota")
        return rows[0][1]

    def _describe(self, kind, raw):
        """Memoize canonical metadata, never body availability or validity.

        Every call hashes its actual bytes; journal reads still fetch and
        authenticate those bytes and compare stored scalar metadata. Entries
        contain only immutable strings/integers, not mutable decoded payouts,
        full bodies, native validation results or mining authorizations.
        """
        if type(kind) is not int or kind not in (SNAPSHOT, TEMPLATE, PROOF) or type(raw) is not bytes or not 1 <= len(raw) <= LIMITS[kind]:
            raise ValueError("invalid bounded journal event")
        key = kind, len(raw), hashlib.sha256(raw).digest()
        saved = self._description_cache.get(key)
        if saved is not None:
            self._description_cache.move_to_end(key)
            return saved
        value = self._describe_uncached(kind, raw)
        if len(self._description_cache) >= DESCRIPTION_CACHE_ENTRIES:
            self._description_cache.popitem(last=False)
        self._description_cache[key] = value
        return value

    @staticmethod
    def _describe_uncached(kind, raw):
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
        root = hashlib.sha256(f"SharePool/hash-gate/event/v{self.profile_version}\0".encode() + bytes.fromhex(head["root"]) +
            struct.pack("<QBQI", sequence, kind, revision, len(raw)) + bytes.fromhex(identity) + bytes.fromhex(digest)).hexdigest()
        result = dict(head, events=sequence, root=root, receipt_revision=revision, bytes=head["bytes"] + RECORD_OVERHEAD + len(raw))
        if result["bytes"] > hash_gate_archive.MAX_COUNTER or sequence > hash_gate_archive.MAX_COUNTER:
            raise ValueError("journal lifetime counter exhausted; no work acknowledged")
        return result, digest

    def _verify_store(self, prefix):
        from hash_gate_startup import verify_store

        verify_store(self, prefix)

    def _check_seal(self):
        if hash_gate_archive.read_head(self.head_path) != self._sealed_head:
            raise ValueError("protected checkpoint changed while gate was open")
        if self._head() != self._sealed_head:
            raise ValueError("unsealed journal commit requires a verified restart")

    def _seal(self, *, initial=False):
        head = self._head()
        if not initial and hash_gate_archive.read_head(self.head_path) != self._sealed_head:
            raise ValueError("protected checkpoint changed before acknowledgment")
        if not initial and head == self._sealed_head:
            return
        hash_gate_archive.write_head(self.head_path, head, exclusive=initial and not self.head_path.exists())
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
        resident = self.resident_bytes() + RECORD_OVERHEAD + len(raw)
        if resident > self.quota:
            raise ValueError("resident journal quota exhausted; no work acknowledged")
        self.db.execute("INSERT INTO journal VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (current["events"], kind, identity, digest,
            raw, previous["root"], current["root"], current["receipt_revision"], height, parent, len(raw), 0, 0))
        self.db.execute("UPDATE journal_meta SET value=?,resident=?", (native_archive.canonical(current).decode(), resident))
        return True

    def _persist(self, items):
        self._check_seal()
        if not items:
            return []
        if self.archive_directory is not None:
            additions = {}
            for kind, raw in items:
                identity = self._describe(kind, raw)[0]
                try:
                    existing = self._read(kind, identity)
                except KeyError:
                    existing = additions.get((kind, identity), raw)
                    additions[kind, identity] = raw
                if existing != raw:
                    raise ValueError("acknowledged evidence identity has conflicting bytes")
            needed = sum(RECORD_OVERHEAD + len(raw) for raw in additions.values())
            if needed > self.quota:
                raise ValueError("offered evidence batch exceeds resident journal quota")
            if self.resident_bytes() + needed > self.quota:
                head = self.archive_head()
                self.rotate_archive(self.archive_directory / ("segment-%020d-%s.spharc" % (head["events"], head["root"])))
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            changed = [self._append(kind, raw) for kind, raw in items]
        self._seal()
        return changed

    def _read(self, kind, identity):
        if not native_archive.is_hash(identity):
            raise ValueError("canonical evidence hash required")
        saved = self.db.execute("SELECT digest,size,height,parent,segment,offset,sequence,revision,previous,root FROM journal WHERE kind=? AND identity=? AND typeof(data)='blob' AND typeof(size)='integer' AND size BETWEEN 1 AND ? AND typeof(digest)='text' AND length(digest)=64 AND typeof(height)='integer' AND height BETWEEN 1 AND 4294967295 AND typeof(parent)='text' AND length(parent)=64 AND typeof(sequence)='integer' AND sequence>=1 AND typeof(revision)='integer' AND revision BETWEEN 0 AND sequence AND typeof(previous)='text' AND length(previous)=64 AND typeof(root)='text' AND length(root)=64 AND typeof(segment)='integer' AND segment>=0 AND typeof(offset)='integer' AND ((segment=0 AND offset=0 AND length(data)=size) OR (segment>0 AND offset>=12 AND length(data)=0))", (kind, identity, LIMITS[kind])).fetchone()
        if saved is None:
            if self.db.execute("SELECT 1 FROM journal WHERE kind=? AND identity=?", (kind, identity)).fetchone():
                raise ValueError("stored evidence metadata exceeds its bound")
            raise KeyError(identity)
        if type(saved[1]) is not int or not 1 <= saved[1] <= LIMITS[kind]:
            raise ValueError("stored evidence exceeds byte bound")
        if saved[4]:
            raw = self._read_cold(kind, identity, saved)
        else:
            raw = self.db.execute("SELECT data FROM journal WHERE kind=? AND identity=?", (kind, identity)).fetchone()[0]
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != saved[0] or self._describe(kind, raw) != (identity, saved[2], saved[3]):
            raise ValueError("stored evidence failed read-time integrity")
        return raw

    def _segment(self, identity):
        row = self.db.execute("SELECT path,start,end FROM segments WHERE id=? AND typeof(path)='text' AND length(path) BETWEEN 1 AND 4096 AND typeof(start)='text' AND length(start) BETWEEN 1 AND 4096 AND typeof(end)='text' AND length(end) BETWEEN 1 AND 4096", (identity,)).fetchone()
        if row is None:
            raise ValueError("cold archive segment metadata is missing or exceeds its bound")
        path = Path(row[0])
        start, end = hash_gate_archive.check_head(json.loads(row[1])), hash_gate_archive.check_head(json.loads(row[2]))
        if (not path.is_absolute() or start["binding"] != self.binding or end["binding"] != self.binding or
                start["events"] >= end["events"] or start["bytes"] >= end["bytes"] or
                row[1] != native_archive.canonical(start).decode() or row[2] != native_archive.canonical(end).decode()):
            raise ValueError("cold archive segment binding is invalid")
        return path, start, end

    def _cold_prefix(self):
        current = native_archive.initial_head(self.binding)
        expected_id = 1
        for identity, in self.db.execute("SELECT id FROM segments ORDER BY id"):
            unused, start, end = self._segment(identity)
            count, first, last = self.db.execute("SELECT count(*),min(sequence),max(sequence) FROM journal WHERE segment=?", (identity,)).fetchone()
            if (identity != expected_id or start != current or count != end["events"] - start["events"] or
                    first != start["events"] + 1 or last != end["events"]):
                raise ValueError("cold archive segments are not a complete journal prefix")
            current, expected_id = end, expected_id + 1
        first_hot = self.db.execute("SELECT min(sequence) FROM journal WHERE segment=0").fetchone()[0]
        if first_hot is not None and first_hot != current["events"] + 1:
            raise ValueError("resident journal does not extend its cold prefix")
        return current

    def _read_cold(self, kind, identity, saved):
        path, start, end = self._segment(saved[4])
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                status = os.fstat(stream.fileno())
                header = native_archive.canonical({"version": 1, "start": start, "end": end})
                if (not stat.S_ISREG(status.st_mode) or status.st_size != 12 + len(header) + end["bytes"] - start["bytes"] or
                        native_archive._take(stream, 12 + len(header)) != hash_gate_archive.MAGIC + struct.pack("<I", len(header)) + header or
                        not 12 + len(header) <= saved[5] <= status.st_size - hash_gate_archive.RECORD.size - saved[1]):
                    raise ValueError("cold archive file or record position failed binding")
                stream.seek(saved[5])
                frame = hash_gate_archive.RECORD.unpack(native_archive._take(stream, hash_gate_archive.RECORD.size))
                expected = (saved[6], kind, saved[7], saved[1], bytes.fromhex(identity), bytes.fromhex(saved[0]),
                            bytes.fromhex(saved[8]), bytes.fromhex(saved[9]))
                if frame != expected:
                    raise ValueError("cold archive record metadata differs from acknowledged evidence")
                return native_archive._take(stream, saved[1])
        except OSError:
            raise ValueError("acknowledged cold archive data is unavailable") from None

    def rotate_archive(self, path):
        """Move resident bodies to a verified immutable segment, retaining IDs.

        The archive is durable before the transaction switches its references.
        Checkpoint, receipt revisions and frozen authorizations are unchanged.
        Missing or altered cold files fail closed on access and restart.
        """
        self._check_seal()
        self._verify_store(self._sealed_head)
        start, end = self._cold_prefix(), self.archive_head()
        if start == end:
            return end
        path = Path(path).absolute()
        if len(str(path)) > 4096:
            raise ValueError("cold archive path exceeds its bound")
        if not path.exists() and not path.is_symlink():
            # The complete store was verified above. Reusing that verification
            # avoids a second lifetime scan; the writer still authenticates each
            # exported body and the sealed endpoint while streaming the suffix.
            from hash_gate_startup import write_verified_archive

            write_verified_archive(self, path, start=start, end=end)
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid() or status.st_mode & 0o022:
                raise ValueError("cold archive must be an owned file without other writers")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        hash_gate_archive._sync_directory(path.parent)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_seal()
            segment = self.db.execute("SELECT COALESCE(max(id),0)+1 FROM segments").fetchone()[0]
            self.db.execute("INSERT INTO segments VALUES (?,?,?,?)", (segment, str(path),
                native_archive.canonical(start).decode(), native_archive.canonical(end).decode()))
            for kind, identity, raw, offset in hash_gate_archive.records(path, initial=start, trusted_head=end,
                    limits=LIMITS, next_head=self._next, with_offsets=True):
                if self._read(kind, identity) != raw:
                    raise ValueError("cold archive does not preserve acknowledged body bytes")
                updated = self.db.execute("UPDATE journal SET data=?,segment=?,offset=? WHERE kind=? AND identity=? AND segment=0",
                                          (b"", segment, offset, kind, identity)).rowcount
                if updated != 1:
                    raise ValueError("cold archive does not cover the exact resident journal")
            if self.db.execute("SELECT 1 FROM journal WHERE segment=0 LIMIT 1").fetchone():
                raise ValueError("cold archive left resident evidence uncovered")
            self.db.execute("UPDATE journal_meta SET resident=0")
        self._check_seal()
        return end

    def archive_head(self):
        self._check_seal()
        return dict(self._sealed_head)

    def export_archive(self, path, *, since=None):
        """Write a full archive or the next immutable checkpoint-linked segment.

        Keep every earlier segment and an independently protected final head.
        Exporting never deletes evidence or resets its receipt sequence.
        """
        self._check_seal()
        start = native_archive.initial_head(self.binding) if since is None else hash_gate_archive.check_head(since)
        self._verify_store(start)
        end = self.archive_head()
        from hash_gate_startup import write_verified_archive

        return write_verified_archive(self, path, start=start, end=end)

    def revalidate_active(self):
        """Reconcile retained evidence with the current native branch.

        Historical receipts remain intact, including work from an orphaned
        branch. Native validation is repeated for eligible origins and proofs;
        storage of a snapshot alone is never a validity assertion.
        """
        self._check_seal()
        height, tip = self._context()
        # Rehydrate the local native content store in bounded individual writes.
        # It applies its own resource limits and can refuse recovery admission.
        for identity, in self.db.execute("SELECT identity FROM journal WHERE kind=? ORDER BY sequence", (SNAPSHOT,)):
            self._submit_snapshot(self._read(SNAPSHOT, identity))
        active = {TEMPLATE: 0, PROOF: 0}
        unpaid = []
        parent = self._parent_snapshot(height, tip, {})
        paid = self._admitted_ids(parent)
        for kind in (TEMPLATE, PROOF):
            cursor = self.db.execute("SELECT identity,height,parent FROM journal WHERE kind=? AND height BETWEEN ? AND ? ORDER BY sequence",
                                     (kind, max(self.activation_height, height + 1 - MAX_SHARE_AGE), height + 1))
            for identity, origin, parent_hash in cursor:
                if not self._eligible(origin, parent_hash, height):
                    continue
                raw = self._read(kind, identity)
                if kind == TEMPLATE:
                    self._native_template(raw, tip, mining=False)
                else:
                    share = parse_share(raw)
                    self._native_share(share, tip)
                    if share.proof_id not in paid:
                        unpaid.append(identity)
                active[kind] += 1
        self._stable(tip)
        self._check_seal()
        result = {"native_tip": tip, "retained_receipts": self._sealed_head["receipt_revision"],
                  "active_templates": active[TEMPLATE], "active_receipts": active[PROOF],
                  "unsettled_proofs": tuple(sorted(unpaid))}
        if self.profile_version == LEDGER_VERSION:
            # Confirmed credit is independent of the raw proof's admission age.
            # Query only the bounded current ledger, never lifetime proof bodies.
            def retained(credits):
                return tuple(sorted(f"{credit.proof_id:064x}" for credit in credits
                    if self.db.execute("SELECT 1 FROM journal WHERE kind=? AND identity=?",
                        (PROOF, f"{credit.proof_id:064x}")).fetchone() is not None))
            pending = retained(parent.pending) if parent is not None else ()
            settled = retained(parent.settled) if parent is not None else ()
            result.update(provisional_proofs=tuple(sorted(unpaid)), confirmed_pending_proofs=pending,
                          current_block_settled_proofs=settled, unsettled_proofs=tuple(sorted(set(unpaid) | set(pending))))
        elif is_tides_profile(self.profile_version):
            # Recent anti-replay IDs prove admission, never one-time payment or
            # present rolling-window membership. Full reward history is separate.
            result.update(provisional_proofs=tuple(sorted(unpaid)), payout_policy="rolling-tides",
                          reward_history_verified=False)
        return result

    @classmethod
    def restore_archive(cls, exports, destination, *, trusted_head, **kwargs):
        """Restore a fresh gate from a complete trusted chain of archive segments.

        Streaming import, integrity checks and current-branch revalidation finish
        in a private staging database before either destination is published.
        A caller must obtain trusted_head independently of the exported files.
        """
        trusted_head = hash_gate_archive.check_head(trusted_head)
        destination = Path(destination)
        head_path = Path(kwargs.get("trusted_head_path") or str(destination) + ".archive-head.json")
        if (destination.absolute() == head_path.absolute() or destination.exists() or destination.is_symlink() or
                head_path.exists() or head_path.is_symlink()):
            raise native_archive.ArchiveError("restore requires fresh database and checkpoint paths")
        descriptor, temporary = tempfile.mkstemp(prefix=".hash-gate-restore-", suffix=".sqlite", dir=destination.parent)
        os.close(descriptor)
        staging = Path(temporary)
        staging_head = Path(str(staging) + ".archive-head.json")
        gate, published_head = None, False
        try:
            gate = cls(staging, **dict(kwargs, trusted_head_path=staging_head))
            initial = native_archive.initial_head(gate.binding)
            for kind, identity, raw in hash_gate_archive.records(exports, initial=initial,
                    trusted_head=trusted_head, limits=LIMITS, next_head=gate._next):
                if gate._describe(kind, raw)[0] != identity or not gate._persist([(kind, raw)])[0]:
                    raise native_archive.ArchiveError("archive contains conflicting or duplicate evidence")
            if gate._head() != trusted_head:
                raise native_archive.ArchiveError("restored journal differs from trusted checkpoint")
            gate._verify_store(trusted_head)
            gate.revalidate_active()
            if gate.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                raise native_archive.ArchiveError("restored journal could not be checkpointed")
            gate.close()
            gate = None
            hash_gate_archive.write_head(head_path, trusted_head, exclusive=True)
            published_head = True
            os.link(staging, destination)
            hash_gate_archive._sync_directory(destination.parent)
            return cls(destination, **kwargs)
        except BaseException:
            if published_head and not destination.exists():
                head_path.unlink(missing_ok=True)
            raise
        finally:
            if gate is not None:
                gate.close()
            for suffix in ("", "-wal", "-shm", ".owner.lock", ".archive-head.json", ".archive-head.json.owner.lock"):
                Path(str(staging) + suffix).unlink(missing_ok=True)

    def snapshot_bytes(self, identity):
        return self._read(SNAPSHOT, f"{identity:064x}" if type(identity) is int else identity)

    def _evidence(self, kind, identity, staged=None):
        if staged is not None and (kind, identity) in staged:
            return staged[kind, identity]
        return self._read(kind, identity)

    def _snapshot(self, identity, staged=None):
        identity = f"{identity:064x}" if type(identity) is int else identity
        try:
            raw = self._evidence(SNAPSHOT, identity, staged)
            if self._snapshot_observer is not None:
                self._snapshot_observer(raw)
        except KeyError:
            result = self.rpc("getsharepoolhashsnapshot", identity)
            if not isinstance(result, dict) or result.get("hash") != identity:
                raise ValueError("native snapshot lookup returned another commitment")
            encoded = result.get("data")
            if type(encoded) is not str or not 1 <= len(encoded) <= MAX_SNAPSHOT_BYTES * 2:
                raise ValueError("native snapshot lookup exceeds byte bound")
            raw = bytes.fromhex(encoded)
            if self._snapshot_observer is not None:
                self._snapshot_observer(raw)
            self._snapshot_decode_cache.decode(raw, self.profile_version)
            if f"{profile_snapshot_hash(raw, self.profile_version):064x}" != identity:
                raise ValueError("native snapshot bytes do not match commitment")
            if staged is None:
                self.register_snapshot(raw)
            else:
                staged[SNAPSHOT, identity] = raw
        # Raw evidence is still obtained and authenticated on every access.
        # Only its canonical decode is reused; mutable payout objects are
        # detached by the cache before handing a snapshot to a caller.
        return self._snapshot_decode_cache.decode(raw, self.profile_version)

    def _submit_snapshot(self, raw):
        self._snapshot_decode_cache.decode(raw, self.profile_version)
        identity = f"{profile_snapshot_hash(raw, self.profile_version):064x}"
        result = self.rpc("submitsharepoolhashsnapshot", raw.hex())
        if (not isinstance(result, dict) or result.get("hash") != identity or
                result.get("status") not in ("stored", "present") or type(result.get("missing")) is not list or
                any(not native_archive.is_hash(value) for value in result["missing"])):
            raise ValueError("native snapshot storage response failed binding")
        return identity

    def _provenance(self, snapshot, staged, **context):
        """Collect the complete bounded opening graph without admitting it.

        An origin's native-parent paid state is required even when it is older
        than the proposed job's parent. Only a successful complete traversal
        exposes its collected bytes to the caller's final atomic admission.
        """
        fetched, complete = dict(staged), {}
        resources = hash_gate_batch.check_graph(snapshot, activation_height=self.activation_height,
            state_cache=self._compact_state_cache, signature_cache=self._signature_cache, **context,
            lookup=lambda identity: self._snapshot(identity, fetched),
            parent_snapshot=lambda identity, height: self._block_snapshot(height, f"{identity:064x}", fetched),
            on_snapshot=lambda identity, raw: complete.__setitem__((SNAPSHOT, f"{identity:064x}"), raw))
        staged.update(complete)
        return resources

    def _rehydrate_retained(self, staged):
        """Re-publish only already durable openings after native cache loss.

        Newly fetched openings already exist at the native RPC source. A
        rejected offer cannot use this path to publish its unadmitted overlay.
        """
        for (kind, identity), raw in staged.items():
            if kind != SNAPSHOT:
                continue
            try:
                retained = self._read(SNAPSHOT, identity)
            except KeyError:
                continue
            if retained != raw:
                raise ValueError("offered snapshot conflicts with retained evidence")
            self._submit_snapshot(retained)

    def register_snapshot(self, raw):
        """Store canonical content. Native 'stored' is never a validity assertion."""
        self._check_seal()
        identity = self._submit_snapshot(raw)
        self._persist([(SNAPSHOT, raw)])
        return identity

    def _native_template(self, raw, tip, snapshot_raw=None, *, mining=True):
        block = parse_block(raw)
        arguments = (raw.hex(),) if snapshot_raw is None else (raw.hex(), snapshot_raw.hex())
        if not mining:
            arguments = (raw.hex(), None if snapshot_raw is None else snapshot_raw.hex(), False)
        result = self.rpc("validatesharepoolhashtemplate", *arguments)
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
        staged = {}
        opening = self._snapshot(block.m_mm_rhs, staged)
        if (not self._relay_pool(opening.envelope.pool) or opening.envelope.genesis != int(REGTEST_GENESIS, 16) or
                opening.envelope.height != block.m_height or opening.envelope.native_parent != block.hashPrevBlock or
                not self._eligible(block.m_height, f"{block.hashPrevBlock:064x}", height)):
            raise ValueError("template is outside this pool or eligible native ancestry")
        self._provenance(opening, staged, mining_job=True)
        self._rehydrate_retained(staged)
        # Explicit registration retains a fully validated native origin before
        # its first proof. Proposal validation still uses non-admitting overlays.
        # Native evidence storage does not grant a local journal entry or ACK;
        # the final tip check and durable admission below can still fail.
        self._native_template(record.data, tip)
        self._stable(tip)
        staged[TEMPLATE, f"{record.template_id:064x}"] = record.data
        self._persist([(kind, body) for (kind, unused), body in staged.items()])
        return f"{record.template_id:064x}"

    def _require_origin(self, share, staged=None):
        identity = f"{share.header_facts.template_id:064x}"
        try:
            raw = self._evidence(TEMPLATE, identity, staged)
            opening_raw = self._evidence(SNAPSHOT, f"{share.header.m_mm_rhs:064x}", staged)
            opening = self._snapshot_decode_cache.decode(opening_raw, self.profile_version)
        except KeyError:
            raise ValueError("proof requires its durably validated full origin and snapshot") from None
        facts = self._origin_facts_cache.describe(raw, self.profile_version)
        if (facts.header != share.header_facts.immutable_header or
                share.envelope.serialize() != opening.envelope.serialize() or
                share.owner_signature != opening.owner_signature):
            raise ValueError("proof does not bind its full origin snapshot")
        return raw, opening_raw, opening, facts

    def _native_share(self, share, tip, staged=None):
        from hash_gate_rpc import missing_snapshot_data

        snapshot_id = f"{share.header.m_mm_rhs:064x}"

        def exact_origin():
            raw, opening_raw, opening, facts = self._require_origin(share, staged)
            # An immutable header/TemplateId alone cannot distinguish witness
            # variants with the same txids. Bind the supplied full body to the
            # exact signed job that the native proof endpoint will authenticate.
            if (f"{profile_snapshot_hash(opening_raw, self.profile_version):064x}" != snapshot_id or
                    facts.job_commitment != opening.job_commitment):
                raise ValueError("proof origin differs from its exact committed job")
            return raw, opening_raw

        origin_raw, snapshot_raw = exact_origin()
        encoded = share.serialize().hex()
        try:
            # This native endpoint independently validates the full origin and
            # its dependencies. A preceding template check duplicates that work.
            result = self.rpc("validatesharepoolhashshare", encoded)
        except Exception as error:
            if not missing_snapshot_data(error):
                raise
            self._check_seal()
            height, current_tip = self._context()
            if current_tip != tip:
                raise ValueError("native tip changed during gate validation") from error
            if not self._eligible(share.envelope.height, f"{share.envelope.native_parent:064x}", height):
                raise ValueError("proof is outside eligible native ancestry") from error
            origin_raw, snapshot_raw = exact_origin()  # Re-read after the failed RPC.
            recovery = {} if staged is None else dict(staged)
            recovery[SNAPSHOT, snapshot_id] = snapshot_raw
            size = 0
            for (kind, unused), raw in recovery.items():
                if kind != SNAPSHOT:
                    continue
                if type(raw) is not bytes or not 1 <= len(raw) <= MAX_SNAPSHOT_BYTES:
                    raise ValueError("native recovery snapshot exceeds byte bound")
                size += len(raw)
                if size > MAX_DEPENDENCY_BYTES:
                    raise ValueError("native recovery dependency byte budget")
            # Only the already bounded, retained dependency set may be replayed;
            # never scan the lifetime archive or admit an unsuccessful offer.
            self._rehydrate_retained(recovery)
            self._submit_snapshot(snapshot_raw)
            # Omit the overlay so native validation also remembers the full body.
            self._native_template(origin_raw, tip, mining=False)
            # Restart, eviction, resource pressure or unavailable history may
            # still prevent validation. One retry only; any failure escapes.
            result = self.rpc("validatesharepoolhashshare", encoded)
        expected = {"valid": True, "native_tip": tip, "proof_id": f"{share.proof_id:064x}",
                    "payout_script": share.envelope.payout_script.hex(), "pool": f"{share.envelope.pool:064x}",
                    "origin_height": share.envelope.height, "native_parent": f"{share.envelope.native_parent:064x}"}
        if not isinstance(result, dict) or result.get("valid") is not True or any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native proof validation response failed binding")
        self._stable(tip)

    def receive(self, share):
        """Acknowledge eligible native-verified work, preserving its original pool.

        V6 relays other pools' work into the same bounded admission queue. This
        receipt neither changes that work's recipient nor promises payment from
        this gate's own pool. V4/v5 retain their existing pool-local policy.
        """
        self._check_seal()
        share = parse_share(share if type(share) is bytes else share.serialize())
        height, tip = self._context()
        if not self._relay_pool(share.envelope.pool) or not self._eligible(share.envelope.height, f"{share.envelope.native_parent:064x}", height):
            raise ValueError("proof is outside this pool or eligible native ancestry")
        self._require_origin(share)
        staged = {}
        opening = self._snapshot(share.header.m_mm_rhs, staged)
        parent = self._parent_snapshot(height, tip, staged) if self.profile_version == LEDGER_VERSION or is_tides_profile(self.profile_version) else None
        self._provenance(opening, staged, trusted_parent=parent,
            root_origin=TemplateRecord.from_block(self._evidence(TEMPLATE, template_id(share.header))), root_depth=1)
        # The native proof endpoint checks its current evidence itself. Only
        # an exact missing-data response permits bounded retained-data replay;
        # ordinary shares must not rewrite their whole opening graph first.
        self._native_share(share, tip, staged)
        return self._persist([(kind, body) for (kind, unused), body in staged.items()] +
                             [(PROOF, share.serialize())])[-1]

    def _relay_pool(self, pool):
        # Native TIDES permits cross-pool admission, while its payouts remain
        # pool-local. The dispatched job still binds this gate's exact policy.
        return is_tides_profile(self.profile_version) or pool == self.pool

    def sync_native_receipts(self, **options):
        """Ingest bounded pages of native P2P snapshot evidence (TIDES profiles).

        See hash_gate_inventory.sync_native_receipts for cursor, budget and
        explicit retry semantics. Native storage alone never authorizes work.
        """
        from hash_gate_inventory import sync_native_receipts
        return sync_native_receipts(self, **options)

    def _eligible(self, height, parent, tip_height):
        return max(self.activation_height, tip_height + 1 - MAX_SHARE_AGE) <= height <= tip_height + 1 and self.rpc("getblockhash", height - 1) == parent

    def _active(self, kind, height):
        # Fetch only scalar metadata before any RPC or full evidence read.
        rows = self.db.execute("SELECT identity,height,parent FROM journal WHERE kind=? AND height BETWEEN ? AND ?",
            (kind, max(self.activation_height, height + 1 - MAX_SHARE_AGE), height + 1)).fetchall()
        return [(identity, self._read(kind, identity)) for identity, origin, parent in rows if self._eligible(origin, parent, height)]

    def active_templates(self):
        self._check_seal()
        height, tip = self._context()
        result = tuple(TemplateRecord.from_block(raw) for unused, raw in self._active(TEMPLATE, height))
        self._stable(tip)
        return tuple(sorted(result, key=lambda record: record.template_id.to_bytes(32, "little")))

    def _block_snapshot(self, height, tip, staged=None):
        if height < self.activation_height:
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
        opening = self._snapshot(header.m_mm_rhs, staged)
        if opening.envelope.height != height or opening.envelope.native_parent != header.hashPrevBlock:
            raise ValueError("native parent snapshot has wrong ancestry")
        return opening

    def _parent_snapshot(self, height, tip, staged=None):
        opening = self._block_snapshot(height, tip, staged)
        if opening is not None and is_compact_tides_profile(self.profile_version):
            opening = materialize_compact_state(opening, activation_height=self.activation_height,
                state_cache=self._compact_state_cache, signature_cache=self._signature_cache,
                parent_snapshot=lambda identity, ancestor_height: self._block_snapshot(
                    ancestor_height, f"{identity:064x}", staged))
        self._stable(tip)
        return opening

    def _admitted_ids(self, parent):
        if parent is None:
            return set()
        records = parent.post_state
        if self.profile_version == LEDGER_VERSION:
            records += parent.pending + parent.settled
        return {entry.proof_id for entry in records}

    def eligible_shares(self):
        self._check_seal()
        height, tip = self._context()
        parent = self._parent_snapshot(height, tip)
        paid = self._admitted_ids(parent)
        result = tuple(parse_share(raw) for unused, raw in self._active(PROOF, height))
        self._stable(tip)
        return tuple(sorted((share for share in result if share.proof_id not in paid), key=lambda share: share.proof_id))

    def _tides_payout_budget(self, tip):
        """Native historical reservation includes recipients rounded to zero.

        It is construction metadata, never evidence of payout validity. New
        current-pool work only shortens that history window at the same target.
        """
        value = self.rpc("getsharepoolhashtidesbudget", f"{self.pool:064x}", self.payout_script.hex())
        if (not isinstance(value, dict) or value.get("native_tip") != tip or
                value.get("pool") != f"{self.pool:064x}" or value.get("payout_script") != self.payout_script.hex() or
                type(value.get("native_bits")) is not int or not 0 < value["native_bits"] < 1 << 32 or
                type(value.get("output_count")) is not int or not 1 <= value["output_count"] <= MAX_SNAPSHOT_BYTES // 31 or
                type(value.get("output_bytes")) is not int or
                not 31 * value["output_count"] <= value["output_bytes"] <= 43 * value["output_count"]):
            raise ValueError("native TIDES payout reservation failed context or size binding")
        self._stable(tip)
        return value

    def _batch(self, height, tip, parent, *, staged=None, offered=(), templates=()):
        """Choose the maximal fitting prefix under this gate's pinned policy.

        V6 orders by origin height, then durable receipt revision. An offered
        proof without a receipt follows all retained receipts of that origin;
        numerical IDs order only those new offers. A later same-origin proof
        cannot overtake an ACK through hash selection. This is local scheduling,
        not a claim about a globally authenticated reception order. V4/v5 keep
        their original (origin height, numerical proof ID) order.

        Only a byte-bounded prefix's bodies are materialized. Deferred receipt
        IDs remain in the indexed journal; counting them streams scalar rows.
        """
        staged = {} if staged is None else staged
        paid = self._admitted_ids(parent)
        floor = max(self.activation_height, height + 1 - MAX_SHARE_AGE)
        ancestry = {origin: self.rpc("getblockhash", origin - 1) for origin in range(floor, height + 2)}
        offered = {f"{share.proof_id:064x}": share for share in offered}
        for share in offered.values():
            if (share.proof_id in paid or ancestry.get(share.envelope.height) != f"{share.envelope.native_parent:064x}"):
                raise ValueError("offered receipt is not currently eligible")
        selected = dict(offered)
        priority = {identity: (share.envelope.height, 1, share.proof_id) for identity, share in offered.items()}
        total = len(offered)
        capacity = (min(MAX_COMPACT_SHARES + 1, self.snapshot_budget // 33 + 1)
                    if is_compact_tides_profile(self.profile_version) else self.snapshot_budget // 512 + 1)
        kept = 0
        order_by = "height,revision" if is_tides_profile(self.profile_version) else "height,identity"
        rows = self.db.execute("SELECT identity,height,parent,revision FROM journal WHERE kind=? AND height BETWEEN ? AND ? ORDER BY " + order_by,
                               (PROOF, floor, height + 1))
        for identity, origin, parent_hash, revision in rows:
            if ancestry.get(origin) != parent_hash or int(identity, 16) in paid:
                continue
            if identity in offered:
                if self._read(PROOF, identity) != offered[identity].serialize():
                    raise ValueError("offered receipt differs from acknowledged evidence")
                priority[identity] = (origin, 0, revision)
                continue
            total += 1
            if kept < capacity:
                selected[identity] = parse_share(self._read(PROOF, identity))
                priority[identity] = (origin, 0, revision)
                kept += 1
        key = ((lambda share: priority[f"{share.proof_id:064x}"]) if is_tides_profile(self.profile_version) else
               (lambda share: (share.envelope.height, share.proof_id)))
        ordered = sorted(selected.values(), key=key)[:capacity]
        supplied_origins = {f"{record.template_id:064x}": record for record in templates}
        payout_budget = self._tides_payout_budget(tip) if is_tides_profile(self.profile_version) else None

        def trial(count):
            # A rejected larger prefix must not retain its fetched dependency
            # bodies across subsequent binary-search attempts.
            trial_staged = dict(staged)
            records, transactions = {}, set()
            expanded = references = wire_lower_bound = 0
            try:
                for share in ordered[:count]:
                    identity = template_id(share.header)
                    if identity in records:
                        continue
                    # Reserve the new job's own future origin before reading
                    # another body. Fetched origins belong only to this trial.
                    if len(records) >= hash_gate_batch.MAX_ORIGIN_CHECKS - 1:
                        raise hash_gate_batch.BatchLimit("origin count")
                    record = supplied_origins.get(identity)
                    if record is None:
                        record = TemplateRecord.from_block(self._evidence(TEMPLATE, identity, trial_staged))
                    record = CompactTemplateRecord.from_record(record)
                    expanded += record.expanded_bytes
                    references += len(record.transactions)
                    if expanded > MAX_EXPANDED_TEMPLATE_BYTES or references > MAX_TEMPLATE_TX_REFERENCES:
                        raise hash_gate_batch.BatchLimit("expanded template budget")
                    for transaction in record.transactions:
                        if transaction.wtxid not in transactions:
                            wire_lower_bound += len(compact_size(len(transaction.raw))) + len(transaction.raw)
                            if wire_lower_bound > self.snapshot_budget:
                                raise hash_gate_batch.BatchLimit("snapshot transaction byte budget")
                            transactions.add(transaction.wtxid)
                    records[identity] = record
                snapshot = build_snapshot(genesis=int(REGTEST_GENESIS, 16), native_parent=int(tip, 16),
                    height=height + 1, pool=self.pool, payout_script=self.payout_script, public_key=self.public_key,
                    sign_owner=lambda unused: None, reward=0, templates=tuple(records.values()), shares=ordered[:count],
                    parent_state=() if parent is None else parent.post_state,
                    version=self.profile_version, parent_snapshot=parent,
                    share_work_bits=self._share_work_bits if self.profile_version == VARIABLE_TIDES_VERSION else 0)
                resources = hash_gate_batch.check_graph(snapshot, snapshot_budget=self.snapshot_budget,
                    mining_job=True, activation_height=self.activation_height, state_cache=self._compact_state_cache,
                    signature_cache=self._signature_cache,
                    lookup=lambda identity: self._snapshot(identity, trial_staged),
                    parent_snapshot=lambda identity, origin_height: self._block_snapshot(origin_height, f"{identity:064x}", trial_staged))
                if payout_budget is not None:
                    # Count the complete native historical set plus distinct
                    # current-pool scripts. A script present in both may be
                    # over-reserved, keeping prefix fit monotonic without a
                    # Python history oracle or fee/rounding assumptions.
                    scripts = {share.envelope.payout_script for share in snapshot.shares if share.envelope.pool == self.pool}
                    count = payout_budget["output_count"] + len(scripts)
                    output_bytes = payout_budget["output_bytes"] + sum(8 + len(compact_size(len(script))) + len(script) for script in scripts)
                    placeholder = len(compact_size(len(snapshot.payouts))) + sum(len(output.serialize()) for output in snapshot.payouts)
                    additional = len(compact_size(count)) + output_bytes - placeholder
                    resources["payout_reservation_bytes"] = additional
                    resources["reserved_snapshot_bytes"] = resources["snapshot_bytes"] + additional
                    resources["reserved_dependency_bytes"] = resources["dependency_bytes"] + additional
                    if resources["reserved_snapshot_bytes"] > self.snapshot_budget:
                        raise hash_gate_batch.BatchLimit("snapshot payout reservation budget")
                    if resources["reserved_dependency_bytes"] > MAX_DEPENDENCY_BYTES:
                        raise hash_gate_batch.BatchLimit("dependency payout reservation budget")
                return snapshot, resources
            except ValueError as error:
                if (isinstance(error, hash_gate_batch.BatchLimit) or "budget" in str(error) or "exceeds byte bound" in str(error) or
                        str(error).startswith(("confirmed ledger capacity;", "TIDES certificate capacity;",
                                               "compact share count exceeds original work bound"))):
                    return None, str(error)
                raise

        low, high, best, reason = 0, len(ordered), None, None
        empty, resources = trial(0)
        if empty is None:
            raise ValueError("even an empty settlement exceeds local or native resource budgets: " + resources)
        best = empty, resources
        # Normal uncongested jobs fit their complete bounded receipt prefix.
        # Avoid rebuilding and traversing every binary-search prefix in that
        # case. A failed full trial still falls back to the same maximal-prefix
        # policy, retaining neither that trial's fetched bodies nor a verdict.
        if high:
            snapshot, resources = trial(high)
            if snapshot is not None:
                low, best = high, (snapshot, resources)
            else:
                high, reason = high - 1, resources
        while low < high:
            middle = (low + high + 1) // 2
            snapshot, resources = trial(middle)
            if snapshot is None:
                high, reason = middle - 1, resources
            else:
                low, best = middle, (snapshot, resources)
        result = {"snapshot": best[0], "resources": best[1], "eligible_count": total,
                  "deferred_count": total - low, "limit_reason": reason}
        if payout_budget is not None:
            result["native_bits"] = payout_budget["native_bits"]
        return result

    def batch_status(self):
        self._check_seal()
        height, tip = self._context()
        staged = {}
        parent = self._parent_snapshot(height, tip, staged)
        result = self._batch(height, tip, parent, staged=staged)
        self._stable(tip)
        snapshot = result.pop("snapshot")
        return dict(result, native_tip=tip, selected_proofs=tuple(f"{share.proof_id:064x}" for share in snapshot.shares),
                    receipt_revision=self._head()["receipt_revision"])

    def receipt_status(self, *, after_revision=0, limit=128):
        """Page retained ACKs, checking actual canonical settlement snapshots.

        v4 settlement is limited to the original proof age. v5 admission is
        limited to that age, while confirmed pending credits remain payable.
        Missing history yields unknown, never an invented payment guarantee.
        """
        if (type(after_revision) is not int or not 0 <= after_revision <= hash_gate_archive.MAX_COUNTER or
                type(limit) is not int or not 1 <= limit <= 256):
            raise ValueError("receipt status requires a bounded revision and page size")
        if self.profile_version == LEDGER_VERSION:
            return self._ledger_receipt_status(after_revision=after_revision, limit=limit)
        if is_tides_profile(self.profile_version):
            return self._tides_receipt_status(after_revision=after_revision, limit=limit)
        self._check_seal()
        height, tip = self._context()
        rows = self.db.execute("SELECT identity,height,parent,revision FROM journal WHERE kind=? AND revision>? ORDER BY revision LIMIT ?",
                               (PROOF, after_revision, limit + 1)).fetchall()
        more, rows = len(rows) > limit, rows[:limit]
        groups, branch = {}, {}
        for identity, origin, parent_hash, revision in rows:
            self._read(PROOF, identity)  # Check each retained receipt before reporting it.
            if origin not in branch:
                branch[origin] = self.rpc("getblockhash", origin - 1) if origin <= height + 1 else None
            if branch[origin] == parent_hash:
                groups.setdefault(origin, set()).add(int(identity, 16))
        paid, unknown = {}, set()
        for origin, identities in groups.items():
            for settlement_height in range(origin, min(height, origin + MAX_SHARE_AGE) + 1):
                try:
                    block_hash = self.rpc("getblockhash", settlement_height)
                    opening = self._block_snapshot(settlement_height, block_hash, {})
                    for share in opening.shares:
                        if share.proof_id in identities:
                            paid[share.proof_id] = block_hash
                except Exception:
                    unknown.update(identities)
        staged = {}
        parent = self._parent_snapshot(height, tip, staged)
        batch = self._batch(height, tip, parent, staged=staged)["snapshot"]
        selected = {share.proof_id for share in batch.shares}
        result = []
        for identity, origin, parent_hash, revision in rows:
            proof = int(identity, 16)
            current_branch = branch[origin] == parent_hash
            eligible = current_branch and max(self.activation_height, height + 1 - MAX_SHARE_AGE) <= origin <= height + 1
            if not current_branch:
                status = "orphaned"
            elif proof in paid:
                status, eligible = "paid", False
            elif proof in unknown:
                status = "unknown"
            elif not eligible:
                status = "expired_unpaid"
            else:
                status = "selected" if proof in selected else "deferred"
            result.append({"proof_id": identity, "origin_height": origin, "receipt_revision": revision,
                           "status": status, "consensus_eligible": eligible, "settled_in": paid.get(proof)})
        self._stable(tip)
        self._check_seal()
        return {"native_tip": tip, "receipts": tuple(result), "retained_receipts": self._head()["receipt_revision"],
                "next_revision": rows[-1][3] if more else None}

    def _ledger_receipt_status(self, *, after_revision, limit):
        """Report chain-confirmed admission separately from eventual settlement.

        Retained ACKs are provisional. Confirmed pending credits never age out.
        Historical settlement discovery is bounded per page and reports unknown
        if any required native opening is unavailable; it never infers payment
        from the recent admitted tombstone set.
        """
        self._check_seal()
        height, tip = self._context()
        rows = self.db.execute("SELECT identity,height,parent,revision FROM journal WHERE kind=? AND revision>? ORDER BY revision LIMIT ?",
                               (PROOF, after_revision, limit + 1)).fetchall()
        more, rows = len(rows) > limit, rows[:limit]
        staged = {}
        parent = self._parent_snapshot(height, tip, staged)
        selected, selection_checked = None, False
        cache, history_bytes, history_limited = {}, 0, False
        if parent is not None:
            cache[height] = tip, parent
            history_bytes = len(parent.serialize())

        def at(block_height):
            nonlocal history_bytes, history_limited
            if block_height in cache:
                return cache[block_height]
            if len(cache) >= RECEIPT_HISTORY_SNAPSHOTS:
                history_limited = True
                raise ValueError("receipt history page budget")
            block_hash = self.rpc("getblockhash", block_height)
            value = self._block_snapshot(block_height, block_hash, {})
            size = len(value.serialize())
            if history_bytes + size > RECEIPT_HISTORY_BYTES:
                history_limited = True
                raise ValueError("receipt history page byte budget")
            history_bytes += size
            cache[block_height] = block_hash, value
            return block_hash, value

        def credit_in(records, proof):
            for credit in records:
                if credit.proof_id != proof.proof_id:
                    continue
                if (credit.origin_height, credit.pool, credit.native_bits, credit.payout_script) != (
                        proof.envelope.height, proof.envelope.pool, proof.header.nBits, proof.envelope.payout_script):
                    raise ValueError("confirmed credit differs from retained proof")
                return credit
            return None

        result = []
        branch = {}
        for identity, origin, parent_hash, revision in rows:
            proof = parse_share(self._read(PROOF, identity))
            if origin not in branch:
                branch[origin] = self.rpc("getblockhash", origin - 1) if origin <= height + 1 else None
            current_branch = branch[origin] == parent_hash
            eligible = current_branch and max(self.activation_height, height + 1 - MAX_SHARE_AGE) <= origin <= height + 1
            status = "provisional" if eligible else "expired_unanchored"
            admitted_in = settled_in = None
            try:
                pending = credit_in(parent.pending, proof) if parent is not None else None
                settled = credit_in(parent.settled, proof) if parent is not None else None
                if not current_branch:
                    status = "orphaned"
                elif pending is not None:
                    status, eligible = "confirmed_pending", False
                    admitted_in = self.rpc("getblockhash", pending.admitted_height)
                elif settled is not None:
                    status, eligible, settled_in = "settled", False, tip
                    admitted_in = self.rpc("getblockhash", settled.admitted_height)
                else:
                    # Admission is constrained to the original j..j+3 window.
                    # Once admitted, membership in pending only changes when
                    # paid, permitting logarithmic discovery of a later payment.
                    admission_height = None
                    for possible in range(origin, min(height, origin + MAX_SHARE_AGE) + 1):
                        block_hash, value = at(possible)
                        credit = credit_in(value.pending, proof)
                        if credit is not None:
                            admission_height = credit.admitted_height
                            admitted_in = self.rpc("getblockhash", admission_height)
                            break
                    if admission_height is not None:
                        low, high = admission_height, height
                        while high - low > 1:
                            middle = (low + high) // 2
                            unused, value = at(middle)
                            if credit_in(value.pending, proof) is not None:
                                low = middle
                            else:
                                high = middle
                        block_hash, value = at(high)
                        if credit_in(value.settled, proof) is None:
                            raise ValueError("confirmed pending credit disappeared without settlement")
                        status, eligible, settled_in = "settled", False, block_hash
            except Exception:
                status, eligible, settled_in = "unknown", False, None
            if status == "provisional" and not selection_checked:
                selection_checked = True
                try:
                    selected = {entry.proof_id for entry in self._batch(height, tip, parent, staged=staged)["snapshot"].shares}
                except Exception:
                    pass  # Admission selection is unavailable; this is still a provisional ACK.
            chosen = (None if selected is None else proof.proof_id in selected) if status == "provisional" else False
            result.append({"proof_id": identity, "origin_height": origin, "receipt_revision": revision,
                "status": status, "consensus_eligible": eligible,
                "selected_for_admission": chosen,
                "admitted_in": admitted_in, "settled_in": settled_in})
        self._stable(tip)
        self._check_seal()
        return {"native_tip": tip, "receipts": tuple(result), "retained_receipts": self._head()["receipt_revision"],
                "next_revision": rows[-1][3] if more else None, "history_limited": history_limited}

    def _tides_receipt_status(self, *, after_revision, limit):
        """Bounded confirmation lookup; admission is not an assertion of payment.

        A proof may participate in many later rewards, or leave its rolling
        window unpaid. This endpoint does not invent a paid-once status or infer
        current window eligibility from recent anti-replay tombstones.
        """
        self._check_seal()
        height, tip = self._context()
        rows = self.db.execute("SELECT identity,height,parent,revision FROM journal WHERE kind=? AND revision>? ORDER BY revision LIMIT ?",
                               (PROOF, after_revision, limit + 1)).fetchall()
        more, rows = len(rows) > limit, rows[:limit]
        cache, history_bytes, history_limited = {}, 0, False
        parent, selected, selection_checked = None, None, False
        try:
            parent = self._parent_snapshot(height, tip, {})
            if parent is not None:
                cache[height] = tip, parent
                history_bytes = len(parent.serialize())
        except Exception:
            history_limited = True

        def at(block_height):
            nonlocal history_bytes, history_limited
            if block_height in cache:
                return cache[block_height]
            if len(cache) >= RECEIPT_HISTORY_SNAPSHOTS:
                history_limited = True
                raise ValueError("receipt history page budget")
            block_hash = self.rpc("getblockhash", block_height)
            value = self._block_snapshot(block_height, block_hash, {})
            if value is None:
                raise ValueError("receipt predates the TIDES profile")
            size = len(value.serialize())
            if history_bytes + size > RECEIPT_HISTORY_BYTES:
                history_limited = True
                raise ValueError("receipt history page byte budget")
            history_bytes += size
            cache[block_height] = block_hash, value
            return block_hash, value

        result, branch = [], {}
        for identity, origin, parent_hash, revision in rows:
            proof = parse_share(self._read(PROOF, identity))
            if origin not in branch:
                branch[origin] = self.rpc("getblockhash", origin - 1) if origin <= height + 1 else None
            current_branch = branch[origin] == parent_hash
            eligible = current_branch and max(self.activation_height, height + 1 - MAX_SHARE_AGE) <= origin <= height + 1
            status = "provisional" if eligible else "expired_unanchored"
            admitted_in = None
            if not current_branch:
                status = "orphaned"
            else:
                try:
                    for possible in range(max(self.activation_height, origin), min(height, origin + MAX_SHARE_AGE) + 1):
                        block_hash, opening = at(possible)
                        admitted = next((value for value in opening.shares if value.proof_id == proof.proof_id), None)
                        if admitted is not None:
                            if admitted.serialize() != proof.serialize():
                                raise ValueError("confirmed admission differs from retained proof")
                            status, eligible, admitted_in = "confirmed_admitted", False, block_hash
                            break
                except Exception:
                    status, eligible = "unknown", False
            if status == "provisional" and not selection_checked:
                selection_checked = True
                try:
                    if parent is None and height >= self.activation_height:
                        raise ValueError("native parent unavailable")
                    selected = {value.proof_id for value in self._batch(height, tip, parent, staged={})["snapshot"].shares}
                except Exception:
                    pass
            chosen = (None if selected is None else proof.proof_id in selected) if status == "provisional" else False
            result.append({"proof_id": identity, "origin_height": origin, "receipt_revision": revision,
                "pool": f"{proof.envelope.pool:064x}", "payout_script": proof.envelope.payout_script.hex(),
                "status": status, "consensus_eligible": eligible, "selected_for_admission": chosen,
                "admitted_in": admitted_in, "reward_window_eligible": None,
                "reward_history_verified": False})
        self._stable(tip)
        self._check_seal()
        return {"native_tip": tip, "receipts": tuple(result), "retained_receipts": self._head()["receipt_revision"],
                "next_revision": rows[-1][3] if more else None, "history_limited": history_limited,
                "payout_policy": "rolling-tides"}

    def make(self, *, ntime, sign_owner, fees=0, transactions=(), witness=False, native_bits=SHARE_BITS):
        """Explicit fixture helper; use make_native for native mempool jobs."""
        if is_tides_profile(self.profile_version):
            raise ValueError("TIDES jobs require make_native and full native history validation")
        self._check_seal()
        height, tip = self._context()
        staged = {}
        parent = self._parent_snapshot(height, tip, staged)
        batch = self._batch(height, tip, parent, staged=staged)["snapshot"]
        result = candidate(genesis=int(REGTEST_GENESIS, 16), native_parent=int(tip, 16), height=height + 1,
            ntime=ntime, pool=self.pool, payout_script=self.payout_script, public_key=self.public_key,
            sign_owner=sign_owner, templates=batch.templates, shares=batch.shares,
            parent_snapshot=parent, fees=fees, transactions=transactions, witness=witness,
            native_bits=native_bits, version=self.profile_version)
        self._stable(tip)
        return result

    def make_native(self, *, sign_owner):
        """Build, attest and finalize a native mempool job without admitting it.

        The native node derives fees, paid state and coinbase payouts. The gate
        binds both RPC responses to its deterministic proposal and exact signer
        payload. Call authorize on the returned pair before dispatching work.
        """
        if not callable(sign_owner):
            raise ValueError("native jobs require an external owner signer")
        self._check_seal()
        height, tip = self._context()
        staged = {}
        parent = self._parent_snapshot(height, tip, staged)
        batch = self._batch(height, tip, parent, staged=staged)
        proposal = batch["snapshot"]

        def decode(result):
            if not isinstance(result, dict):
                raise ValueError("native job response must be an object")
            bodies = []
            for name, bound in (("template", MAX_TEMPLATE_BYTES), ("snapshot", self.snapshot_budget)):
                encoded = result.get(name)
                if type(encoded) is not str or not 1 <= len(encoded) <= 2 * bound:
                    raise ValueError("native job response exceeds " + name + " byte bound")
                bodies.append(bytes.fromhex(encoded))
            raw, snapshot_raw = bodies
            block, snapshot = parse_block(raw), Snapshot.deserialize(snapshot_raw)
            if is_tides_profile(self.profile_version) and block.nBits != batch["native_bits"]:
                raise ValueError("native difficulty changed after payout reservation; prepare a new job")
            reward = result.get("reward")
            if (normalize_template(raw) != raw or block.hashPrevBlock != int(tip, 16) or
                    block.m_height != height + 1 or snapshot.envelope != proposal.envelope or
                    snapshot.job_commitment != job_hash(block) or block.m_mm_rhs != snapshot.hash or
                    type(reward) is not int or not 0 <= reward <= 21_000_000 * 100_000_000 or
                    result.get("native_parent") != tip or result.get("height") != height + 1 or
                    result.get("commitment") != snapshot.hash_hex or
                    result.get("job_commitment") != f"{snapshot.job_commitment:064x}"):
                raise ValueError("native job response failed policy, template or commitment binding")
            # Native construction may change payout amounts to its actual fees;
            # every other proposed accounting byte remains fixed.
            # v6 payouts require the full authenticated history at the native
            # node. Never substitute the v4 one-batch or v5 one-time formula.
            payouts = (snapshot.payouts if is_tides_profile(self.profile_version) else
                       credit_outputs(proposal.settled, reward, self.payout_script) if self.profile_version == LEDGER_VERSION else
                       work_outputs(proposal.shares, reward=reward, fallback_script=self.payout_script))
            expected = replace(proposal, job_commitment=snapshot.job_commitment, payouts=payouts,
                owner_signature=snapshot.owner_signature)
            if expected.serialize() != snapshot_raw:
                raise ValueError("native job changed the proposed settlement evidence or payouts")
            self._stable(tip)
            return block, snapshot, reward

        prepared = self.rpc("preparesharepoolhashjob", proposal.serialize().hex())
        block, snapshot, reward = decode(prepared)
        if (snapshot.owner_signature != bytes(64) or
                prepared.get("signing_payload") != snapshot.signing_payload.hex() or
                prepared.get("signing_hash") != snapshot.owner_message[::-1].hex()):
            raise ValueError("native job signing payload failed exact snapshot binding")
        signature = sign_owner(snapshot)
        if (type(signature) is not bytes or len(signature) != 64 or
                not verify_schnorr(self.public_key, signature, snapshot.owner_message)):
            raise ValueError("external owner signer returned an invalid job attestation")
        signed = replace(snapshot, owner_signature=signature)
        self._stable(tip)
        final = self.rpc("finalizesharepoolhashjob", block.serialize().hex(), signed.serialize().hex())
        final_block, final_snapshot, final_reward = decode(final)
        if (final_snapshot.serialize() != signed.serialize() or final_reward != reward or
                job_hash(final_block) != job_hash(block)):
            raise ValueError("native finalization changed the signed job")
        if is_tides_profile(self.profile_version):
            self._native_template(final_block.serialize(), tip, final_snapshot.serialize())
        self._check_seal()
        return final_block, final_snapshot

    def authorize(self, raw, snapshot_raw=None):
        """Validate a whole offer before acknowledging any of its evidence.

        Native validation uses a temporary snapshot overlay. Only the final
        single journal commit constitutes local admission; refusals cannot
        invalidate a previously frozen job by advancing its evidence sequence.
        Announce an accepted snapshot separately with register_snapshot().
        """
        self._check_seal()
        height, tip = self._context()
        block = parse_block(raw)
        if block.hashPrevBlock != int(tip, 16) or block.m_height != height + 1:
            raise ValueError("new mining jobs require the current native parent")
        staged = {}
        if snapshot_raw is not None:
            if Snapshot.deserialize(snapshot_raw).hash != block.m_mm_rhs:
                raise ValueError("job and supplied snapshot commitments differ")
            staged[SNAPSHOT, f"{block.m_mm_rhs:064x}"] = snapshot_raw
        snapshot = self._snapshot(block.m_mm_rhs, staged)
        envelope = snapshot.envelope
        if (envelope.pool, envelope.public_key, envelope.payout_script) != (self.pool, self.public_key, self.payout_script):
            raise ValueError("job violates this miner's pool/key/payout policy")
        if self.profile_version == VARIABLE_TIDES_VERSION and envelope.share_work_bits != self._share_work_bits:
            raise ValueError("new job violates this miner's current share-work assignment")
        if len(snapshot.serialize()) > self.snapshot_budget:
            raise ValueError("job exceeds this miner's settlement byte budget")
        # Bound and retain the complete candidate's provenance in a temporary
        # map. Native overlay preflight then establishes validity; neither step
        # admits an unsuccessful offer to the local journal.
        self._provenance(snapshot, staged, mining_job=True)
        self._rehydrate_retained(staged)
        self._native_template(raw, tip, snapshot.serialize())

        # Check policy against the already acknowledged set. Introduced origins
        # and dependencies are staged without changing that set or its revision.
        for record in snapshot.templates:
            origin = parse_block(record.data)
            opening = self._snapshot(origin.m_mm_rhs, staged)
            if (not self._relay_pool(opening.envelope.pool) or opening.envelope.genesis != int(REGTEST_GENESIS, 16) or
                    opening.envelope.height != origin.m_height or opening.envelope.native_parent != origin.hashPrevBlock or
                    not self._eligible(origin.m_height, f"{origin.hashPrevBlock:064x}", height)):
                raise ValueError("template is outside this pool or eligible native ancestry")
            staged[TEMPLATE, f"{record.template_id:064x}"] = record.data
        parent = self._parent_snapshot(height, tip, staged)
        included = {share.proof_id for share in snapshot.shares}
        batch = self._batch(height, tip, parent, staged=staged, offered=snapshot.shares, templates=snapshot.templates)["snapshot"]
        expected = {share.proof_id for share in batch.shares}
        missing = [f"{identity:064x}" for identity in expected - included]
        if missing:
            raise JobOmission(missing)
        if included != expected:
            raise ValueError("job does not contain the deterministic eligible work prefix")
        own_id = template_id(block)
        required = {f"{record.template_id:064x}" for record in batch.templates}
        supplied = {f"{record.template_id:064x}" for record in snapshot.templates}
        if required != supplied or own_id in supplied:
            raise TemplateOmission(required - supplied)

        # Preserve the complete local origin of every prospective receipt.
        for share in snapshot.shares:
            self._require_origin(share, staged)
            staged[PROOF, f"{share.proof_id:064x}"] = share.serialize()
        self._stable(tip)
        staged[TEMPLATE, own_id] = normalize_template(raw)
        self._persist([(kind, body) for (kind, unused), body in staged.items()])
        head = self.archive_head()
        authorization = HashMiningAuthorization(raw, tip, snapshot.hash_hex, head["receipt_revision"],
            snapshot.serialize(), head["events"], height, self._dispatch_policy())
        return replace(authorization, dispatch_seal=self._dispatch_mac(authorization))

    def _dispatch_policy(self):
        """Bind stable policy, excluding the next job's mutable v8 assignment.

        Exact assigned bits are already MAC-bound inside snapshot_bytes. A
        later retarget must not revoke or rewrite an issued job's old target.
        """
        value = {"config": self.config.hex(), "binding": self.binding, "genesis": REGTEST_GENESIS,
            "pool": self.pool, "public_key": self.public_key.hex(), "payout_script": self.payout_script.hex(),
            "snapshot_budget": self.snapshot_budget, "profile_version": self.profile_version,
            "rules": self.rules, "mode": self.mode, "activation_height": self.activation_height,
            "quota": self.quota}
        return hashlib.sha256(native_archive.canonical(value)).hexdigest()

    def _dispatch_mac(self, authorization):
        # Hash the exact immutable bytes, not only the job/snapshot identifiers.
        # Incremental updates avoid copying the potentially large job together
        # with its opening. Explicit lengths make the encoding unambiguous.
        digest = hmac.new(self._dispatch_key, b"SharePool/hash-gate/dispatch/v1\0", hashlib.sha256)
        digest.update(struct.pack("<QQQ", authorization.native_height,
            authorization.receipt_sequence, authorization.evidence_sequence))
        for value in (bytes.fromhex(authorization.policy_binding), bytes.fromhex(authorization.native_parent),
                      bytes.fromhex(authorization.commitment), authorization.block_bytes, authorization.snapshot_bytes):
            digest.update(struct.pack("<Q", len(value)))
            digest.update(value)
        return digest.digest()

    def _issued_authorization(self, authorization):
        if (self.db is None or self._dispatch_key is None or os.getpid() != self._dispatch_pid or
                type(authorization) is not HashMiningAuthorization):
            return False
        try:
            if (set(vars(authorization)) != HashMiningAuthorization.__dataclass_fields__.keys() or
                    type(authorization.block_bytes) is not bytes or not 1 <= len(authorization.block_bytes) <= MAX_TEMPLATE_BYTES or
                    type(authorization.snapshot_bytes) is not bytes or not 1 <= len(authorization.snapshot_bytes) <= MAX_SNAPSHOT_BYTES or
                    type(authorization.dispatch_seal) is not bytes or len(authorization.dispatch_seal) != 32 or
                    type(authorization.native_height) is not int or not 0 <= authorization.native_height < 0x7fffffff or
                    any(type(value) is not int or not 0 <= value <= hash_gate_archive.MAX_COUNTER
                        for value in (authorization.receipt_sequence, authorization.evidence_sequence)) or
                    any(not native_archive.is_hash(value) for value in
                        (authorization.native_parent, authorization.commitment, authorization.policy_binding)) or
                    authorization.policy_binding != self._dispatch_policy()):
                return False
            return hmac.compare_digest(authorization.dispatch_seal, self._dispatch_mac(authorization))
        except (AttributeError, TypeError, ValueError, OverflowError):
            # Even exact frozen dataclasses can be fabricated with __new__ or
            # altered with object.__setattr__. They are data, not authority.
            return False

    def _dispatch_context_current(self, authorization, *, newer_receipts=False):
        if not self._issued_authorization(authorization):
            return False
        self._check_seal()
        height, tip = self._context()
        head = self._head()
        self._stable(tip)
        receipts = head["receipt_revision"]
        return (tip == authorization.native_parent and height == authorization.native_height and
                (receipts >= authorization.receipt_sequence if newer_receipts else
                 receipts == authorization.receipt_sequence) and
                head["events"] >= authorization.evidence_sequence)

    def needs_refresh(self, authorization):
        return not self._dispatch_context_current(authorization)

    def ready_for_continued_work(self, authorization):
        """Check context for an already dispatched job with its fixed cutoff.

        Later acknowledged receipts belong to a subsequent job; they cannot
        rewrite the bytes already being hashed. This is not initial dispatch
        approval or evidence that a caller actually dispatched the capability.
        A scheduler must track that handoff itself and still use the strict
        ready_for_dispatch fence for every new job. No validity is cached here.
        """
        return self._dispatch_context_current(authorization, newer_receipts=True)

    def ready_for_dispatch(self, authorization):
        """Fence initial dispatch of a job issued by this open gate instance.

        An invalid or altered capability returns False; native/profile/journal
        failures raise and also prohibit dispatch. The caller must dispatch the
        returned immutable block_bytes, keep observing refresh signals, and
        authorize again after restart. This is not an in-process sandbox.
        """
        return not self.needs_refresh(authorization)

    def close(self):
        self._dispatch_key = None
        self._description_cache.clear()
        self._snapshot_decode_cache.clear()
        self._origin_facts_cache.clear()
        self._compact_state_cache.clear()
        self._signature_cache.clear()
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
