#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Append-only gate evidence and independently protected durable high-water.

A hash chain proves completeness only relative to a trusted checkpoint. Rolling
back both the database and its protected checkpoint is outside this mechanism.
No peer-provided checkpoint is trusted here. Records and exports are streamed.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import stat
import tempfile

DEFAULT_QUOTA = 512 * 1024 * 1024
MAX_QUOTA = 4 * 1024 * 1024 * 1024
MAX_EVENTS = 1_000_000
MAX_DATA = 4_000_000
MAGIC = b"SPNARC1\x00"
RECORD = struct.Struct("<QBQI32s32s32s32s")
HEAD_FIELDS = {"version", "binding", "events", "root", "receipt_revision", "bytes"}


class ArchiveError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def is_hash(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def check_head(head):
    if (type(head) is not dict or set(head) != HEAD_FIELDS or type(head["version"]) is not int or
            head["version"] != 1 or not is_hash(head["binding"]) or not is_hash(head["root"]) or
            type(head["events"]) is not int or not 0 <= head["events"] <= MAX_EVENTS or
            type(head["receipt_revision"]) is not int or not 0 <= head["receipt_revision"] <= head["events"] or
            type(head["bytes"]) is not int or not 0 <= head["bytes"] <= MAX_QUOTA):
        raise ArchiveError("invalid trusted archive checkpoint")
    return dict(head)


def initial_head(binding):
    return {"version": 1, "binding": binding, "events": 0,
            "root": digest(b"SharePool/archive/genesis/v1\x00" + bytes.fromhex(binding)),
            "receipt_revision": 0, "bytes": 0}


def next_head(head, kind, identity, raw, receipt_revision):
    if (kind not in (0, 1) or type(kind) is not int or not is_hash(identity) or
            type(raw) is not bytes or not 1 <= len(raw) <= (MAX_DATA if kind == 0 else 1024) or
            receipt_revision != head["receipt_revision"] + kind):
        raise ArchiveError("invalid contiguous archive event")
    sequence = head["events"] + 1
    if sequence > MAX_EVENTS:
        raise ArchiveError("archive event quota exhausted; no work acknowledged")
    data_hash = digest(raw)
    root = digest(b"SharePool/archive/event/v1\x00" + bytes.fromhex(head["root"]) +
                  struct.pack("<QBQI", sequence, kind, receipt_revision, len(raw)) +
                  bytes.fromhex(identity) + bytes.fromhex(data_hash))
    result = dict(head, events=sequence, root=root, receipt_revision=receipt_revision,
                  bytes=head["bytes"] + RECORD.size + len(raw))
    return result, data_hash


def read_head(path):
    """Read the protected final inode without following a substituted symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ArchiveError("protected archive checkpoint is missing or invalid") from None
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid() or
                status.st_nlink != 1 or status.st_mode & 0o022 or not 1 <= status.st_size <= 4096):
            raise ArchiveError("protected archive checkpoint has unsafe ownership, mode or size")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ArchiveError("protected archive checkpoint exceeds bound")
    finally:
        os.close(descriptor)
    try:
        head = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ArchiveError("protected archive checkpoint is malformed") from None
    check_head(head)
    if raw != canonical(head) + b"\n":
        raise ArchiveError("protected archive checkpoint is not canonical")
    return head


def write_head(path, head, *, exclusive=False):
    """Fsync data and its directory before any corresponding acknowledgment."""
    check_head(head)
    path = Path(path)
    if path.exists() or path.is_symlink():
        if exclusive:
            raise FileExistsError(str(path))
        read_head(path)  # Refuse replacing unsafe or corrupt existing checkpoints.
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(head) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _take(stream, count):
    raw = stream.read(count)
    if len(raw) != count:
        raise ArchiveError("truncated archive export")
    return raw


def export_records(path, *, trusted_head, binding, quota):
    """Yield a fully bound, sequential binary export without trusting its header.

    The caller must consume to EOF before relying on completeness. Each record
    is bounded before allocation, and the final checkpoint must match exactly.
    """
    trusted_head = check_head(trusted_head)
    if trusted_head["binding"] != binding or trusted_head["bytes"] > quota:
        raise ArchiveError("archive checkpoint binding or quota mismatch")
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ArchiveError("archive export is missing or invalid") from None
    stream = os.fdopen(descriptor, "rb")
    with stream:
        status = os.fstat(stream.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_size > quota + 8192:
            raise ArchiveError("archive export is missing or exceeds quota")
        if _take(stream, len(MAGIC)) != MAGIC:
            raise ArchiveError("unsupported archive export")
        size = struct.unpack("<I", _take(stream, 4))[0]
        if not 1 <= size <= 4096:
            raise ArchiveError("archive header exceeds bound")
        raw_header = _take(stream, size)
        if raw_header != canonical(trusted_head):
            raise ArchiveError("archive export does not match the trusted high-water")
        current = initial_head(binding)
        for unused in range(trusted_head["events"]):
            sequence, kind, revision, size, identity, data_hash, previous, root = RECORD.unpack(_take(stream, RECORD.size))
            if kind not in (0, 1) or not 1 <= size <= (MAX_DATA if kind == 0 else 1024):
                raise ArchiveError("archive record exceeds bound")
            raw = _take(stream, size)
            expected, expected_hash = next_head(current, kind, identity.hex(), raw, revision)
            if (sequence != expected["events"] or previous.hex() != current["root"] or
                    root.hex() != expected["root"] or data_hash.hex() != expected_hash or expected["bytes"] > quota):
                raise ArchiveError("archive export contains a gap or corrupt event")
            yield (sequence, kind, identity.hex(), revision, expected_hash, raw, previous.hex(), root.hex())
            current = expected
        if stream.read(1) or current != trusted_head:
            raise ArchiveError("archive export is incomplete or contains trailing data")


class DurableArchive:
    """Caller owns SQLite transaction boundaries and its exclusive process lock."""
    def __init__(self, db, *, binding, quota):
        if type(quota) is not int or not 4096 <= quota <= MAX_QUOTA:
            raise ArchiveError("archive quota must be between 4096 bytes and 4 GiB")
        self.db, self.binding, self.quota = db, binding, quota

    def create(self):
        self.db.execute("CREATE TABLE archive_events (sequence INTEGER PRIMARY KEY, kind INTEGER NOT NULL, identity TEXT NOT NULL, receipt_revision INTEGER NOT NULL, data_hash TEXT NOT NULL, data BLOB NOT NULL, previous_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, origin_height INTEGER NOT NULL, origin_parent TEXT NOT NULL, origin_template TEXT NOT NULL, UNIQUE(kind,identity))")
        self.db.execute("CREATE INDEX archive_origin_height ON archive_events(origin_height,kind)")
        self.db.execute("CREATE TABLE archive_state (singleton INTEGER PRIMARY KEY, value TEXT NOT NULL, initialized INTEGER NOT NULL)")
        self.db.execute("INSERT INTO archive_state VALUES (1,?,0)", (canonical(initial_head(self.binding)).decode(),))

    def head(self):
        saved = self.db.execute("SELECT singleton,value FROM archive_state LIMIT 2").fetchall()
        if len(saved) != 1 or saved[0][0] != 1 or len(saved[0][1]) > 4096:
            raise ArchiveError("archive high-water metadata is invalid")
        try:
            result = json.loads(saved[0][1])
        except (ValueError, TypeError):
            raise ArchiveError("archive high-water metadata is malformed") from None
        check_head(result)
        if result["binding"] != self.binding or canonical(result).decode() != saved[0][1]:
            raise ArchiveError("archive belongs to another miner or pool")
        if result["bytes"] > self.quota:
            raise ArchiveError("archive exceeds configured quota")
        return result

    def append(self, kind, identity, raw, *, origin_height, origin_parent, origin_template, receipt_revision=None):
        if type(origin_height) is not int or origin_height < 1 or not is_hash(origin_parent) or not is_hash(origin_template):
            raise ArchiveError("invalid archived origin context")
        previous = self.head()
        saved = self.db.execute("SELECT data_hash,length(data) FROM archive_events WHERE kind=? AND identity=?", (kind, identity)).fetchone()
        if saved is not None:
            # Template identity excludes mutable PoW search fields. The gate
            # checks normalized header equivalence; retain its original body.
            if kind == 1 and saved != (digest(raw), len(raw)):
                raise ArchiveError("acknowledged proof differs from its durable archive")
            return False
        revision = previous["receipt_revision"] if kind == 0 else receipt_revision
        current, data_hash = next_head(previous, kind, identity, raw, revision)
        if current["bytes"] > self.quota:
            raise ArchiveError("archive byte quota exhausted; no work acknowledged")
        self.db.execute("INSERT INTO archive_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (current["events"], kind, identity, revision, data_hash, raw, previous["root"], current["root"],
                         origin_height, origin_parent, origin_template))
        self.db.execute("UPDATE archive_state SET value=? WHERE singleton=1", (canonical(current).decode(),))
        return True

    def records(self, *, trusted_prefix=None):
        head = self.head()
        prefix = initial_head(self.binding) if trusted_prefix is None else check_head(trusted_prefix)
        if prefix["binding"] != self.binding or prefix["events"] > head["events"]:
            raise ArchiveError("archive is behind its protected high-water")
        count, size, oversized = self.db.execute("SELECT count(*),COALESCE(sum(length(data)+?),0),COALESCE(max(length(data)),0) FROM archive_events", (RECORD.size,)).fetchone()
        if count != head["events"] or size != head["bytes"] or oversized > MAX_DATA or count > MAX_EVENTS:
            raise ArchiveError("archive count or byte integrity failed")
        current, matched = initial_head(self.binding), prefix == initial_head(self.binding)
        cursor = self.db.execute("SELECT sequence,kind,identity,receipt_revision,data_hash,data,previous_hash,chain_hash FROM archive_events ORDER BY sequence")
        for sequence, kind, identity, revision, data_hash, data, previous, root in cursor:
            if type(data) is not bytes:
                raise ArchiveError("archive evidence is not canonical bytes")
            expected, expected_hash = next_head(current, kind, identity, data, revision)
            if (sequence != expected["events"] or previous != current["root"] or
                    root != expected["root"] or data_hash != expected_hash):
                raise ArchiveError("archive contains a missing or corrupt event")
            if sequence == prefix["events"]:
                matched = expected == prefix
            yield (sequence, kind, identity, revision, data_hash, data, previous, root)
            current = expected
        if current != head or not matched:
            raise ArchiveError("archive diverges from protected high-water")

    def extension_records(self, prefix):
        """Verify only a newly committed extension of an already verified head."""
        prefix, head = check_head(prefix), self.head()
        if prefix["binding"] != self.binding or prefix["events"] > head["events"]:
            raise ArchiveError("archive is behind its protected high-water")
        if prefix["events"]:
            saved = self.db.execute("SELECT chain_hash,receipt_revision FROM archive_events WHERE sequence=?", (prefix["events"],)).fetchone()
            if saved != (prefix["root"], prefix["receipt_revision"]):
                raise ArchiveError("archive diverges from protected high-water")
        elif prefix != initial_head(self.binding):
            raise ArchiveError("archive genesis checkpoint is invalid")
        current = prefix
        for row in self.db.execute("SELECT sequence,kind,identity,receipt_revision,data_hash,data,previous_hash,chain_hash FROM archive_events WHERE sequence>? ORDER BY sequence", (prefix["events"],)):
            sequence, kind, identity, revision, data_hash, raw, previous, root = row
            expected, expected_hash = next_head(current, kind, identity, raw, revision)
            if (sequence != expected["events"] or previous != current["root"] or
                    root != expected["root"] or data_hash != expected_hash):
                raise ArchiveError("archive extension is missing or corrupt")
            yield row
            current = expected
        if current != head:
            raise ArchiveError("archive extension does not match durable high-water")

    def export(self, path, *, trusted_prefix):
        path, head = Path(path), self.head()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                encoded = canonical(head)
                stream.write(MAGIC + struct.pack("<I", len(encoded)) + encoded)
                for sequence, kind, identity, revision, data_hash, raw, previous, root in self.records(trusted_prefix=trusted_prefix):
                    stream.write(RECORD.pack(sequence, kind, revision, len(raw), bytes.fromhex(identity),
                                             bytes.fromhex(data_hash), bytes.fromhex(previous), bytes.fromhex(root)))
                    stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return head
