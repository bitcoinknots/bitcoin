#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Streaming, immutable hash-gate archive segments.

Segments are evidence copies, never a source of trust for their own checkpoint.
The terminal checkpoint comes from independently protected local state. Each
record is bounded before reading its body; no export is materialized in memory.
"""
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

import native_archive

MAGIC = b"SPHARC1\0"
HEADER_LIMIT = 8192
RECORD = struct.Struct("<QBQI32s32s32s32s")
MAX_COUNTER = (1 << 63) - 1


def check_head(head):
    """Lifetime counters are bounded by SQLite/int64, not a retention quota."""
    if (type(head) is not dict or set(head) != native_archive.HEAD_FIELDS or type(head["version"]) is not int or
            head["version"] != 1 or not native_archive.is_hash(head["binding"]) or not native_archive.is_hash(head["root"]) or
            any(type(head[key]) is not int or not 0 <= head[key] <= MAX_COUNTER for key in ("events", "receipt_revision", "bytes")) or
            head["receipt_revision"] > head["events"]):
        raise native_archive.ArchiveError("invalid trusted hash-gate checkpoint")
    return dict(head)


def read_head(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise native_archive.ArchiveError("protected checkpoint is missing or invalid") from None
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid() or status.st_nlink != 1 or
                status.st_mode & 0o022 or not 1 <= status.st_size <= 4096):
            raise native_archive.ArchiveError("protected checkpoint has unsafe ownership, mode or size")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(4097)
    finally:
        os.close(descriptor)
    try:
        head = json.loads(raw)
    except (ValueError, UnicodeError):
        raise native_archive.ArchiveError("malformed protected checkpoint") from None
    check_head(head)
    if raw != native_archive.canonical(head) + b"\n":
        raise native_archive.ArchiveError("noncanonical protected checkpoint")
    return head


def write_head(path, head, *, exclusive=False):
    check_head(head)
    path = Path(path)
    if path.exists() or path.is_symlink():
        if exclusive:
            raise FileExistsError(str(path))
        read_head(path)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(native_archive.canonical(head) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_segment(path, *, start, end, records):
    """Publish a complete immutable segment, never overwrite an existing copy."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(str(path))
    header = native_archive.canonical({"version": 1, "start": start, "end": end})
    if len(header) > HEADER_LIMIT:
        raise native_archive.ArchiveError("archive header exceeds bound")
    descriptor, staging = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(MAGIC + struct.pack("<I", len(header)) + header)
            for sequence, kind, revision, identity, digest, previous, root, raw in records:
                stream.write(RECORD.pack(sequence, kind, revision, len(raw), bytes.fromhex(identity),
                    bytes.fromhex(digest), bytes.fromhex(previous), bytes.fromhex(root)))
                stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, path)
        _sync_directory(path.parent)
    finally:
        Path(staging).unlink(missing_ok=True)
    return dict(end)


def records(paths, *, initial, trusted_head, limits, next_head, with_offsets=False):
    """Yield a contiguous segment chain and verify its exact trusted endpoint.

    Consumers must exhaust this iterator before publishing recovered evidence.
    next_head performs protocol-specific event hashing and counter checks.
    """
    trusted_head = check_head(trusted_head)
    if trusted_head["binding"] != initial["binding"]:
        raise native_archive.ArchiveError("archive checkpoint binding mismatch")
    if isinstance(paths, (str, os.PathLike)):
        paths = (paths,)
    current, count = dict(initial), 0
    for path in paths:
        count += 1
        if count > trusted_head["events"] + 1:
            raise native_archive.ArchiveError("archive segment count exceeds bound")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise native_archive.ArchiveError("archive segment is missing or invalid") from None
        with os.fdopen(descriptor, "rb") as stream:
            status = os.fstat(stream.fileno())
            if not stat.S_ISREG(status.st_mode) or not 1 <= status.st_size <= MAX_COUNTER:
                raise native_archive.ArchiveError("archive segment exceeds file bound")
            if native_archive._take(stream, len(MAGIC)) != MAGIC:
                raise native_archive.ArchiveError("unsupported hash-gate archive segment")
            size = struct.unpack("<I", native_archive._take(stream, 4))[0]
            if not 1 <= size <= HEADER_LIMIT:
                raise native_archive.ArchiveError("archive header exceeds bound")
            raw_header = native_archive._take(stream, size)
            try:
                header = json.loads(raw_header)
            except (ValueError, UnicodeError):
                raise native_archive.ArchiveError("malformed archive header") from None
            if (type(header) is not dict or set(header) != {"version", "start", "end"} or
                    type(header["version"]) is not int or header["version"] != 1 or
                    raw_header != native_archive.canonical(header)):
                raise native_archive.ArchiveError("noncanonical archive header")
            start, end = check_head(header["start"]), check_head(header["end"])
            if (start != current or end["binding"] != initial["binding"] or
                    not start["events"] <= end["events"] <= trusted_head["events"] or
                    not start["bytes"] <= end["bytes"] <= trusted_head["bytes"]):
                raise native_archive.ArchiveError("archive segments have a gap or another binding")
            if status.st_size != 12 + size + end["bytes"] - start["bytes"]:
                raise native_archive.ArchiveError("archive segment size differs from its checkpoints")
            for unused in range(end["events"] - start["events"]):
                offset = stream.tell()
                sequence, kind, revision, size, identity, digest, previous, root = RECORD.unpack(
                    native_archive._take(stream, RECORD.size))
                if kind >= len(limits) or not 1 <= size <= limits[kind]:
                    raise native_archive.ArchiveError("archive record exceeds body bound")
                raw = native_archive._take(stream, size)
                expected, expected_digest = next_head(current, kind, identity.hex(), raw)
                if (sequence != expected["events"] or revision != expected["receipt_revision"] or
                        previous.hex() != current["root"] or root.hex() != expected["root"] or
                        digest.hex() != expected_digest):
                    raise native_archive.ArchiveError("archive record failed its hash chain")
                yield (kind, identity.hex(), raw, offset) if with_offsets else (kind, identity.hex(), raw)
                current = expected
            if stream.read(1) or current != end:
                raise native_archive.ArchiveError("archive segment has a wrong endpoint or trailing bytes")
    if not count or current != trusted_head:
        raise native_archive.ArchiveError("archive is incomplete at the trusted checkpoint")
