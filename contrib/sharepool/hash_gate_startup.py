#!/usr/bin/env python3
"""Full authenticated journal verification with sequential cold-segment reads.

No persisted verification cache or filesystem timestamps replace evidence reads.
Every startup still authenticates the complete lifetime journal and every proof's
exact origin. This removes duplicate reads and file opens, not security checks.
"""
import hash_gate_archive
import native_archive
from hash_snapshot import MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, parse_share


LIMITS = (MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, 1024)
PROOF = 2


def verify_store(gate, prefix):
    """Verify all bytes and metadata, retaining at most one segment/body reader."""
    prefix = hash_gate_archive.check_head(prefix)
    head = gate._head()
    if prefix["binding"] != gate.binding or prefix["events"] > head["events"]:
        raise ValueError("journal is behind protected high-water")
    overhead = hash_gate_archive.RECORD.size
    count, size, bad, resident = gate.db.execute(
        "SELECT count(*),COALESCE(sum(size+?),0),COALESCE(sum(kind NOT IN (0,1,2) OR typeof(data)!='blob' OR typeof(size)!='integer' OR size<1 OR size>CASE kind WHEN 0 THEN ? WHEN 1 THEN ? ELSE 1024 END OR typeof(segment)!='integer' OR segment<0 OR typeof(offset)!='integer' OR (segment=0 AND (offset!=0 OR length(data)!=size)) OR (segment>0 AND (offset<12 OR length(data)!=0))),0),COALESCE(sum(CASE WHEN segment=0 THEN size+? ELSE 0 END),0) FROM journal",
        (overhead, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES, overhead)).fetchone()
    if count != head["events"] or size != head["bytes"] or bad or resident != gate.resident_bytes():
        raise ValueError("journal count or data length failed integrity")
    invalid = gate.db.execute(
        "SELECT 1 FROM journal WHERE typeof(sequence)!='integer' OR sequence<1 OR typeof(kind)!='integer' OR typeof(revision)!='integer' OR revision<0 OR typeof(height)!='integer' OR height<1 OR height>4294967295 OR typeof(identity)!='text' OR length(identity)!=64 OR typeof(digest)!='text' OR length(digest)!=64 OR typeof(previous)!='text' OR length(previous)!=64 OR typeof(root)!='text' OR length(root)!=64 OR typeof(parent)!='text' OR length(parent)!=64 LIMIT 1").fetchone()
    if invalid is not None:
        raise ValueError("journal scalar metadata exceeds its bound")
    # Validate the complete segment table and its exact row ranges before any
    # body is materialized. A dangling/overlapping segment is never ignored.
    gate._cold_prefix()
    current = native_archive.initial_head(gate.binding)
    matched = current == prefix
    stream, stream_segment = None, None

    def advance():
        try:
            return next(stream)
        except native_archive.ArchiveError as error:
            if str(error) == "archive segment is missing or invalid":
                raise ValueError("acknowledged cold archive data is unavailable") from None
            raise

    def finish_segment():
        nonlocal stream, stream_segment
        if stream is not None:
            try:
                advance()
            except StopIteration:
                pass
            else:
                raise ValueError("cold archive segment has unreferenced records")
            finally:
                stream.close()
                stream, stream_segment = None, None

    try:
        cursor = gate.db.execute(
            "SELECT sequence,kind,identity,digest,previous,root,revision,height,parent,size,segment,offset,data FROM journal ORDER BY sequence")
        for sequence, kind, identity, digest, previous, root, revision, height, parent, size, segment, offset, raw in cursor:
            if segment != stream_segment:
                finish_segment()
                if segment:
                    path, start, end = gate._segment(segment)
                    if start != current:
                        raise ValueError("cold archive segment does not continue verified journal")
                    stream = hash_gate_archive.records(path, initial=start, trusted_head=end,
                        limits=LIMITS, next_head=gate._next, with_offsets=True)
                    stream_segment = segment
            if segment:
                try:
                    actual_kind, actual_identity, raw, actual_offset = advance()
                except StopIteration:
                    raise ValueError("cold archive segment has missing journal records") from None
                if (actual_kind, actual_identity, actual_offset) != (kind, identity, offset):
                    raise ValueError("cold archive record metadata differs from acknowledged evidence")
            if type(raw) is not bytes or len(raw) != size:
                raise ValueError("stored evidence failed read-time integrity")
            expected, expected_digest = gate._next(current, kind, identity, raw)
            if (sequence != expected["events"] or digest != expected_digest or previous != current["root"] or
                    root != expected["root"] or revision != expected["receipt_revision"] or
                    gate._describe(kind, raw) != (identity, height, parent)):
                raise ValueError("journal contains missing or corrupt acknowledged evidence")
            # Dependencies are still obtained through fresh authenticated reads.
            # They may occur later in the journal: the full hash-chain pass must
            # also succeed before the gate can acknowledge any new work.
            if kind == PROOF:
                gate._require_origin(parse_share(raw))
            current = expected
            if sequence == prefix["events"]:
                matched = current == prefix
        finish_segment()
        if current != head or not matched:
            raise ValueError("journal diverges from protected high-water")
    finally:
        if stream is not None:
            stream.close()


def write_verified_archive(gate, path, *, start, end):
    """Write a suffix immediately after the caller's full store verification.

This private helper is used by export and rollover under the same owner lock.
It never certifies a checkpoint or skips source read-time authentication. Every
exported record and the sealed endpoint are checked again while streaming.
"""
    start, end = hash_gate_archive.check_head(start), hash_gate_archive.check_head(end)
    gate._check_seal()
    if (start["binding"] != gate.binding or end != gate.archive_head() or
            start["events"] > end["events"] or start["bytes"] > end["bytes"]):
        raise native_archive.ArchiveError("archive write is outside verified checkpoint bounds")

    def records():
        current = start
        cursor = gate.db.execute(
            "SELECT sequence,kind,identity,digest,previous,root,revision FROM journal WHERE sequence>? ORDER BY sequence",
            (start["events"],))
        for sequence, kind, identity, digest, previous, root, revision in cursor:
            raw = gate._read(kind, identity)
            expected, expected_digest = gate._next(current, kind, identity, raw)
            if (sequence != expected["events"] or revision != expected["receipt_revision"] or
                    previous != current["root"] or root != expected["root"] or digest != expected_digest):
                raise native_archive.ArchiveError("journal export diverges from its trusted checkpoint")
            yield sequence, kind, revision, identity, digest, previous, root, raw
            current = expected
        if current != end:
            raise native_archive.ArchiveError("journal changed during archive export")
        gate._check_seal()

    return hash_gate_archive.write_segment(path, start=start, end=end, records=records())
