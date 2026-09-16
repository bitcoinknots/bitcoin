# Native archive startup and index repair

This change affects local evidence storage. It changes no snapshot hash, payout
rule, activation schedule or public-network behavior. It does not change the
portable archive chunk format.

## Normal restart

Each accepted snapshot commits its raw bytes, size/checksum metadata, bounded
template-source references and exact aggregate counters in one synchronous
LevelDB write batch. Quarantine updates its metadata and counters in the same
way. A format-versioned checkpoint binds the selected snapshot profile and its
rules hash. Local job records are retired only after a durable snapshot source
has been indexed. At most four source references are retained per template, and
a new snapshot replaces the oldest reference when that bound is reached.

Ordinary restart reads the ready checkpoint and checks the configured quota
against its charged-byte total. It does not traverse snapshot records or populate
the historical snapshot cache. Raising the quota therefore does not trigger a
scan. Snapshot payloads remain authenticated on uncached retrieval. A checksum
on each source index is bound to its template ID; looking up a template also
authenticates the referenced snapshot and checks the returned template identity.
Inventory and stored-record counts describe advisory index availability. They do
not probe raw payload keys: LevelDB existence checks would read entire values.
An externally removed or changed payload is therefore discovered when it is
actually retrieved. A previously authenticated RAM copy remains usable; reoffers
force a read of its durable backing before treating storage as repaired.

`getsharepoolhashstatus` exposes startup instrumentation and the repair-required
flag. A ready restart has `fast_path=true`, `records_scanned=0`,
`bytes_scanned=0`, and `batches=0` in its archive startup statistics. These measure
the snapshot-index work only. LevelDB may recover its bounded write log and open
its tables, and the existing bounded local transaction, unfinished-template and
pending-block caches are read separately. Total startup time and RSS are not
promised constant regardless of the storage engine, disk, or those local caches.

Archive prefix traversals require exact 33-byte keys. A short or trailing-byte
key within the range is local corruption, not the end of that range. Rebuild
preserves evidence and refuses to mark an incomplete index ready; inventory
records repair-required and fails explicitly. Such underlying malformed keys
require a sound database restore rather than repeated automatic index repair.

## First migration and interrupted recovery

A previous r2 archive has no checkpoint. Its first startup durably records a
rebuild phase, clears disposable metadata/source indexes, and then authenticates
the existing raw snapshots. Existing raw evidence is not deleted. Migration also
recalculates the logical quota: the new checksummed source index requires a
224-byte allowance per decoded template occurrence, replacing 192 bytes.

Every rebuild batch commits its index changes, counters, phase and exclusive
cursor atomically. It processes at most 64 records, stopping when accumulated raw
bytes reach 16 MiB; one bounded snapshot can cross that threshold, so a batch of
valid payloads totals less than 32 MiB. The implementation retains one decoded
snapshot at a time plus bounded per-batch index updates. It never builds a RAM
map for all historical snapshots. Index clearing uses the same 64-record bound.

Shutdown is checked between committed batches. Graceful interruption, a process
crash or a quota failure leaves completed batches durable. The next start resumes
the saved phase and cursor, including when the explicit repair flag is no longer
present. At most the unfinished batch is repeated. If quota is exhausted, raise
the positive finite `-sharepoolarchivemib` value and restart. Do not delete the
database or its checkpoint to resume. Rebuild is startup maintenance; mining and
RPC service start after it completes.

## Repairing local damage

A malformed/unsupported checkpoint, a mismatched profile or rules hash, or a
persisted repair-required marker refuses ordinary startup. A valid checkpoint
for a different profile is never reinterpreted by the repair flag. Use the
original configuration or a separate store for another profile.

If a ready node discovers missing or damaged metadata, missing payload records,
or a damaged source index, it marks local repair required. Affected lookups return
unavailable evidence; they do not become consensus-invalid results. New archive
admissions wait for repair when accounting/index integrity is unknown. Already
authenticated unrelated evidence remains usable. Stop the node and restart with
its existing options plus:

```sh
-sharepoolarchiveindexrebuild=1
```

Remove that explicit flag after successful repair so future starts use the ready
checkpoint. Repair rebuilds metadata and source references from surviving
hash-authenticated records and removes stale index entries. It can recover an
older intact template source outside the four retained references. Records with
wrong content hashes are quarantined and still charged; verified network
reoffers or archive imports can replace them. Missing raw records must be
recovered from peers or backups. Hash-correct malformed snapshot encodings remain
available to consensus validation as evidence of invalidity.

The checkpoint and index checksums detect accidental local damage. They are not
signed roots, anti-rollback anchors, or proof that a chain's complete evidence is
available. An offline actor replacing a database consistently cannot be detected
by this local checkpoint alone. Ordinary startup intentionally does not scrub
every payload or discover unrelated out-of-band database edits. Explicit repair
does that full scan; native validation and offline backup verification must still
check every dependency required by the intended chain tip.

## Verification

The final native run passed 145 C++ cases, including all 32
[store/archive cases](../src/test/sharepool_hash_store_tests.cpp), and the native
archive scenario. Seven functional scenarios passed before the final malformed-key
fix; exact build provenance is in the [follow-up report](sharepool-capacity-startup-report.md).
Store coverage includes interrupted migration and repair,
quota failure/resumption, checkpoint/profile mismatches, source-index damage,
lazy payload quarantine and exact counter recovery. The 65,540-record unit fixture
uses small hash-addressed records to verify migration followed by a structurally
zero-scan restart; it is not a workload of validated mining snapshots.

The [native archive scenario](../test/functional/feature_sharepool_hash_archive.py)
checks 11 signed mining snapshots, direct payouts, archive recovery, explicit
index rebuilding, quota changes and chainstate reindexing. Its separate paging
phase reaches 1,041 stored records by adding 1,030 opaque transport fixtures;
those extra records establish pagination behavior, not mining validity. Normal
restart reports zero snapshot records/bytes scanned. These checks establish no
startup-millisecond guarantee or sustained multi-GiB archive benchmark.
