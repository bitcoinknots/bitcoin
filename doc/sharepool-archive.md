# Hash-only snapshot archive operations

The archive retains full snapshot preimages outside blocks. Blocks still contain
only their selected-profile snapshot hash. Storing or importing an authenticated
preimage is not a consensus approval or a mining acknowledgement.

This implementation is restricted to the explicit regtest hash-only profiles.
The archival changes do not change consensus hashes. The separate TIDES v6
admission-cohort rule revision does change its rules hash and requires a fresh
regtest chain; an archive cannot migrate an old chain into the revised rules.

## Capacity and memory

`-sharepoolarchivemib=1024` is the default positive, finite local quota. Increase
it explicitly when provisioning more disk. The quota charges the snapshot's raw
bytes plus 128 bytes per record and 224 bytes per decoded template for keys and
source-index overhead. The template allowance conservatively covers a complete
four-source index record even when snapshots share existing records. There is no fixed
snapshot-count ceiling. `getsharepoolhashstatus` reports raw retained bytes,
`archive_charged_bytes`, and `archive_max_bytes` separately.

Provision additional physical free space for LevelDB indexes, write logs,
compaction, archive exports, and the ordinary block database. The quota is not a
filesystem-space guarantee. Exhaustion leaves dependent blocks pending and
preserves previously stored evidence. Raising the quota and restarting permits
recovery to continue. Lowering it below retained charged bytes refuses startup.

Snapshot and template-source indexes reside in LevelDB. Snapshot RAM caching is
bounded by both 64 MiB and 4,096 objects; inventory pages scan at most 1,024 keys.
The deduplicated local job cache remains bounded. In v6, a template already
contained in a durable snapshot can release its duplicate local record, and
shared transactions are released only after their remaining local references
are gone. Unarchived jobs still consume the bounded local cache.

Ordinary startup loads a versioned, checksummed accounting checkpoint bound to
the selected profile and rules hash. It reads no historical snapshot payloads.
Snapshot bytes, metadata, template-source indexes and counters are committed in
one synchronous LevelDB batch. Bounded unfinished jobs and pending block bodies
still require their own startup reads; opening and recovering LevelDB's write log
also costs I/O. This removes the full archive scan from normal restarts, not all
startup work.

The first start of a previous r2 archive migrates its disposable indexes once.
Migration and explicit repair authenticate the retained payloads in bounded,
durably checkpointed batches. Their total time still grows with retained history;
interruption resumes from the last committed cursor. A quota increase can resume
a stopped migration. See [startup and repair](sharepool-archive-startup.md).

Retrieval authenticates every uncached payload against its requested hash.
Corrupt preimages are quarantined, remain charged, and can be replaced by verified
reoffers. Damaged or missing metadata/source indexes require explicit repair with
`-sharepoolarchiveindexrebuild=1`; missing or damaged records remain unavailable.
The local checkpoint does not establish consensus validity or archive completeness.
Neither corruption nor quota exhaustion makes a block invalid.

## Inspect and export

Use an existing node running the intended profile and activation schedule.

```sh
bitcoin-cli -regtest -named getsharepoolhashstatus count=128
bitcoin-cli -regtest -named exportsharepoolhasharchive filename=/absolute/backup/chunk-0001.spha max_records=128 max_bytes=33554432
```

Each export creates a new absolute filename exclusively. POSIX files are created
private and set to mode 0600 through their descriptor; Windows uses the destination
directory ACL. Export checks file sync and close, then checks the POSIX directory
sync. `directory_synced` reports that final guarantee; it is false for imports and
on Windows, where this directory-fsync guarantee is unavailable. Existing files
are not overwritten. Imports require regular files; FIFOs and devices are refused
before parsing. A failed export may leave an incomplete new file. The default RPC chunk limits are 128 records and 32 MiB of raw
snapshot payload; the hard per-call limits are 1,024 records and 256 MiB. Each
individual record also retains the normal 16 MiB snapshot bound.

File I/O and archive transcript hashing run outside the main chain mutex.
Individual bounded inventory pages, snapshot reads, and durable record admissions
take their own lock scopes; a complete chunk does not monopolize chain validation.

Record the returned `next_after` and use it as the next call's `after` value,
with a new filename. Continue until `inventory_complete` is true. If a byte
budget cannot fit the next snapshot, increase that call's byte budget within the
hard limit. Inventory inspection similarly returns `inventory_next`,
`inventory_complete`, and `inventory_revision`.

The cursor uses the store's serialized-hash ordering, not block height. It is
exclusive and should be treated as opaque. A page may contain no available
hashes while advancing over quarantined records. An active node may also receive
new records before a cursor already visited. Consequently, a completed traversal
does **not** prove that a backup contains all evidence required by a chain tip.
Record the source tip, repeat exports as needed, and verify recovery against that
tip independently.

## Import and verify recovery

Keep the original archive files until recovery is verified. Import into a node
configured for the same snapshot profile and consensus rules:

```sh
bitcoin-cli -regtest -named importsharepoolhasharchive filename=/absolute/backup/chunk-0001.spha max_records=128 max_bytes=33554432
```

Repeat for each chunk. The format binds its selected hash profile, ordered unique
record hashes, payload lengths, counts, cursors and footer checksum. Each payload
is individually hashed before durable admission; malformed but hash-correct
committed preimages remain available as evidence of invalidity. A wrong profile,
corrupt payload, truncated footer, trailing bytes or exceeded resource budget
fails the call.

Import is incremental: records verified before a later failure remain durable.
Re-importing a correct chunk is safe and checks the durable backing even when a
sound RAM copy exists. If a call fails because of local quota or storage failure,
resolve capacity or storage first and retry the complete chunk. Do not discard a
chunk because some earlier records were accepted.

The footer checksum detects damage; it does not establish that the file came
from a trusted node, includes every historical snapshot, or settles any miner's
work. `inventory_complete` only describes the exporter's local traversal.

Use a disposable recovery node with the intended native block history to test
the backup, including restart and full reindex. Disable networking during this
verification so peers cannot silently fill backup gaps. Require successful
native validation through the recorded tip and `verifychain 4 0`; missing
snapshot dependencies must be recovered before considering the backup complete.
Follow the existing profile-directory guard: do not overwrite a profile marker,
change its pinned paths, or reuse an old v6 chain to bypass a rules change.

These chunks contain snapshot preimages. They are not backups of native block
files, pending block bodies, unfinished local jobs, signer keys, gate journals,
wallets or miner connection configuration. Those have separate durability and
recovery requirements.
