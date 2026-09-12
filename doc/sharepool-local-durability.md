# Local signer integrity and gate archives

These tools support the experimental, explicitly enabled native regtest profile.
They do not activate sharepool rules on a public network.

## Native job construction and deterministic carry

Use `gate.make_native(sign_owner=signer.sign_owner)` for a real native mempool
job. The gate proposes its deterministic settlement batch to
`preparesharepoolhashjob`; the node chooses valid mempool transactions, derives
fees, the canonical paid state and exact coinbase payouts, and returns the
unsigned job. Before calling the signer, the gate checks the returned policy,
tip, complete accounting bytes, payout amounts, normalized template hash and
exact signing payload. It then calls `finalizesharepoolhashjob` with the signed
snapshot and verifies that the finalized response contains that same job.

```python
block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
authorization = gate.authorize(block.serialize(), snapshot.serialize())
# Dispatch only while gate.ready_for_dispatch(authorization) is true.
```

Construction and finalization do not admit evidence or authorize mining. The
separate `authorize` call performs native validation and atomic local admission.
`make(ntime=..., fees=..., transactions=...)` remains an explicit Python fixture
helper; callers must not use its supplied fee/transaction values as a substitute
for native job construction.

The configured `snapshot_budget` defaults to the native 16 MiB limit and is
bound into the protected gate configuration. At a fixed tip and acknowledged
receipt revision, eligible unpaid receipts are ordered by origin height and then
numeric proof ID. The gate selects the largest prefix that fits the compact
snapshot, unique dependency bytes, origin count and graph-depth limits. A new
settlement reserves one additional dependency edge above its selected origins.
It includes exactly the full origin templates of the selected proofs. Unworked
issued templates stay archived locally and do not create mandatory refresh
chains. New acknowledged work or a tip change requires refresh; unrelated
unworked inventory and archive rotation do not invalidate frozen jobs.

Deferred receipts retain their exact evidence and receipt revision. Creating or
authorizing a job does not mark its work paid. `batch_status()` reports the next
selected IDs, eligible/deferred counts and resource use. `receipt_status()`
provides bounded revision pages and checks actual canonical block snapshots,
reporting `paid`, `selected`, `deferred`, `orphaned`, `expired_unpaid` or `unknown`.
Missing historical openings produce `unknown`, never a payment claim. A
reorganization can reactivate retained work if its native ancestry and age are
eligible again.

The native three-block age rule remains unchanged. Local durability does not
make an expired deferred receipt payable: accepting unlimited future work on old
templates would not prove when that work was performed. Guaranteed indefinite
carry therefore remains an unresolved protocol requirement; it needs an
authenticated pending-credit checkpoint, data availability and spent-credit
tracking before the existing age cutoff. These local changes do not claim that
mainnet requirement is solved.

## Checksummed signer records

New `bitcoin-sharepool-signer init` files use `SPKEY002`: eight magic/version
bytes, the canonical public signing policy, the 32-byte private scalar, and a
32-byte SHA256 checksum. The checksum covers
`"SharePool/signer-key/v2\0" || magic || policy || scalar`. Validation precedes
public-key output and signing. File ownership, mode 0600, regular-file,
single-link, no-follow and macOS ACL checks still apply.

This checksum detects accidental corruption. It is not encryption or an
authentication mechanism against someone who can replace both a private key
and its checksum. The independently configured public key and signing policy
remain the identity reference.

Legacy `SPKEY001` files require explicit migration:

```text
bitcoin-sharepool-signer migrate LEGACY_KEYFILE NEW_KEYFILE
```

Send the canonical previously trusted public policy followed by the 32-byte
x-only public key as one hexadecimal line on stdin. The signer refuses a
different policy or identity, retains the original file,
and creates the destination exclusively with the same key and policy. It never
overwrites a key or silently converts an existing file. Obtain the expected
public key from the owner's existing trusted configuration, not a new reading
of a potentially corrupted legacy record.

The Python adapter exposes the same operation as
`NativeSigner.migrate(..., expected_public_key=..., pool=..., payout_script=...)`.
Private file bytes remain inside the native signer process.

## Streaming evidence backups

The gate journal records canonical snapshots, complete origin templates and
acknowledged proofs. Its hash chain is useful only relative to a trusted final
checkpoint. Keep the protected checkpoint independently of exported data.
Restoring a database and an older checkpoint together cannot establish that
later acknowledgments never existed.

```python
first_head = gate.export_archive("segment-001.spharc")
# Continue admitting work normally.
final_head = gate.export_archive("segment-002.spharc", since=first_head)

restored = HashMiningGate.restore_archive(
    ["segment-001.spharc", "segment-002.spharc"],
    "restored.sqlite", trusted_head=final_head,
    rpc=rpc, pool=pool, public_key=public_key, payout_script=payout_script,
)
```

Each immutable segment declares its start and end checkpoints and contains
contiguous, bounded journal records. The exporter writes and fsyncs a private
temporary file before exclusively publishing its final name. Incremental
exports retain earlier evidence; keep every segment needed to reconstruct the
chain. Existing export or restore destinations are never overwritten.

Restore reads at most one bounded event body at a time. It verifies canonical
headers, every event hash, sequence and receipt revision, the exact trusted
endpoint, and complete origin/snapshot bindings. It imports into a private
staging database, restores native snapshot data, and revalidates eligible
templates and proofs against the current native branch before publishing the
database and protected checkpoint. Missing native data or failed validation
leaves the destination unpublished; native content storage may retain supplied
snapshot data and applies its own resource limits.

`gate.revalidate_active()` performs the same native branch reconciliation on an
existing gate. It reports retained receipts, eligible templates/proofs and unpaid
proof IDs. Paid, expired and orphaned evidence is retained. If a reorganization
makes retained work eligible again, its original receipt sequence is preserved.

## Resident quota and cold history

Gate schema 2 keeps lifetime event metadata in SQLite while allowing old bodies
to reside in immutable archive segments. It has no one-million-event or 4 GiB
lifetime cutoff. Counters are checked signed 64-bit integers; disk capacity is
still finite. The configured quota limits resident bodies and their logical
record overhead, rather than all previously acknowledged work. SQLite metadata,
WAL files, staging space and cold archive storage require additional disk space.

Pass an explicit `archive_directory` when opening a gate to enable automatic
rollover before a new batch would exceed its resident quota. The directory must
be an owned private directory; a missing directory is created with mode 0700.
Without this option, quota exhaustion refuses admission before acknowledgment.
A single offered batch larger than the resident quota is also refused.

`gate.rotate_archive(path)` performs a manual rollover. It writes, fsyncs and
verifies the complete next segment before a SQLite transaction replaces resident
body copies with segment/offset references. It retains every event's identity,
hash, receipt revision and native origin metadata. The protected hash-chain head
does not change, so rotating history does not invalidate an otherwise current
frozen mining authorization. `gate.resident_bytes()` reports the current logical
resident use.

Cold reads check the immutable segment header, exact record metadata and body
hash against the retained journal. Restart validates the whole retained chain;
missing or altered cold files fail closed. Never delete or edit a referenced
segment. Full exports transparently stream both resident and cold evidence.
Restore can use a caller-selected `archive_directory` to reconstruct a history
larger than its resident quota; incoming export files cannot choose local output
paths. An interrupted or refused restore can leave verified prefix segments in
that explicitly selected archive directory, but never publishes a partially
validated destination database.

## Native standalone template recovery

The native template cache stores transaction bytes once per witness transaction
ID and stores each template's normalized header, ordered transaction references
and exact body checksum in the same durable database batch. On startup, bounded
damaged local template or transaction records are quarantined rather than
advertised as available. Quarantined bytes still consume local quota; unreadable
records conservatively retain their serialized storage size in that accounting.

A damaged standalone record does not hide an independently hash-verified full
template in an indexed snapshot. That fallback supplies evidence for native
validation; it does not authorize work or silently rewrite the damaged record.
A subsequent fully validated template reoffer atomically replaces its exact
record and any damaged referenced transactions, then updates cache and quota
accounting after the durable batch succeeds. Shared transaction references can
become readable again once their common transaction has been repaired.

This handles bounded content damage in the native standalone template and
transaction records. It does not repair LevelDB structural corruption, missing
database files, damaged snapshot or pending-block records detected at startup,
or exhausted local quota. Those remain explicit local availability/restore
conditions, never evidence that a consensus-valid block is invalid.
