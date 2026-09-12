# Hash-only settlement test profile, version 2

This separately enabled regtest profile places the flat hash of a complete
canonical settlement snapshot in the native header's `m_mm_rhs` field. The
snapshot contains full normalized origin templates, submitted proofs, the next
paid state and exact monetary payouts. Snapshot bytes travel and persist outside
the Bitcoin block. Coinbase contains the actual payouts and, where applicable,
the ordinary Bitcoin witness commitment; it contains no settlement carriers.

The profile is an implementation for testing. Mainnet remains disabled. The
version 1 self-contained profile and its durable gate remain separate.

## Native activation and interfaces

Use a fresh disposable regtest data directory with these options:

```
bitcoind -regtest -datadir=/path/to/fresh/test-directory \
  -testactivationheight=blake2b@1 -sharepoolheight=1 -sharepoolhashonly=1
```

Public networks reject this override. Without `-sharepoolhashonly=1`, an
explicit `-sharepoolheight` continues to select the separate version 1 profile.
Changing the profile of an existing chain is not a migration procedure.

- `submitsharepoolhashsnapshot(hex)` durably stores a bounded preimage and retries
  pending blocks. Its `stored`/`present` result does not certify validity.
- `getsharepoolhashsnapshot(hash)` returns complete bytes; `getsharepoolhashstatus`
  reports the active profile, available objects and pending-block count.
- `validatesharepoolhashtemplate(hex)` checks the full native template, required
  snapshots, exact payouts and actual fees without requiring candidate PoW.
- `validatesharepoolhashshare(hex)` checks proof work, authorization, eligible
  native ancestry and the complete locally available origin evidence.

Validation RPCs return error `-25` with `sharepool-hash-data-missing` for missing
dependencies and `-26` for invalid evidence. `submitblock` returns
`sharepool-hash-data-missing` while retaining a bounded pending block for retry.

Peers negotiate `sphhello` on their existing Bitcoin connections, advertise
rotating pages through `sphinv`, and exchange bounded `sphget`/`sphdata` chunks.
Local snapshot storage retains up to 1 GiB and 65,536 objects; separately stored
validated template bodies are bounded to 256 MiB and 65,536 objects. The pending
queue holds at most 16 blocks and 64 MiB. These are local resource limits, not
proof that an unavailable committed snapshot violates consensus.

## Canonical bytes and commitment

Use Bitcoin serialization with canonical CompactSize lengths. Integers are
little-endian; hashes use native uint256 serialization. H is double SHA256.
Domain strings include their terminating NUL.

The rules commitment is:

```
H("SharePool/rules/v2\0" ||
  uint32(0x207fffff) || uint32(3) || uint32(16*1024*1024) ||
  uint32(4_000_000) || uint32(64) || uint32(64*1024*1024))
```

These fields specify the fixed approved share target, maximum age, snapshot
bytes, individual template bytes, dependency depth, and unique dependency bytes.
There is no independent 32-share snapshot ceiling. Consensus byte and dependency
budgets remain necessary, and the actual payout outputs still consume block
space. Removing a proof-count limit does not make resources unlimited.

The complete snapshot serializes, in order:

1. A version 2 envelope using the original envelope layout: genesis, rules,
   height, native parent, nonzero pool ID, x-only owner public key and payout
   script. All three former root fields are reserved and must be zero.
2. The fixed 64-byte owner authorization.
3. A vector of template records, each containing its uint256 normalized
   template ID and a byte vector of the full normalized native block body.
4. A vector of shares, each containing its full native header, version 2 origin
   envelope and fixed 64-byte owner authorization.
5. A vector of post-state entries: uint32 origin height and uint256 proof ID.
6. A vector of actual monetary `CTxOut` payouts.

Template records are unique and sorted by their serialized uint256 ID bytes.
Proofs and paid-state entries are unique and sorted by numeric proof ID.
Payouts are unique and sorted by script bytes. Scripts are compared as exact
bytes, not address strings. Reject trailing bytes and noncanonical encodings.
Decoders bound counts by bytes remaining before allocating or looping.

```
m_mm_rhs = H("SharePool/snapshot/v2\0" || complete_snapshot_bytes)
```

This is one flat digest of all those bytes. It does not construct a settlement
Merkle tree. The ordinary Bitcoin transaction Merkle root is still required by
Bitcoin block validation.

Owner signatures use the separate domain `SharePool/owner/v2\0` over genesis,
rules, height, native parent, pool, owner public key and vector-encoded payout
script. The `HashSigner` adapter uses the native private-key signer and verifies
its returned signature without reading the private key file.

Template normalization sets `nNonce`, `m_nonce2`, `m_nonce3`, `m_extranonce`, and
`m_time_offset` to zero. Its ID uses the existing normalized-header SHA256 ID;
the displayed SHA256 digest maps to the native uint256 RPC display convention.
The record retains every transaction byte. Full native validation must still
verify the body's transaction, UTXO, script, fee and witness context.

## Dependency and availability rules

Only already issued origin jobs can enter a snapshot. The containing winning
job and its winning proof cannot be placed inside their own hash preimage.
Each share's header commits to its full origin snapshot; supplying only an
origin envelope cannot establish attribution. Validators need the corresponding
snapshot dependencies and complete origin bodies. Shared dependencies are
deduplicated, and the depth and byte limits are consensus rules.

Paid state derives from the authenticated snapshot of the actual native parent.
It remains global across pools. Native validation checks ancestry, proof work,
owner binding, eligibility, duplicate/replayed proofs, state transition and
every actual coinbase amount/script using the block's validated fees. A proof
from origin height j remains eligible through j+3, and expires at j+4.

Snapshot storage is not mining approval. In particular,
`submitsharepoolhashsnapshot` returning `stored` or `present` only acknowledges
bounded content-addressed storage; canonical encoding, dependencies and the
containing block may still fail validation. Hash-matching malformed bytes remain
available so validators can establish invalidity instead of waiting forever.
Missing snapshot data leaves a block pending. A timeout,
peer refusal or local disk quota cannot make it permanently consensus-invalid.
Bytes with the wrong hash are a bad response, not proof that the block itself
is invalid. Nodes must retain and serve historical snapshots for reindex and
reorg validation.

The new P2P path exchanges full snapshot objects over existing Bitcoin peers.
Live proof publication can use a new signed candidate snapshot containing the
already issued full origin and proof. Publish the origin's snapshot dependency
first. The version 1 raw-template/raw-share relay does not implement this format.

Replication reduces the risk of missing data but cannot guarantee continuing
availability. Neither a flat digest nor a coordinator's inventory proves that
all miners disclosed their work or that every peer can fetch it.

## Local durable mining gate

`contrib/sharepool/hash_mining_gate.py` uses a separate SQLite journal and
protected checkpoint. Its `HashMiningGate` binds the exact regtest profile,
pool, public key and payout script. It performs native full-template validation
before template admission or mining authorization, and again for each origin
before proof admission. The separate native proof RPC authenticates work and
attribution. Snapshot inventory never authorizes hash power.

Before authorizing a new current-tip job, the gate imports and validates its
templates and proofs. The selected snapshot must include every locally known,
currently eligible unpaid proof and every known eligible template, excluding
the containing job itself. Newly supplied evidence receives the same validation
as separately received evidence. Another miner's different receipt history does
not alter native block validity.

The return value freezes the complete job, snapshot and durable journal
sequence. Check `ready_for_dispatch()` immediately before dispatch and watch
`needs_refresh()` while hashing. New evidence or a changed tip calls for a new
job. Already solved commitments cannot be rewritten. Later work and the winning
proof can only enter later eligible snapshots.

The journal stores full snapshot, normalized template and proof bytes as a
contiguous append-only hash chain. Each proof increments a monotonic receipt
revision; pruning never resets it because this initial version 2 gate does not
prune journal evidence. SQLite WAL/FULL commits precede an atomically written,
fsynced protected checkpoint and any positive acknowledgement. A crash after
the database commit but before checkpoint completion returns no acknowledgement;
startup verifies the full extension and conservatively preserves that work.

The default logical journal quota is 512 MiB, configurable from 4096 bytes to
4 GiB, with at most one million events. It counts encoded records, not all disk
use. SQLite indexes, WAL, backups and filesystem overhead need additional disk
space. Quota exhaustion refuses new admission before acknowledging it; it never
evicts known work. This initial gate's finite, unpruned journal is a deployment
limit, not an indefinite retention service.

Startup verifies schema, policy, bounded row lengths/counts, data hashes, event
sequence/linkage, every retained proof's full origin, and the protected
high-water. Every evidence read checks its bytes. Lifetime locks prevent two
gate writers. Missing or unsafe checkpoint files, corruption, a stale database,
and incompatible version 1 databases fail closed. RPC requests occur outside
write transactions. Different native branches filter eligibility from actual
ancestor hashes; retained old evidence is never silently lost.

Keep the checkpoint independently protected and backed up. Restoring both the
database and checkpoint to the same old state cannot be detected using those
two files alone. The version 1 export/recovery API is not compatible with this
new journal; an independently verified streaming export/import workflow for the
version 2 journal is still required before operational deployment.

## Python integration

`hash_snapshot.candidate(...)` returns `(block, snapshot)`. Supply the previous
authenticated `parent_snapshot`, all required `templates`, selected `shares`,
and either an explicit functional-test secret or `public_key` plus `sign_owner`.
`snapshot.serialize()`, `snapshot.hash`, and `snapshot.hash_hex` expose the exact
wire bytes and commitment. Fixture signing helpers are for tests.

The gate exposes `register_snapshot(raw)`, `register_template(raw)`,
`receive(share)`, `active_templates()`, `eligible_shares()`,
`make(ntime=..., sign_owner=...)`, and
`authorize(block_raw, snapshot_raw=None)`. All native dependencies must be
available before template/proof validation. The caller manages native P2P
snapshot publication and imports fetched template/proof records through the
gate; merely storing a peer snapshot does not acknowledge its individual work.

Deterministic Python tests cover a 100-proof snapshot and 100 durable
acknowledgements, restart and omission policy, full template coverage, malformed
canonical data, missing-dependency refusal, frozen jobs, tip races, quota
rollback, corruption, stale backups and checkpoint failure. These tests use RPC
doubles for gate behavior. Real native integration tests provide separate
consensus/P2P evidence; neither set establishes production readiness.
