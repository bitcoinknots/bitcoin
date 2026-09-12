# Hash-only settlement test profile, version 4

The optional [v5 confirmed-work ledger](sharepool-confirmed-ledger.md) adds a
native-parent payout cutoff while preserving the v4 profile described here.

This separately enabled regtest profile places the flat hash of a complete
canonical settlement snapshot in the native header's `m_mm_rhs` field. The
snapshot contains full normalized origin templates, submitted proofs, the next
paid state and exact monetary payouts. Snapshot bytes travel and persist outside
the Bitcoin block. Coinbase contains the actual payouts and, where applicable,
the ordinary Bitcoin witness commitment; it contains no settlement carriers.

The profile is an implementation for testing. Mainnet remains disabled. The
version 1 self-contained profile and its durable gate remain separate. Version 4
changes the transaction representation and rule hash from v3; start a
fresh chain. Native snapshots use a separate `sharepool-snapshots-v4` database.

## Native activation and interfaces

Use a fresh disposable regtest data directory with these options:

```
bitcoind -regtest -datadir=/path/to/fresh/test-directory \
  -testactivationheight=blake2b@1 -sharepoolheight=1 -sharepoolhashonly=1
```

Public networks reject this override. Without `-sharepoolhashonly=1`, an
explicit `-sharepoolheight` continues to select the separate version 1 profile.
Changing the profile of an existing chain is not a migration procedure.

- `preparesharepoolhashjob(unsigned_snapshot)` uses the native mempool to construct
  the complete job, derive paid state, calculate exact fees and reserve payout
  space. It validates the unsigned job and all signed dependencies before
  returning the exact statement for the external signer.
- `finalizesharepoolhashjob(template, signed_snapshot)` inserts the signed flat
  commitment and validates the complete current-tip job. Neither builder RPC
  admits evidence or authorizes mining; the durable gate must still approve it.
- `submitsharepoolhashsnapshot(hex)` durably stores a bounded preimage and signals
  the dedicated worker to retry pending blocks. Its `stored`/`present` result does not certify validity.
- `getsharepoolhashsnapshot(hash)` returns complete bytes; `getsharepoolhashstatus`
  reports the active profile, available objects and pending-block count.
- `validatesharepoolhashtemplate(hex, snapshot_hex, mining=true)` checks the full native
  template, required snapshots, exact payouts and actual fees without candidate
  PoW; physical search fields are normalized before checking the underlying
  job. The optional snapshot is an in-memory overlay; this form does not admit
  snapshot or template evidence. Dependencies must already be available. Without
  the overlay, a successful call remembers the validated template. New jobs
  reserve one future origin/depth slot; `mining=false` restores historical
  evidence without claiming it is suitable for newly dispatched work.
- `validatesharepoolhashshare(hex)` checks proof work, authorization, eligible
  native ancestry and the complete locally available origin evidence.

Validation RPCs return error `-25` with `sharepool-hash-data-missing` for missing
dependencies and `-26` for invalid evidence. `submitblock` returns
`sharepool-hash-data-missing` while retaining a bounded pending block for retry.

Peers negotiate `sphhello` on their existing Bitcoin connections, advertise
changed inventory pages through `sphinv`, and exchange bounded `sphget`/`sphdata`
chunks. Inventory replays after a completed cycle plus 60 seconds so bounded
queues can recover dropped advertisements; it does not repeat unchanged pages
every second. Existing peer iteration is randomized. FIFO turns additionally
bound overtaking among continuously ready connections in each priority class.
Required block data starts first. When both classes stay ready, three required
turns are followed by an ordinary turn. Dependency requirements belong to tracked
pending blocks; unauthenticated hints cannot consume their reserved slots.
Fairness is per connection, not per operator.
Requests expire even when send buffers are paused.
Local snapshot storage retains up to 1 GiB and 65,536 objects; separately stored
validated templates use shared Wtxid-keyed transaction storage, bounded to
256 MiB of encoded transactions/references, 65,536 template records and 262,144
transaction records. The 64 MiB transaction cache also accounts serialized bytes,
not complete allocator/RSS cost. The pending
queue holds at most 16 blocks and 64 MiB. These are local resource limits, not
proof that an unavailable committed snapshot violates consensus.

## Canonical bytes and commitment

Use Bitcoin serialization with canonical CompactSize lengths. Integers are
little-endian; hashes use native uint256 serialization. H is double SHA256.
Domain strings include their terminating NUL.

The rules commitment is:

```
H("SharePool/rules/v4\0" ||
  uint32(0x207fffff) || uint32(10) || uint32(3) || uint32(16*1024*1024) ||
  uint32(4_000_000) || uint32(64) || uint32(64*1024*1024) ||
  uint32(512*1024*1024) || uint32(2_000_000) || uint32(2048))
```

These fields specify the maximum share target, target scaling shift, maximum
age, snapshot bytes, individual template bytes, dependency depth, and unique
dependency bytes, summed expanded template bytes, transaction references and
unique origin validations per walk. Each proof's target is derived from its contextual native
header difficulty; a miner cannot select an easier target independently:

```
share_target = min(native_target * 1024, DecodeCompact(0x207fffff))
credited_work = floor(2^256 / (share_target + 1))
```

Malformed or noncanonical compact targets fail. Origin validation also requires
`nBits` to equal Bitcoin's expected target for that native ancestor. Exact integer
work is aggregated by payout script across templates and origin difficulties.
Largest remainders allocate the whole subsidy plus fees; ties use script bytes.
Equal-target proofs still receive equal weight. Multiprecision arithmetic avoids
loss or overflow when weights span different difficulties.

The factor 1024 is an experimental rule, not a measured production setting. It
roughly targets 1024 shares per network block at an unclamped difficulty; a small
pool receives only its fraction of that rate. Operational share rates, variance,
validation cost and admission policy need calibration before deployment. Regtest
hits the easy-target clamp and does not benchmark production hashing.
Matching a regular pool also requires a comparable miner share rate and payout
window. The current one-time payment and network-height expiry are not a
rolling PPLNS/TIDES window; see [the comparison](sharepool-difficulty-capacity.md).
There is no independent 32-share snapshot ceiling. Consensus byte and dependency
budgets remain necessary, and the actual payout outputs still consume block
space. Removing a proof-count limit does not make resources unlimited.

The complete snapshot serializes, in order:

1. A version 4 envelope using the original envelope layout: genesis, rules,
   height, native parent, nonzero pool ID, x-only owner public key and payout
   script. All three former root fields are reserved and must be zero.
2. The fixed 64-byte owner authorization.
3. A uint256 exact-job commitment.
4. A vector of unique full transaction byte vectors, including witness, ordered
   strictly by serialized Wtxid bytes.
5. A vector of template records: uint256 normalized ID, complete normalized
   native header, and CompactSize indexes into the transaction table in that
   template's exact transaction order.
6. A vector of shares, each containing its full native header, version 4 origin
   envelope and fixed 64-byte owner authorization.
7. A vector of post-state entries: uint32 origin height and uint256 proof ID.
8. A vector of actual monetary `CTxOut` payouts.

Template records are unique and sorted by their serialized uint256 ID bytes.
Proofs and paid-state entries are unique and sorted by numeric proof ID.
Payouts are unique and sorted by script bytes. Scripts are compared as exact
bytes, not address strings. Reject trailing bytes and noncanonical encodings.
Decoders bound counts by bytes remaining before allocating or looping. Every
table entry must be referenced. Out-of-range indexes, duplicate/unsorted Wtxids,
unused transactions and expanded resource overflows are rejected. Each expanded
body must have the claimed transaction count, template ID and ordinary native
transaction root. Different witness bytes are distinct table entries even when
their txids agree. C++ templates share immutable transaction references; the
Python codec shares immutable serialized transaction bytes. This saves repeated
transaction bodies without changing what the flat commitment attests.

```
m_mm_rhs = H("SharePool/snapshot/v4\0" || complete_snapshot_bytes)
```

This is one flat digest of all those bytes. It does not construct a settlement
Merkle tree. The ordinary Bitcoin transaction Merkle root is still required by
Bitcoin block validation.

The signature binds both the exact job and every snapshot field:

```
job = H("SharePool/job/v4\0" || full_normalized_block_with_m_mm_rhs_zero)
contents = H("SharePool/contents/v4\0" || snapshot_with_64_zero_signature_bytes)
message = H("SharePool/owner/v4\0" || envelope || job || contents)
```

The snapshot includes `job` before calculating `contents`. The owner signs
`message`; the final signed snapshot hash becomes `m_mm_rhs`. Clearing only the
commitment field and physical search fields prevents a signature/hash fixed
point. Coinbase, transactions, witness bytes, time, difficulty and remaining
header fields are attested. Changing them or the snapshot requires a new
signature. Changing a permitted nonce/search field does not. This authenticates
the owner's job; it does not prove that the owner independently chose its
transaction set or disclosed all work.

The `HashSigner` adapter sends a bounded statement (envelope, job and contents)
to the native `sign-job` command, checks the returned signature, and never reads
private key bytes. The signer enforces its regtest/pool/key/payout policy; the
caller remains responsible for checking the statement against the actual job
and native validation. Legacy `sign` cannot authorize the new profile.

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

Before authorizing a new current-tip job, the gate stages and validates offered
templates and proofs without admitting them. It selects a bounded prefix of
eligible unpaid acknowledged work in `(origin height, numeric proof ID)` order.
The snapshot contains the complete origins of those selected proofs. Unworked
issued templates remain archived but are not mandatory settlement records.
Different receipt histories affect local mining choices, never block consensus.
Deferred receipts remain durable; actual canonical settlement determines payment.
Missing historical data is reported as unknown, never as proof of payment.
Failed checks, omitted selected work, tip races or storage refusals leave the
journal and evidence revision unchanged. Explicitly announce an accepted
snapshot with `register_snapshot()`; authorization uses a read-only native overlay.

The return value freezes the complete job, snapshot and durable journal
sequence. Check `ready_for_dispatch()` immediately before dispatch and watch
`needs_refresh()` while hashing. New evidence or a changed tip calls for a new
job. Already solved commitments cannot be rewritten. Later work and the winning
proof can only enter later eligible snapshots.

The journal stores full snapshot, normalized template and proof bytes as a
contiguous append-only hash chain. Each proof increments a monotonic receipt
revision; moving old bodies to immutable archive segments never resets it. SQLite WAL/FULL commits precede an atomically written,
fsynced protected checkpoint and any positive acknowledgement. A crash after
the database commit but before checkpoint completion returns no acknowledgement;
startup verifies the full extension and conservatively preserves that work.

The resident journal quota is configurable. With an explicit archive directory,
old bodies can be rotated into verified immutable segments before new admission.
The journal retains their hash, sequence, receipt revision and segment location;
reads verify the external frame and body. Rollover fsyncs the segment before an
atomic database switch. Missing/corrupt cold data fails closed. Lifetime counters
are bounded uint63 values, separate from resident quotas. Physical disk, SQLite
metadata growth and startup history verification remain operational costs.
Without configured cold storage, exhaustion refuses new work before ACK.

Startup verifies schema, policy, bounded row lengths/counts, data hashes, event
sequence/linkage, every retained proof's full origin, and the protected
high-water. Every evidence read checks its bytes. Lifetime locks prevent two
gate writers. Missing or unsafe checkpoint files, corruption, a stale database,
and incompatible version 1 databases fail closed. RPC requests occur outside
write transactions. Different native branches filter eligibility from actual
ancestor hashes; retained old evidence is never silently lost.

Keep the checkpoint independently protected and backed up. Restoring both the
database and checkpoint to the same old state cannot be detected using those
two files alone. The separate hash-gate streaming archive supports full/incremental exports and
restore into a fresh destination, with trusted checkpoint verification and native
branch revalidation before publication. It does not reuse the version 1 format.
See [local durability](sharepool-local-durability.md) for the checksum-protected
signer key format, explicit migration, archive and recovery boundaries.

## Python integration

`hash_snapshot.candidate(...)` returns `(block, snapshot)`. Supply the previous
authenticated `parent_snapshot`, all required `templates`, selected `shares`,
and either an explicit functional-test secret or `public_key` plus `sign_owner`.
`snapshot.serialize()`, `snapshot.hash`, and `snapshot.hash_hex` expose the exact
wire bytes and commitment. Fixture signing helpers are for tests.

The gate exposes `register_snapshot(raw)`, `register_template(raw)`,
`receive(share)`, `active_templates()`, `eligible_shares()`,
`make_native(sign_owner=...)`, and
`authorize(block_raw, snapshot_raw=None)`. All native dependencies must be
available before template/proof validation. The caller manages native P2P
snapshot publication and imports fetched template/proof records through the
gate; merely storing a peer snapshot does not acknowledge its individual work.

Deterministic Python tests cover a 100-proof snapshot and 100 durable
acknowledgements, restart and omission policy, complete selected-proof origin coverage, malformed
canonical data, missing-dependency refusal, frozen jobs, tip races, quota
rollback, corruption, stale backups and checkpoint failure. These tests use RPC
doubles for gate behavior. Real native integration tests provide separate
consensus/P2P evidence; neither set establishes production readiness.

## Scheduling and remaining production work

Pending-block retry has a dedicated lifecycle worker with a coalesced notification
and bounded duty cycle. Native scripts execute outside `cs_main` after their coin
context is captured; a changed tip invalidates speculative results. During worker
and RPC preparation, immutable snapshot decoding, hashing and signature checks
also run outside the global lock. Initial P2P acceptance still checks its first
snapshot graph under `cs_main` and the message-processing mutex before it defers
uncached origins. Cold database reads and synchronous writes, native coins-view
preparation, and ordinary native block connection still use `cs_main`. Final
acceptance uses an authenticated complete-body result and checks actual reward
again.
Unpublished overlays and unsigned jobs never populate that settlement-success
cache. A per-session origin map and LRU reward cache prevent repeated work from
ordinary eviction. Controlled historical/reindex paths may still validate
synchronously; worker telemetry exposes those fallbacks. This is not a hard
latency guarantee on arbitrary hardware or deep reorganizations.

Only an explicitly enabled regtest `-sharepoolhashonly` profile raises the HTTP
request-body ceiling to 48 MiB. This fits a maximum 16 MiB snapshot plus a
4,000,000-byte template encoded as hexadecimal JSON. RPC field, snapshot and
native block bounds still apply independently. Ordinary nodes and public
networks retain the existing 32 MiB HTTP ceiling; P2P limits are unchanged.

Carry-forward currently preserves receipts and selects later batches only while
the proofs remain eligible under the existing j through j+3 rule. At j+4 an
unsettled receipt is explicitly `expired_unpaid`, not deleted or marked paid.
Guaranteed indefinite carry needs an authenticated pending-credit checkpoint
before expiry and reorg-safe spent-credit accounting. Simply accepting arbitrarily
old headers would allow new work on obsolete, easier jobs. That protocol design
is unresolved; the current batch API must not promise eventual payment.

Native retained snapshot/template quotas, historical native evidence archival,
production difficulty/variance calibration, adversarial WAN load, and an
activation/data-availability policy remain deployment blockers. Full snapshots
must stay retrievable; neither a flat hash nor a signature forces a withholding
coordinator to provide bytes. No public network activation is provided. The
[production gap register](sharepool-production-gaps.md) tracks these limits.
