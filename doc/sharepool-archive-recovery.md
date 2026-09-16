# Recovering acknowledged SharePool work

This guide covers the experimental, regtest-only native mining gate. Its archive
preserves the full origin templates and proof bytes the gate has acknowledged,
including work that has expired or was paid on a chain that later reorganizes.
Recovery preserves the miner's local inclusion policy. It does not establish
that a peer disclosed every share, change Bitcoin block validity, or activate
SharePool on a public network.

The implementation is in
[`native_archive.py`](../contrib/sharepool/native_archive.py) and
[`native_mining_gate.py`](../contrib/sharepool/native_mining_gate.py).

## What is durable

Schema 3 stores an append-only event log in the same SQLite database as the
bounded hot cache. Each event contains an original template or proof, its
identity and SHA256 digest, the previous event hash, and a monotonically
increasing event number. Proof events also increment the permanent receipt
revision. Template events do not increment that revision. The archive's hashes
are local audit commitments, separate from the native block's SPN1 commitment.

Admission proceeds in this order:

1. Validate the complete origin and proof through the local enforcing native
   node. Receiving a proof also requires its full origin body.
2. Commit the event, archive high-water, receipt revision, and hot-cache changes
   in one SQLite transaction using WAL and `synchronous=FULL`.
3. Write the new protected checkpoint to a separate file, fsync it, atomically
   replace its previous version, and fsync the containing directory.
4. Return the acknowledgment or mining authorization.

A crash after the SQLite commit but before the checkpoint write does not produce
an acknowledgment. On restart, the gate verifies that the database is a complete
extension of the protected checkpoint and seals that conservative extension.
Such work remains known even if the caller did not receive an acknowledgment;
retrying the same proof does not increment the revision again.

The hot cache retains a conservative 144-block native ancestry horizon. Before
pruning any row, the gate verifies that the actual archived bytes preserve its
intact template or proof. Paid proofs are not discarded early. The append-only
archive itself is never pruned by this implementation.

## Protect the high-water separately

By default, the protected checkpoint is `<gate database>.archive-head.json`.
`trusted_head_path=` can place it elsewhere. It contains:

- `binding`: the configured regtest network, pool, public key and payout binding;
- `events` and `root`: the complete event-chain high-water;
- `receipt_revision`: the permanent acknowledged-proof high-water;
- `bytes`: the encoded archive size, including record headers;
- `version`: checkpoint format version 1.

Back up this small checkpoint independently of the exported archive. A hash
chain can prove completeness only relative to a checkpoint already trusted by
the operator. Never use a peer's claimed head, or the header of the export being
restored, as the source of that trust.

**Restoring both an old database and its old protected checkpoint is an
undetectable rollback.** Prevent that with protected or off-host checkpoint
backup. The gate cannot determine that an external backup is the latest if all
newer trusted state has been lost. An export at an older checkpoint omits later
acknowledgments even when that older export is internally valid.

Checkpoint reads use a descriptor opened without following the final symlink.
The file must be regular, have one hard link, belong to the current user, and
not be writable by group or other users. Checkpoint data is public; confidentiality
is not required. New checkpoints are created with mode `0600`. Both the database
and its protected checkpoint have lifetime exclusive POSIX owner locks. Keep
these files in operator-controlled directories and do not remove their `.owner.lock`
files while a gate is open. Platforms without the required process-lock support
fail closed.

## Export and restore

These are Python APIs for an operator-controlled process. `rpc` must be a bounded
client for the local regtest node with native SharePool enforcement active.
`public_key` is the miner's public x-only key, not signing material.

```python
from native_mining_gate import NativeMiningGate

options = dict(
    rpc=rpc,
    pool=pool_id,
    public_key=public_key,
    payout_script=payout_script,
)

with NativeMiningGate("gate.sqlite", **options) as gate:
    protected_head = gate.export_archive("round-history.spna")
    # Preserve protected_head independently/off-host before treating this export
    # as the recovery source for all acknowledgments through that high-water.
```

The export path must be new. Exports stream a bounded header and individual
records; they do not construct a quota-sized JSON or hexadecimal document.
Export verification checks every record and the full chain. The caller must
consume an entire stream before considering it complete.

Restore an export into a **new** destination using the independently protected
checkpoint for the required high-water:

```python
with NativeMiningGate.restore_archive(
    "round-history.spna",
    "recovered-gate.sqlite",
    trusted_head=protected_head,
    **options,
) as recovered:
    # Ordinary gate admission is now available against the recovered native tip.
    current = recovered.active_inventory()
```

The checkpoint must match the complete export exactly, including its receipt
revision. Missing, truncated, stale, reordered or modified records fail. A valid
export for another miner or pool also fails. No peer-completeness assertion is
accepted as a substitute.

Restore first verifies the complete stream, imports into a private staging
SQLite database, and performs native recovery there. Only the completed,
checkpointed database is published to the requested destination. A malformed
export or failed native validation leaves that destination absent and reusable.
Staging files are cleaned on handled failures. A process or machine crash can
leave private staging files; those are not a published recovered gate. After
publication, a later startup or RPC failure can leave a complete destination
that must be inspected or reopened; it is not evidence that recovery validation
was skipped.

## Recover a deep native reorganization

Normal admission latches when the current native chain no longer contains the
saved retention anchor, including rollback below its height. Returning to the
old tip does not automatically clear the latch. Close the old gate handle, then
use the explicit recovery entry point:

```python
with NativeMiningGate.recover_archive("gate.sqlite", **options) as recovered:
    job = recovered.authorize(complete_candidate_bytes)
```

`recover_archive` remains reachable when the normal constructor refuses the
latched store. The temporary recovery handle cannot receive proofs, register
origins, authorize mining or dispatch work through ordinary gate methods.

Recovery verifies the complete append-only archive against the protected head.
It then selects every archived template and proof currently eligible on the
actual native ancestry. Complete origin bodies are revalidated using
`validatesharepooltemplate`; proofs use `validatesharepoolshare`. The origin
validator checks transaction/script validity and actual fees in a temporary
native UTXO view, up to three ancestors behind the tip. The live native chain is
not rewound by the gate.

Only after all required checks succeed with the same native tip does one SQLite
transaction replace the hot cache, update the retention anchor and clear the
latch. Failure during partial validation leaves the previous hot cache,
permanent revision and latch unchanged. No receipt is counted again. Previously
paid proofs are restored as evidence: the actual parent block's authenticated
paid-state opening decides whether they are still paid on the replacement chain.

Recovery at a much earlier height also preserves proofs whose original heights
are still in the future. As the native chain advances, the gate rehydrates any
missing, now-eligible canonical archived origins and proofs through the same
native validators before admission or dispatch. This adds no new archive event
or receipt revision. It prevents later acknowledgments from being forgotten
merely because they were ineligible at the instant of recovery.

## Bounds and migration

The default archive quota is **512 MiB** of encoded event records. An explicit
`archive_quota=` may range from 4096 bytes to **4 GiB**. The event count is also
bounded at **1,000,000**. Admission fails before acknowledgment if either quota
would be exceeded; existing history is never deleted to make room. Reopening
with a larger supported quota can provide additional capacity without changing
the protected head. This is a bounded local archive, not an unlimited production
storage service or a cold-storage eviction protocol.

The hot cache remains bounded: 128 active templates and 128 active receipts,
18,944 retained rows of each kind, 256 MiB of retained template bodies, and 64
job audit records. Recovery and rehydration also enforce their bounds. If all
required eligible evidence does not fit, the gate refuses mining admission.
It never selects a subset and silently forgets the rest.

The configured archive quota counts logical records, not total filesystem use.
SQLite imposes an additional main-database page cap that reserves space for the
bounded hot cache and indexes. WAL transactions, exports and restore staging
require additional disk space. Disk-full or fsync errors refuse acknowledgment;
provision storage for these extra copies. Full startup/export/recovery integrity
checks stream the complete bounded archive and can take longer as it grows.

Version 1 stores had no pruning and can migrate after integrity validation.
Version 2 stores can migrate automatically only when no valid origin could have
been pruned: their anchor is at most height 3, `pruned_through` is zero, and their
receipt sequence is complete from 1 through the saved revision. Each schema
migration uses an explicit transaction, including DDL. A pre-pruned version 2
store cannot manufacture the missing templates or proofs and remains closed.
An archive that started after those losses cannot prove their recovery.

The archive protects locally acknowledged evidence relative to the protected
checkpoint. It does not guarantee delivery of unseen shares, prove use of a
particular DATUM executable, or remove the need for independent review before
any production deployment.
