# Production gap register

This branch is an opt-in regtest implementation. Passing its tests does not
authorize mainnet deployment. Versions 4 and 5 have separate wire/rules and local
database profiles; use a fresh test chain. Historical reports describe their
recorded source revisions.

## Current follow-up

The optional [v5 confirmed ledger](sharepool-confirmed-ledger.md) anchors
admissions in native blocks and derives later payouts from the actual parent.
It preserves confirmed pending credits beyond proof expiry. It remains a
bounded regtest experiment: provisional ACK coverage, abandoned-pool capacity,
pool continuation and rolling-window payout variance are unresolved.

The v4 review's first three implementation issues are addressed in this
revision: new work reserves a future dependency edge; ACK archives retain the
complete transitive opening and native-parent closure; and required snapshot
requests are isolated by pending-block provenance. Python DAG traversal and
rejected registration retention were hardened alongside those fixes.
Pending native block bodies are now retained without repeatedly downloading
them while their separate snapshot data is missing. Retention does not confer
validity or advance the common ancestor.

## Hardening implemented in version 4

| Area | Implementation | Evidence to inspect |
|---|---|---|
| Large overlapping templates | One canonical Wtxid transaction table; complete header and ordered references per template. Separate compact-byte, expanded-byte, reference and origin budgets. | Python codec and native hash tests, including 100 reconstructed 3.85 MB templates. This is a wire/storage fixture, not 100 native-valid 4 MB blocks. |
| Native job construction | Mempool selection, reserved coinbase space, exact subsidy/fees, derived paid state, external exact-job signature and full finalization. | `feature_sharepool_hash_builder.py`; preparation and finalization do not admit evidence or authorize dispatch. |
| Validation scheduling | Dedicated bounded retry worker, script checks outside `cs_main`, context rechecks, LRU and per-session caches, complete-body success cache. | `feature_sharepool_hash_worker.py`, including real scripts, responsive P2P/RPC, concurrent tip change, durable pending restart and competing forks. |
| Dependency reuse | Completed origins retain intrinsic descendant depth, with witness-sensitive identity and remaining-depth checks on reuse. | Dense DAG, witness distinction and partial-missing longest-path native tests. |
| Durable ACK storage | Streaming verified archives and cold rollover before admission; sequence, hashes and receipt revisions survive rotation. | Gate/archive tests, including 100 ACKs with a4KiB resident quota, restart, restore, corruption and reorg. |
| Batch overflow | Deterministic bounded selection by origin height and numeric proof ID. Deferred receipts remain durable; only canonical settlement marks payment. | Batch tests, native builder adapter tests and 100-miner integration. |
| Refresh-only chains | Unworked issued jobs remain local evidence but are not mandatory records in each settlement. Complete origins of selected proofs remain required. | Seventy unworked refreshes and dependency-budget batch cases. |
| Signer corruption | Checksummed key/policy record; explicit legacy migration requires a previously trusted policy and public key. | Native signer tests. The checksum detects corruption, not an attacker able to rewrite both data and checksum. |

The native integration entry point is `HashMiningGate.make_native()`, then
`authorize()` and a final freshness check with `ready_for_dispatch()`.
The last check alone is not a complete dispatch authorization (see below).
`candidate()` and `make()` remain
explicit fixture helpers. A stored snapshot, valid signature or constructed job
alone is never a mining ACK.

## Remaining production requirements

**Guaranteed carry beyond proof age.** The existing proof window remains origin
height j through j+3. Overflow can defer a durable receipt until it becomes
`expired_unpaid`; retention is not a promise of eventual payment. Removing the
age rule would permit fresh work on obsolete, easier jobs. An indefinite payment
contract needs a pending-credit checkpoint anchored before expiry, explicit
credit ownership, reorg-safe spent accounting, a bounded arrival/service policy,
and rules for which rewards fund deferred credits. Local ACK timestamps cannot
establish that global history. Version 4 does not provide that protocol. The separately enabled v5 ledger
implements confirmed-credit accounting, with the limitations described above.
Deterministic carry is the intended behavior; this revision implements bounded
selection and durable retention, but does not complete that payment guarantee.

**Native historical evidence retention.** Gate cold archives do not replace the
node's consensus evidence database. Native snapshot retention still has local
byte/object quotas. Deduplicated standalone templates reduce repeated bodies
but do not provide unlimited archival storage. A production deployment needs
historical archival/restore, state-index scaling, disk provisioning and recovery
that preserves reindex/reorg availability. Storage exhaustion is local missing
data, never evidence that a block is consensus-invalid.

**Difficulty and capacity objectives.** A finite proof rate cannot guarantee
accurate sampling for arbitrarily small permissionless participants. Choose the
supported miner share rate, payout window, comparison horizon and measured
validation/traffic budget. The requested objective is variance comparable to a
regular pool at the same hashrate. Given direct coinbase payouts, the working
reference is a rolling work window such as PPLNS/TIDES. Fixed-duration proof-count
sampling variance alone does not establish miner payout variance. Version 4 one-time settlement and network-height expiry are not that rolling
window. Version 5 removes confirmed-credit expiry, but its one-time settlement
is also not a rolling window.
Payouts currently use only selected eligible proofs; an empty selection pays the
snapshot owner. With sparse sampling, that fallback also needs explicit treatment
in the payout policy and variance tests. Receipt expiry is not a percentage of
pool revenue lost: every found block still distributes its complete reward.
See [difficulty and payout comparison](sharepool-difficulty-capacity.md).
Regtest's easy-target clamp does not measure production hashing or validate the
experimental shift 10 as a deployment choice. An FPPS-style guarantee independent
of pool block luck would additionally require funding that absorbs that risk.

**Worst-case latency.** Initial network graph checks, coin-view preparation,
cold database reads/fsync and native chain connection still include work under
global locks. Historical/reindex fallback remains synchronous. Worker tests
measure one host and loopback workload; WAN loss, sustained backlogs, slow disks,
large independently changing transaction sets and deep forks still require
measured limits and recovery testing. There is no hard millisecond guarantee.

**Data availability and activation.** A valid hash authenticates supplied bytes;
it cannot compel disclosure or prove that undisclosed work does not exist.
Nodes with missing bytes remain pending. Replication helps availability but
does not remove that assumption. Public activation requires a reviewed protocol,
deployment/rollback plan and compatible consensus participants; these regtest
flags are not a mainnet activation mechanism.

**Recovery findings F7.** Startup still lacks bounded quarantine/restore for
corrupt snapshot and pending-block records. The template index retains one
snapshot source and does not search alternative retained copies if that source
is unreadable. These are local data-fault availability findings, not demonstrated
remote corruption. Runtime quarantine of other records does not close them.
Final static review also found that rejection of an invalid alternate body with
the same header hash can evict a retained pending body in `ProcessNewBlock()`.
The duplicate-fetch fix does not cover this adversarial eviction path; a bounded
reproduction and retention rule remain to be added.

**Dispatch binding finding F8.** `ready_for_dispatch()` checks the active tip and
receipt revision, but does not bind the supplied authorization to the issuing
gate, policy or exact bytes. A caller must retain the exact authorization from
the correct gate; this API must not be treated as a standalone approval of an
arbitrary object. Issuer-bound authorization remains an integration requirement.

**What is attested.** Distinct valid template headers, full authorized bodies,
submitted PoW and exact coinbase allocations can be checked. They do not prove
independent transaction selection, miner hardware identity, a precise physical
hashrate from arrival times, or that a particular software implementation was
used. Production claims must describe enforced behavior, not those stronger
unobservable properties.

## Release evidence

Use the [v5 verification report](sharepool-v5-hardening-report.md) and its per-run
binary/source hashes for this revision. The v4 report remains historical.
Model results, wire fixtures, mocked gate tests and native integration
tests provide different evidence; none should be presented as ASIC testing,
WAN throughput or mainnet consensus approval. Mainnet remains disabled.
