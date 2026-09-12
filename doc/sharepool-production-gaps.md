# Production gap register

This branch is an opt-in regtest implementation. Passing its tests does not
authorize mainnet deployment. Version 4 changes the wire/rules and local database
format; use a fresh test chain. Historical v3 reports describe the older code.

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

The production entry point is `HashMiningGate.make_native()`, then `authorize()`
and a final `ready_for_dispatch()` check. `candidate()` and `make()` remain
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
establish that global history. No such credit protocol is activated here.
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
sampling variance alone does not establish miner payout variance. The current
one-time settlement and network-height expiry are not that rolling window.
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

**What is attested.** Distinct valid template headers, full authorized bodies,
submitted PoW and exact coinbase allocations can be checked. They do not prove
independent transaction selection, miner hardware identity, a precise physical
hashrate from arrival times, or that a particular software implementation was
used. Production claims must describe enforced behavior, not those stronger
unobservable properties.

## Release evidence

Use the v4 verification report and its binary/source hashes for the actual test
revision. Model results, wire fixtures, mocked gate tests and native integration
tests provide different evidence; none should be presented as ASIC testing,
WAN throughput or mainnet consensus approval. Mainnet remains disabled.
