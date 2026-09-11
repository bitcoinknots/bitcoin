# Permissionless checkpoint accounting reference

Status: executable Python experiment, tested against the checkout based on
`v29.4.1.knots20260508`. This implements a permissionless accounting history and
synthetic candidate reward settlements. It does **not** implement Knots block
validation, Bitcoin fork choice, spendable payouts, or a running mining network.

The current reference is
[`pow_share_ledger.py`](../contrib/sharepool/pow_share_ledger.py). The earlier
[signed receipt protocol](sharepool-live-protocol.md) remains a separate baseline.
Its gateway and HTTP replication are not connected to this checkpoint ledger.
The newer [hardware integration report](sharepool-hardware-and-production.md)
adds actual Testnet4 ASIC proofs and a separate passive native-chain observer.
Those components are also not yet integrated with this synthetic reward ledger.

## Ordering and participation

Anyone can propose and mine a checkpoint. No coordinator signing key, appointed
validator set, or quorum authorizes checkpoint inclusion. A checkpoint commits to
its rules, parent checkpoint, height, canonical ordered actions, action count,
post-state Merkle root, and nonce. Its BLAKE2b-256 hash must meet the common fixed
checkpoint target; the hash is interpreted as a big-endian integer. This is a
separate checkpoint format, not the Knots header serialization.

Each replica verifies the full payload, dependencies, signatures, share proofs,
and deterministic state transition before storing a checkpoint or counting its
work. Its chainwork is its parent's verified chainwork plus
`floor(2^256 / (checkpoint_target + 1))`. The selected history has greatest
chainwork; equal work selects the lexicographically smallest checkpoint ID.
Sibling work is never summed. A transport's advertised tip does not override
that choice. With fixed targets, greater chainwork also means greater height.

Miner registration is self-authorized using the existing test registry. Key or
payout updates require the existing authorized signatures. A registry change
becomes usable for jobs only after a valid checkpoint includes it. Signatures
authorize identities and jobs; they do not select the ledger history.

An optional coordinator can propose job data operationally. The reference's
`make_job` lets a registered miner construct and validate the same job locally,
then sign it. Neither checkpoints nor reward settlement need a coordinator seal.

## Jobs, snapshots, and delayed settlement

A job binds the exact checkpoint ID, its post-state Merkle root, that state's
registry, candidate reward parent and height, origin epoch, miner identity,
approved share target, serial, and deterministic payout root. Its manifest root
is placed in `m_mm_rhs` before hashing. The coinbase contains the registered tag
and identity and exactly the payouts computed from the committed state.

The validator reconstructs the coinbase and header and verifies the miner's
signature. A proof may vary only nonce and extranonce and must meet its approved
target. Credit comes from that target, not from how unusually low its hash was.
Different registered tags produce different templates even with identical
non-coinbase transaction selections; they do not receive separate work quotas
when their payout script is the same.

For a proof included in a checkpoint whose parent is `P`, its job checkpoint `J`
must be an ancestor of `P`, and:

```text
height(P) - height(J) <= max_job_age
origin_epoch = floor(height(J) / epoch_checkpoints)
budget_key = (pool_id, origin_epoch, original_payout_script_bytes)
```

The age boundary is inclusive and applies to ordinary and winning proofs.
There is no use of peer arrival time, claimed submission time, or a coordinator
timestamp for eligibility. A newly signed job on an old checkpoint remains
possible within that boundary: this is bounded stale-snapshot eligibility, not
proof that a miner used the globally latest snapshot or signed at a certain time.

A winner must extend the candidate reward tip at `P`, and must be the last and
only winning action in its checkpoint. Its immutable coinbase pays the unpaid
claims at `J`. Later claims already included between `J` and `P` stay pending.
The winning proof becomes one pending claim; promotion of a previously included
ordinary share does not credit it twice. Subsequent eligible jobs pay that tail
once. Ordinary proofs from an earlier reward parent can still arrive within the
checkpoint ancestry and age rules.

For example, a job at `J` commits to share A. Share B is then included while the
job is hashing. If that job wins within its age limit, it pays A and leaves B
and the winning proof pending. Refreshing the next job changes both the snapshot
and `m_mm_rhs`; it cannot alter the solved job. No proof commits to itself.

All unpaid work in a job snapshot participates in its proportional allocation,
using integer arithmetic and deterministic largest-remainder rounding. With no
unpaid claims, the registered finder receives the synthetic fixed reward. This
bootstrap rule and the absence of an explicit coordinator fee are experimental
economic choices. Coinbase matching is against the job's committed registry,
not each replica's unrelated latest observation. Paid and pending claims retain
the payout script authorized by their original registry.

## Quotas and progress

The allowance aggregates all credited proofs under the same budget key,
including already paid work. Changing a tag, miner ID, or signing key does not
reset a destination's allowance. There is no percentage rule.

The admission policy is `credit-and-stop`: a new job's own checkpoint must have
enough remaining allowance for one more target-weighted proof. Eligible
in-flight proofs continue to receive credit even if later inclusion exceeds the
current allowance. Excess is reported; it does not automatically invalidate a
candidate reward settlement. The age and per-checkpoint action bounds limit
eligible spillover in ledger terms. They do not establish a hard physical
hashrate ceiling or enforce use of DATUM software.

Anyone can mine an empty checkpoint at the same target and chainwork weight as
a populated checkpoint. It earns zero payout-share credit. Such checkpoints
advance epochs even when every payout script has exhausted its allowance and
no reward block has been found. No coordinator seal or permission is needed.

**These epochs count checkpoint work, not elapsed time.** The illustrative input
`5 TH/s * 600 seconds` produces a numeric allowance of `3 * 10^15` work units,
but an epoch does not demonstrably last 600 seconds. More checkpoint hashpower
can accelerate quota renewal and job expiry. Production difficulty adjustment,
clock policy, security budget, and incentives to mine checkpoints are not
specified. Easy fixture targets offer no production attack resistance.

## Disagreement and data availability

| Situation | Reference behavior |
| --- | --- |
| Full valid histories arrive in different orders | Replicas converge on greatest verified checkpoint work, then smallest ID. |
| A child is received without its parent or job checkpoint | It remains unresolved and contributes no work; retry with dependencies validates it. The importer reports unresolved count and does not persist a download queue. |
| A proposer withholds its checkpoint payload | That checkpoint cannot become locally selected. Other participants can mine and supply a competing history. Inclusion of a particular withheld share is not guaranteed. |
| A proof is too old for the current branch | Current-branch inclusion rejects it. It can still enter an eligible sibling history, which must compete under the same fork rule. |
| A competing history wins | Provisional registry, pending claims, paid IDs, reward tip, and balances switch together. Orphaned claims are not unioned into the selected branch. |
| An orphaned proof is resubmitted | It needs explicit inclusion, an ancestral origin checkpoint, and remaining age eligibility; its epoch is not remapped. |
| Replicas use different rules | They reject each other's bundles and cannot converge by simply sharing more work. |

PoW replaces the coordinator's exclusive ordering authority with competition
over checkpoint work. It does not guarantee prompt data availability, complete
share disclosure, censorship resistance against dominant checkpoint hashpower,
or instant finality. A partition can produce temporary disagreement. The same
full valid object set and rules converge within the reference's storage bounds.

The synthetic reward history deliberately reorganizes with checkpoint fork
choice, including rollback of a previously displayed payout. **This does not
choose or reorganize Bitcoin's actual chain.** Resolving the relationship between
base-chain block validity, base-chain PoW, and checkpoint anchoring is required
before connecting this experiment to real funds. Do not reject stock Bitcoin
blocks using a replica's independently selected local checkpoint tip.

## Resource admission and remaining implementation work

Checkpoints have bounded payloads and action counts. Invalid state, signatures,
or PoW never enter the caches; a partially invalid checkpoint changes no state.
Imports may retain individually valid checkpoints before a later bundle object
fails, and callers must retry missing dependencies explicitly.

Before accepting a resulting state, the validator reserves coinbase space for
all unpaid payout scripts, its resulting registry, and ancestor registries whose
jobs remain eligible. Oversized registration or update sets are rejected before
they strand accepted work. Expired unused destinations can release reservations;
pending claims retain theirs until paid. The laboratory coinbase bound is 4096
bytes. This admission rule preserves the existing full-snapshot allocation;
it introduces no payout batching.

The store retains all valid branches and full immutable states. Its configured
maximum is at most 4096 checkpoints; reaching it stops new storage. This is a
laboratory bound, not a safe production pruning or fork-eviction policy. A mined
fork flood can exhaust it. Convergence and heartbeat progress are claimed only
within those bounds. Save/restore is capped at 64 MiB and replays validation;
atomic replacement is not a complete crash-recovery system. Validation and
storage cost grow with history; no production throughput claim is made.

Other remaining work includes native Knots integration, DATUM/ASIC job transport,
full transactions and UTXO validation, fees and reward schedule, coinbase
maturity, multi-pool aggregation, peer discovery/downloads, production keys and
cryptography, checkpoint incentives, and coexistence with other `m_mm_rhs` uses.

## Reproduction

From the repository root, using Python 3 and this checkout's test framework:

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/run_pow_ledger_scenarios.py
```

The [scenario report](../contrib/sharepool/results/pow-ledger.json) covers eight
cases with three independent validating objects per case: shared-payout quotas,
empty checkpoint renewal, delayed settlement, expired-job forks, missing-data
retry, reward-history reorganization, equal-work ties, and store replay. These
are direct object deliveries in one process, not network or GPU benchmarks.
The [unit-test log](../contrib/sharepool/results/unit-tests.txt) includes the new
adversarial checkpoint tests and earlier accounting, registry, and gateway tests.
This reference's subset contains 149 tests: 25 checkpoint tests and 124 earlier
baseline tests. The combined log also includes the later native/hardware tests.
Checkpoint cases exercise forged PoW and post-state roots, immutable payout
origins, repeated proofs, exact age boundaries, payout-capacity admission and
release, reordered dependencies, and settlement rollback.
The earlier six HTTP scenarios and previously recorded stock-node regtest
results test their respective baselines, not this new ledger's native operation.
