# Current v6 resource model

The corrected model does **not** establish a production envelope for SHIFT14.
Its variance result assumed uncongested admission. The current codec's repeated
job openings, recent state, payout coinbases and history reads impose additional
costs that the earlier proof/template feasibility screen did not include.
Native SHIFT10 and consensus byte/count limits remain unchanged in this work.

The new [machine-readable resource artifact](../contrib/sharepool/results/tides-v6-resource-budget.json)
contains necessary-bound failures and conditional upper bounds. It does not
replace historical variance artifacts or rerun their simulations. Generate it
with:

```sh
python3 -B contrib/sharepool/tides_service_contract.py --resource-only \
  --output contrib/sharepool/results/tides-v6-resource-budget.json
```

## Workload and byte accounting

The illustration holds native bits at `0x17034219`, admits all network work
cooperatively, and evaluates proposed SHIFT14: approximately 20,114.21 proofs
per expected native block, rounded up to 20,115 for byte accounting. Pool work
uses the existing eight-network-work window and issued-job cutoff. There is no
new assumption that a coordinator can compel another producer to include data.

The workload explicitly specifies current proofs, recent proof/origin counts,
distinct exact jobs, payout recipients, transaction-body size/count and shared
transaction sets. A job is an exact origin template, not a unique physical miner.
Each table row assumes a distinct coinbase per job; different header commitments
alone do not require different coinbase transactions. Distinct non-coinbase sets
are disjoint and reused within their declared group. All origins and the winning
pool use the row's recipient count and script length.

For short payout scripts, each proof serializes to 512 bytes, recent state to
36 bytes per entry, certificates to 100 bytes each, and payout outputs to
31 bytes each. P2TR proofs/outputs are 524/43 bytes. An immediately admitted
steady workload repeats about four native-height cohorts of state and
certificates in the next complete snapshot. A job with no new share delta still
repeats approximately three inherited cohorts. These are explicit cohort
assumptions, not bounds on every backlog pattern.

The transaction table deduplicates whole serialized transactions. Different
coinbase transactions do not share their identical payout-output prefixes. With
the modeled 100-byte scriptSig and witness commitment, each coinbase serializes
to 3,334 bytes for 100 short-script recipients or 31,236 bytes for 1,000.
The model includes table/vector prefixes, index lengths, template headers,
proof/state/certificate vectors, envelope, signature, job commitment and history
head. Lower and upper bounds differ where exact transaction sizes and table
indexes are unspecified. Independent tests compare these formulas with the
actual v6 Python codec, including real transaction serialization and CompactSize
boundaries. These serialization fixtures do not establish native transaction
validity, fees, sigop cost or validation throughput.

## Mean and burst constraints

The following rows use short scripts and one shared non-coinbase transaction
set unless stated otherwise. Snapshot/closure values are upper wire bounds in
MiB. Each dependency forest includes the current snapshot, its distinct actual
parent and one distinct empty-current-delta opening per direct job. It assumes
certificate shortcuts terminate further dependency traversal; additional
recursive dependencies only add cost.

| Declared mean workload | Snapshot | Dependency closure | Result |
| --- | ---: | ---: | --- |
| 16 jobs, 100 recipients, 100 kB bodies | 12.74 | 58.76 | These bounds fit at the illustrative mean only |
| 100 jobs, 100 recipients, 100 kB bodies | 13.11 | 236.60 | Exceeds 64 MiB dependency limit |
| 100 jobs, 1,000 recipients, 100 kB bodies | 15.77 | 244.58 | Exceeds dependency limit |
| 1,000 jobs, 1,000 recipients, 100 kB bodies | 43.61 | 2,475.08 | Exceeds snapshot and dependency limits |
| 100 jobs, 100 recipients, distinct 100 kB transaction sets | 22.32 | 255.01 | Exceeds snapshot and dependency limits |

Certificates avoid recursive validation; they do not eliminate the exact opening
needed to authenticate a job. The 100-job/100-recipient case repeats a minimum
approximately 2.10 MiB opening per job even though the non-coinbase transaction
set is shared. This is the dominant missing bound. Opening deduplication by hash
does not merge different signed jobs.

At this illustrative mean, the declared 100-recipient/100-kB workload allows
767 origins under snapshot, expanded-body, reference and reserved-origin bounds
alone; including optimistic exact-opening dependencies reduces that to **18**,
or an average of at least 1,117.5 proofs per job. For 1-MB bodies and 2,000
transactions, the corresponding counts are 258 and **17**. These numbers are
diagnostics of a tightly specified workload, not permission rules or a supported
miner-count guarantee. A 3.85-MB body leaves insufficient root space at this
mean even with one job under the declared serialization bounds.

The first-order limits also remain necessary: at most 2,048 unique origin checks
across the dependency graph, 512 MiB of expanded templates and 2 million
transaction references per snapshot. Mining construction reserves one future
origin and depth edge. Even perfect non-coinbase wire reuse does not remove
expanded-body/reference charges. For example, 4,000,000-byte bodies allow at
most 134 origins by expanded bytes alone. Such byte/count examples do not assert
that all native weight/sigop limits can be reached simultaneously.

With fixed native probability per proof, proofs through the next native find
are geometric. The numerical binomial-tail calculation gives a one-interval
99th percentile of 92,628 proofs and a four-interval total 99th percentile of
202,047. Putting the first count into one snapshot, with three previous mean
cohorts, makes even the 16-job root **50.64 MiB**. That stress case is not a
joint 99% queue guarantee. Carrying work forward may distribute it across later
blocks; its survival then depends on producer scheduling, competing load and
the existing finite proof age. The uncongested variance result cannot certify
that congested process.

Away from the easy-target clamp, SHIFT14 density ranges from 16,384 to strictly
less than 32,768 proofs per expected native block. At the conservative upper
endpoint, proofs plus four recent-state cohorts alone require **20.5 MiB** for
short scripts, before templates, certificates or payouts. No amount of origin
reuse makes that fit the current 16-MiB snapshot. Unbounded waiting-time tails
and finite resource/age limits prevent an unconditional admission guarantee.

## Recipients and historical reads

The mining RPC's conservative coinbase reservation is
`4 * (379 + serialized_payout_outputs) + 36` weight units. With no ordinary
transaction space reserved, its recipient ceilings are:

| Native weight allowance | Short scripts | P2TR |
| --- | ---: | ---: |
| 4,000,000 WU | 32,245 | 23,246 |
| Contextual RDTS 800,000 WU | 6,439 | 4,642 |

These are reservation bounds, not maximum physical miner populations or a
promise that the remainder of a proposed block is valid. Repeated unique
coinbases can exhaust snapshot bytes well below these counts. Conversely, an
eight-work window containing about 160,914 distinct positively paid recipients
cannot fit one direct-payout coinbase. Sharing templates or changing proof
difficulty does not solve that output limit. A future service contract must
account for recipient population and preserve acknowledged payment obligations;
silently dropping positive payouts or treating addresses as permissioned
identities does not close it.

History costs are a separate local limit. Without a persistent authenticated
pool-specific index, gathering eight network-work units for a pool at fraction
`q` spans approximately `8/q` native blocks at the mean work rate. At the declared
13.11-MiB snapshot size, cold full-snapshot scan estimates are:

| Pool fraction | Native snapshots | Cold bytes | Global admissions examined |
| --- | ---: | ---: | ---: |
| 10% | 80 | 1.02 GiB | 1.61 million |
| 1% | 800 | 10.24 GiB | 16.09 million |
| 0.1% | 8,000 | 102.45 GiB | 160.91 million |

These are conditional operation/read-volume estimates for fully admitted work,
not measured disk speed or a claim that this globally loaded dependency workload
is presently admissible. Approximate selected-pool retained state is 23 MiB
using an explicitly assumed 128-byte `Admission` object plus script storage;
the whole oldest admitted cohort can increase it. The portable model does not
measure `sizeof(Admission)` or allocator overhead.

History scan budgets (4,096 blocks, 65,536 entries and 64 MiB per call) are
resumable local limits. The default derived-delta cache and aggregate retained
query budget are each 64 MiB, with up to 16 query cursors; each cursor does not
get its own 64 MiB. Different parent/work queries can evict cached progress.
Missing data and local resource exhaustion must remain distinguishable from
empty history or invalid payouts.

## Design implications

Keep the current difficulty and consensus limits while measuring exact resource
usage before issuing jobs. Bound and expose snapshot bytes, complete dependency
closure, expanded bodies, references, recipients and context-specific coinbase
reservation; expose queue/backpressure and pending history explicitly. Local
validation caches can reduce repeated CPU work without changing these encoded
charges or creating additional inclusion capacity.

A future denser profile needs structural work: share or derive immutable
settlement payload/state while preserving exact per-job attestations, reduce
repeated transaction sequences without treating distinct transactions as equal,
and address direct-coinbase recipient limits and finite-age backlog semantics.
An authenticated pool-specific history index can reduce local scans, but must
retain branch/cutoff correctness and reconstruction from committed records.
These are candidate directions, not implemented rules in this model. Simply
raising limits, globally making shares easier, or requiring many miners to reuse
one job does not establish the requested variance and template-diversity
contract.
