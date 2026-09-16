# Live load and production capacity follow-up

This follow-up measures work that keeps arriving while settlement runs. It also
reduces repeated archive-origin reads and evaluates native snapshot preparation.
It changes no consensus target, settlement hash, payout rule or activation.
The [verification manifest](../contrib/sharepool/results/capacity-followup-verification.json)
records final sources, binaries, test coverage and the separate capture scopes.

## Live native workload

The new [functional fixture](../test/functional/feature_sharepool_hash_live_capacity.py)
uses 100 logical miner gates, one source thread with its own RPC connection, one
collector owner and two native nodes. Each miner signs its exact job. New jobs
use real fee-paying mempool transactions, explicit coinbase tags, current native
parents and DATUM-style refresh timing. The native nodes check the actual proof,
complete snapshot and direct coinbase payouts.

The source schedule continues during block construction, submission and peer
verification. Its eight-item handoff queue is bounded; each item's serialized
block, snapshot and proof are limited to two MiB. One producer and one consumer
can also retain an in-flight item. These are wire-payload bounds, not process RSS
bounds. Each gate remains on its original owner thread.

The [100-miner capture](../contrib/sharepool/results/production-live-100.json)
scheduled 240 requests over 120 seconds, with a block opportunity every 20
seconds. Blocks are deliberately solved at easy regtest difficulty. A delayed
opportunity is not followed by a burst of artificial catch-up blocks while the
source is active.

| Pipeline stage | At 120 seconds | Including later catch-up/drain |
| --- | ---: | ---: |
| Scheduled requests | 240 | 240 |
| Actual proofs offered | 211 | 240 |
| Durable acknowledgments | 205 | 240 |
| Native admissions | 168 | 240 |
| Peer-verified admissions | 168 | 240 |

At the cutoff, 29 requests were still waiting for source preparation, six proofs
were offered but unacknowledged, and 37 acknowledged proofs awaited admission.
The workload therefore did not keep up with two scheduled requests per second.
All 240 later settled across eight blocks, with zero rejection or acknowledged
expiry, after 158.82 seconds of live operation and drain. The additional 38.82
seconds is not credited to the fixed-phase admission rate.

The 1.4 verified proofs/s measured during the phase is neither a sustainable
rate nor an upper capacity bound. The source driver is serial, jobs and shares
are synthetic work on real native templates, and both validating nodes run on
one host. Six native-tip changes interrupted source job preparation and caused
fresh attempts. This capture does not model 100 independent native machines,
WAN traffic, full block weight or ASIC efficiency.

Every phase counter is recomputed from exact proof IDs and completion timestamps.
The separate [boundary capture](../contrib/sharepool/results/production-live-boundary.json)
sets a ten-second phase and a twenty-second block interval: it correctly counts
20 acknowledgments and zero admissions during the phase, then 20 admissions in
the explicitly separate drain. Final draining cannot turn an overloaded phase
into a capacity pass.

## Native construction and validation

Operation-local canonical table preparation can supply snapshot size, commitment
hash and the owner's signing digest without reconstructing the same tables for
each of those calculations. All signatures, dependency limits, native origins,
ancestry and payout checks remain required.

The diagnostic 30-miner pair improved from 89.33 to 82.97 seconds, but the
original 100-miner, three-epoch workload did not reproduce that improvement.
The [larger repeat](../contrib/sharepool/results/production-gaps-native-followup-capacity-100.json)
admitted all 900 proofs across eight blocks with no expired work or final
backlog, and verified payouts and recovery on the second node. It took **719.03
seconds**, versus 640.51 previously. Third-epoch preparation of all 100 origins
and their registration took **155.16 seconds**, versus 137.35; ingress took
135.40 seconds versus 114.47.

These historical before/after captures do not isolate host effects. The first
epoch also slowed before substantial history accumulated. A smaller successful
comparison cannot override this larger result, and neither proves a native
production-latency improvement.

A controlled cache-on/off/on comparison then replayed the same 100 template and
100 proof validations against identical saved native state, after warmup. The
three runs took 24.252, 24.107 and 23.840 seconds. Cache-off differed from the
mean of cache-on runs by only 0.25%, while the two cache-on runs themselves
differed by 1.70%. All 200 complete responses and changed-authentication and
missing-origin controls matched. This does not isolate the larger slowdown to
the optional cache or demonstrate a cache speedup. The bounded retention path
is retained; further optimization needs profiling under the larger workload.

The [concurrency change](sharepool-native-concurrency-budget.md) adds one shared
128 MiB allowance for optional decoded-cache retention, while retaining each
invocation's 64 MiB ceiling. Exhaustion declines caching and still returns
available evidence for validation. This does not bound live objects held by
verifiers, persistent per-thread history, HTTP bodies or total process memory.
Durable I/O under the chain lock and validation fairness still need service-wide
budgets.

## One large block with 100 direct recipients

The [heavy-template run](../contrib/sharepool/results/production-gaps-heavy-100-recipients.json)
used 100 distinct signed jobs sharing the same 100 witness-bearing transactions,
with distinct coinbases and header commitments. An explicit 16 MiB batch budget
allowed all 100 proofs into one settlement. Both native nodes accepted the
**3,379,600-weight-unit block** (84.49% of the fixture's four-million-unit limit).
Its snapshot was **3,428,617 bytes**, and its coinbase weighed **12,840 units**.

An [independent read of the stopped node's block file](../contrib/sharepool/results/production-heavy-100-recipient-check.json)
verified the exact 100 fixture scripts, each receiving **50,011,000 satoshis**
from the regtest subsidy and fees. There was no initial deferral, expired work,
unresolved receipt or final backlog. This closes the earlier finite coverage
gap between 100 logical miners and 100 simultaneous payout recipients.

It does not close the throughput gate. Serial source preparation and collector
registration took **505.40 seconds**, proof ingress **167.81 seconds**, local
settlement construction/submission **73.17 seconds**, and follower recovery
**40.40 seconds**. The complete run, including diagnostics and receipt/recovery
checks, took **1,026.18 seconds**. Sampled CPU time was 614.21 seconds in the
Python driver, 248.00 seconds on node 0 and 138.15 seconds on node 1. Driver RSS
peaked near 1.04 GB; the native nodes peaked near 116 and 107 MB. These are
observations from this fixture, not node sizing requirements.

The transactions deliberately use large nonstandard witnesses allowed by the
isolated test configuration. They exercise bytes and weight, not expensive
signature checks. This is one finite shared-transaction-set run, without live
churn, WAN latency or a production-load claim. It uses the pre-shared-budget
binary recorded in its wrapper; the new optional-retention cap is validated
separately.

## Archive and sampling

The [archive change](sharepool-archive-origin-facts.md) reuses exact authenticated
origin facts only within a complete verification pass. At 5,000 proofs and 100
interleaved origins, median full verification fell from 1.743 to 0.426 seconds;
cold-file opens fell from 10,001 to 201. Every historical record still verifies.
This improves repeated reads without making startup independent of lifetime
history. The archive document specifies the checkpoint/retention choices needed
to change that guarantee explicitly.

The [capacity report](sharepool-production-capacity-gate.md) combines recorded
admission evidence, explicit share-cadence scenarios and coinbase space. It keeps
Poisson proof-count sampling separate from payout variance. Under its illustrative
100-equal-miner, one-day-round, thirty-second-share scenario, one global target
would require more proofs than the unchanged per-block count budget can admit.
A faster local implementation cannot remove that protocol constraint.

## Final verification and hardware

The final shared-budget build passed **61 focused native cases**, including
exact valid/invalid/missing results with ample, partial, tiny and zero retention.
A standalone ThreadSanitizer run completed eight threads with 10,000 cache
operations each; an injected failure in actual cache insertion released its
reservation and preserved caller evidence. This is helper coverage, not a
whole-node race or saturation qualification.

The [final regression sweep](../contrib/sharepool/results/capacity-followup-regressions.json)
passed **337 Python tests and ten native scenarios**, covering earlier profiles,
worker behavior, state reuse, DATUM cadence, archive recovery, P2P relay and TCP
Stratum. Final source and binary hashes are recorded separately from the earlier
performance captures.

The [physical Goldshell test](sharepool-v7-hardware-preparation.md#physical-goldshell-observation)
produced four acknowledged proofs and four native blocks. Independent replay
verified exact work, commitments and coinbase payouts. The original current
Convoy configuration was restored, followed by a successful read-only resumption
check. This tests the optional Blake2b/Sia regtest path, not SHA256 mainnet ASICs
or sustained miner efficiency.

Mainnet remains disabled. The unresolved requirements include sustained load
with realistic template churn, an explicit sampling/payout contract, total live
memory and lock/fairness budgets, bounded lifetime recovery, WAN behavior and
long-session hardware qualification. The added tests identify these remaining
limits; successful finite draining does not remove them.
