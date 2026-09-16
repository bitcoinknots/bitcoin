# V8 preparation and admission measurements

The [admission-pressure follow-up](sharepool-v8-admission-pressure.md) reduces
repeated preparation and refuses new credits when the next local settlement
cannot accommodate them. Mainnet remains disabled. The measurements below do
not establish sustained capacity or regular-pool payout variance.

## 100 miners, 1 MiB local snapshot budget

Both runs scheduled 1,000 proofs over 60 seconds at ten shares per minute per
miner. They used two loopback Debug native nodes, fixed easy assignments 2/4/6,
20-second block opportunities, 40-second template refresh and origin-reference
deduplication. The follow-up changes both gateway/native code and source
ownership, from one serial owner to eight owner threads on the same host.
Consequently, this is an observed comparison of the combined changes, not an
isolated measurement of any optimization or distributed gateway capacity.

| Measurement | Previous serial source | Eight-owner follow-up |
| --- | ---: | ---: |
| Offered within 60 seconds | 236 | 403 |
| Acknowledged within 60 seconds | 236 | 389 |
| Admitted and peer verified within 60 seconds | 229 | 382 |
| Scheduled requests still unproduced at cutoff | 764 | 597 |
| Offered but awaiting ACK at cutoff | 0 | 14 |
| ACKs awaiting settlement at cutoff | 7 | 7 |
| Eventually admitted with verified payouts | 1,000 | 1,000 |
| Expired ACKs / capacity refusals / rejected proofs | 0 / 0 / 0 | 0 / 0 / 0 |
| Jobs / settlement blocks | 903 / 26 | 747 / 17 |
| Live phase plus catch-up and drain | 594.959 s | 401.358 s |
| Aggregate collector registration and ACK service | 309.147 s | 330.305 s |
| Collector service p95 | 500.5 ms | 604.1 ms |
| Collector proof RPC attempts / failures | 1,000 / 0 | 1,000 / 0 |
| Collector snapshot-write RPCs | 5,885 | 764 |
| Native node 0 CPU time | 465.21 s | 404.26 s |

Elapsed live-and-drain time was 32.54% shorter, and first-minute ACKs increased
from 236 to 389. The run still **missed the requested cadence**: 597 scheduled
requests remained unproduced at the one-minute cutoff. Correct eventual payouts
do not turn those late requests into first-minute throughput.

Collector service was 6.84% longer and its p95 increased 20.69% under the new
concurrent load. The source owners accumulated 2,167 seconds of overlapping
queue wait, with a 9.70-second p95. Those owner intervals cannot be summed into
wall time. Fourteen offered items awaiting ACK at cutoff are consistent with
the eight-item FIFO plus up to eight producer-held items and one consumer item.

Node 0 averaged approximately one CPU core; the driver averaged 0.68 cores and
reached a sampled peak RSS of 717.6 MB across its 100 gateway instances. The
native nodes' sampled peaks were 88.6 and 77.2 MB. Sampling is every five seconds;
these are observations, not hard memory bounds or production requirements.

The fixture transferred 4,861,371 logical payload bytes, including 513,000 proof
bytes, 747 full origins and 253 references. It avoided 1,345,577 repeated origin
bytes. Separately, node 0 recorded 4,275,919 bytes sent and 1,256,888 received
over loopback P2P. These count different transports and must not be added into a
mainnet bandwidth estimate.

[Previous capture](../contrib/sharepool/results/v8-scalability-100-final.json) ·
[Follow-up capture](../contrib/sharepool/results/v8-throughput-100-workers.json) ·
[Independent event comparison](../contrib/sharepool/results/v8-throughput-comparison.json)

## 100 miners, 64 KiB overload

The same 100-miner/eight-owner workload offered 1,000 proofs. It acknowledged
873 and refused 127 native-valid proofs before acknowledgement because they
did not fit the next local prefix. All 873 ACKs settled and were peer verified
with exact work-weighted coinbase payouts. There were zero expired ACKs, zero
invalid/stale rejections and exactly 873 confirmed receipts in the journal.
Refused work was neither acknowledged nor counted as delivered capacity.

At 60 seconds, the source had offered 160 proofs: 122 were acknowledged, 21
were refused and 17 remained in flight. Both nodes had admitted 98; 24 ACKs
awaited settlement and 840 scheduled requests were still unproduced. The run
took 596.196 seconds including catch-up and drain, across 27 settlement blocks.
Its largest snapshot was 64,877 bytes against the 65,536-byte local budget.

The earlier serial 64 KiB run acknowledged all 1,000, admitted 904 and left 96
expired. The new policy avoids that outcome in this workload by refusing excess
credit before ACK. It does not recover refused work, prove capacity for every
scheduled share, or guarantee settlement under arbitrary block arrivals/reorgs.

Tight-budget processing is still expensive: collector registration/ACK attempts
took 540.710 seconds in aggregate, with a 1.621-second p95. Full-prefix overflow
can invoke the exact fitting-prefix fallback, and new work still receives fresh
native validation. Permissionless overload fairness remains an open concern.

[Overload capture](../contrib/sharepool/results/v8-throughput-100-small.json) ·
[Earlier expiry evidence](../contrib/sharepool/results/v8-scalability-100-expiry-forensics.json) ·
[Independent event and receipt comparison](../contrib/sharepool/results/v8-throughput-comparison.json)

## Revision boundary

The two large throughput workloads use the preparation reuse, incremental
admission accounting and deadline pressure described above. They preceded the
final contextual coinbase-output guard and graceful construction retry added
during review. Their exact
prelaunch sources and binary hashes are preserved separately from final-code
verification. The largest workload uses 100 payout identities, well below the
native ordinary or reduced-data payout reservation limits; nevertheless, the
401-second result is a measurement of the recorded revision, not a fresh
benchmark of the final code.

The raw reports' `source_sha256` maps were read from disk at run completion.
The large run overlapped an edit to the unused inventory importer; three
already imported Python files changed on disk during the small run's final
coinbase-guard work. The processes continued using their loaded prelaunch code.
Use the [large](../contrib/sharepool/results/v8-throughput-large-prelaunch.json)
and [small](../contrib/sharepool/results/v8-throughput-small-prelaunch.json)
prelaunch manifests for the measured revision. A
[source patch](../contrib/sharepool/results/v8-throughput-benchmark-source.diff)
against `4eb1e2a40aca74360b4ce325fb9c239f56bb6d2e` reconstructs all 26
[recorded source hashes](../contrib/sharepool/results/v8-throughput-benchmark-sources.json);
that reconstruction was independently checked before publication.

## Final-code verification

All 386 gateway Python tests, 10 capacity-fixture tests and 121 selected native
C++ cases passed. Four final native integration fixtures passed: ordinary and
reduced-data payout-budget RPCs with signed job construction, capacity-refused
winning blocks and missing-only recovery, v8 Stratum wire/CLI behavior, and v4
archive provenance with native payouts. The pressure fixture acknowledged 25
proofs and refused three without adding receipts; the exact winning block was
still accepted.

A final eight-miner/eight-owner smoke acknowledged all 16 scheduled proofs
within 12 seconds and settled all 16 with exact payouts during the subsequent
drain. There were no refusals, invalid rejections, expired ACKs or extra
receipts. Source and binary hashes matched before and after the run. Its short
duration does not replace the two larger measurements above.

The earlier 100-miner weighted-payout, assignment, fork, restart and reindex
fixture also passed its 13 checks on the preserved pre-guard revision. That
result is recorded separately from the final-code checks. These correctness
tests do not measure production variance or sustained distributed capacity.

[Final verification](../contrib/sharepool/results/v8-throughput-verification.json) ·
[Native commands and hashes](../contrib/sharepool/results/v8-throughput-native-verification.json) ·
[Python log](../contrib/sharepool/results/v8-throughput-python-tests.txt) ·
[Final smoke audit](../contrib/sharepool/results/v8-throughput-final-smoke-verification.json)

## Remaining capacity constraints

The next measured bottleneck is collector admission. Each receipt still needs
current provenance, native validation and durable journal sealing. Repeated
evidence reads, canonicalization, ancestry RPCs and per-receipt filesystem
barriers remain. Native history preparation and block assembly also contend
under the main chain lock when multiple owners share one node.

The optional accountant prevents rebuilding the complete pending batch for
every ACK. It does not cache native validity, remove provenance validation,
bound aggregate permissionless CPU/RSS, or reserve global inclusion capacity.
Inventory pagination remains bounded but can revisit shared source snapshots.

The unchanged 32,768-proof consensus limit independently prevents 1,000 miners
from submitting ten shares per minute into every average ten-minute block:
that workload produces 100,000 proofs. Template origins, dependency data and
coinbase outputs can bind sooner. Faster validation alone cannot remove those
limits, block-arrival variance or the need for durable evidence availability.
