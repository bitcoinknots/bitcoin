# Authenticated archive origin reuse

The mining gate still verifies its complete acknowledged journal before startup
or rollover succeeds. This change removes repeated origin reads within that
verification. It does not prune receipts, skip historical files, alter settlement
rules or make restart independent of lifetime history.

## What changed

For every proof, the old streaming verifier authenticated its full template and
snapshot again. Five thousand proofs sharing one origin therefore opened the
cold file 10,001 times: once for the complete sequential walk and twice per proof.

The verifier now retains only the origin's immutable header, serialized envelope
and owner signature, keyed by the exact template and snapshot identities. The
first use obtains both bodies through the existing authenticated reader. Every
proof compares its own header, envelope and signature against those facts,
including on a cache hit. Entries exist only during one complete verification
call and are limited to 1 MiB of conservatively charged retained objects and
1,024 entries. Eviction and oversized entries cause fresh authenticated reads.
This is a retained-object budget, not a bound on process RSS or transient decoding.

The independent full walk still checks every record's actual body, canonical
metadata, sequence, revision, digest, hash-chain links and segment offset. It must
reach the protected checkpoint before mining can continue. Origins that follow
their proofs in journal order remain covered by that walk. The cache cannot
authorize a proof, acknowledge work or establish native validity. No cache entry
survives a new verification call, and no filesystem timestamp or persisted
verification verdict is used.

As with any finite file scan, verification proves the bytes read during that
pass; it cannot promise that storage will remain unchanged afterward. Mining
operations continue to authenticate evidence when they read it.

## Finite measurements

The baseline is the exact `hash_gate_startup.py` at `c94b5cb`. Both arms use the
same current gate code, identical canonical evidence and protected checkpoint,
and the same rollover path. Only the full verification function differs.

| Fixture | Full cold verification, median | Cold opens | Resident-to-cold rollover |
| --- | ---: | ---: | ---: |
| 5,000 proofs, one origin | 1.426 → 0.378 s | 10,001 → 3 | 1.256 → 0.831 s |
| 5,000 proofs, 100 interleaved origins | 1.743 → 0.426 s | 10,001 → 201 | 1.595 → 0.920 s |
| 100 proofs, 100 distinct origins | 0.056 → 0.054 s | 201 → 201 | 0.052 → 0.050 s |

The 5,000-proof verification reductions are 73.5% and 75.6%. A workload without
repeated origins has little reuse, as the last row shows. More active origins
than the cache can retain will also cause rereads; correctness does not depend on
cache capacity.

The [one-origin capture](../contrib/sharepool/results/production-archive-origin-facts-single.json)
and [100-origin capture](../contrib/sharepool/results/production-archive-origin-facts-many.json)
include 100, 1,000 and 5,000 proof cases, three verification repeats, exact source
hashes, CPU time and operation counts. Proofs are solved regtest fixtures; their
setup uses direct journal persistence outside the measured region and does not
claim native mining validity. Origins are small, same-owner templates with
different timestamps. Runs use local storage, warm OS file cache and fixed
baseline-first ordering. They are descriptive measurements, not production
throughput or confidence intervals.

The 24 focused archive/startup tests cover complete restore, native branch
reconciliation through the fixture RPC, cold corruption and missing files,
protected high-water rollback, failed rollover preservation, exact proof-field
comparison after a warm origin, eviction and disabled caching, fresh-pass
corruption detection, and proof-before-origin ordering. Native validity remains
the responsibility of the separate native integration suite.

## Why bounded lifetime restart remains a separate design

The current guarantee is stronger than a fast startup index: all acknowledged
historical bodies must be present and authenticated before the gate starts.
Checking that guarantee requires reading those bodies. A commitment authenticates
bytes when obtained; it cannot establish that unread bytes are still available.
This change therefore improves the constant cost while leaving startup and the
verification part of rollover proportional to lifetime journal data. The SQLite
receipt index and cold storage also continue growing with lifetime acknowledgments.

There are two coherent paths to a bounded normal restart:

1. **Keep the complete archive, verify historical data on demand.** Extend the
   independently protected local checkpoint to commit a canonical active-state
   capsule: the gate policy and native branch, lifetime counters and high-water
   root, exact active receipts and dependency closure, deterministic carry queue,
   and the indexed archive manifest. Restart would authenticate that capsule and
   a bounded append tail. Historical files would be checked on access and by a
   background scrub. An authenticated read failure would stop any operation
   needing that evidence. This retains cryptographic authentication but explicitly
   changes the promise that *every historical file is available before startup*.

2. **Prune historical evidence after a retained recovery horizon.** Use the same
   authenticated capsule and retain enough evidence for the active TIDES state,
   acknowledged carry-forward work and a documented reorganization horizon.
   Crossing that horizon must withdraw mining and recover/verify missing history;
   it must never silently treat missing receipts as paid or discard their
   accountability. A fixed number of blocks alone does not prove an eight-block
   *work* window or its dependency closure has been retained.

Either path needs an atomic migration and checkpoint publisher, crash/rollback
tests, exact duplicate-receipt behavior after compaction, archive authentication
paths, dependency-closure bounds, and reorganization recovery tests before it can
replace the present full scan. Neither is implemented by this optimization. The
native snapshot archive already has a separate bounded index-startup mechanism;
that does not automatically establish the mining gate's acknowledged-work state.
