# Archive startup, payout fitting and production capacity measurements

This pass fixes archive startup scaling and a reproduced payout-sizing failure,
adds a bounded parsing optimization, and measures repeated native admission and
the payout-variance/capacity tradeoff. It does **not** establish a production
share difficulty or mainnet readiness. V6 remains rules revision 2 with SHIFT10,
separate pools, an eight-block-work window and proportional clipping of work
admitted at the same native height. The complete external snapshot is still
committed by a flat hash in `m_mm_rhs`.

The source base is `5d3194f1c110d4aebd218de8de7d64a01e7d3662`. The
[verification manifest](../contrib/sharepool/results/capacity-startup-verification.json)
records final source and binary hashes, test commands and artifact hashes.
Earlier reports remain evidence for their own recorded revisions.

## Implemented fixes

**Archive restart no longer authenticates every historical payload up front.**
An atomic, versioned checkpoint binds the profile, rules hash and aggregate
index counters. Ordinary restart reads that checkpoint; payload retrieval still
authenticates the actual bytes. Legacy migration and explicit repair commit
bounded batches with a durable cursor, so a crash, shutdown or quota failure
does not restart the entire scan. Inventory stays metadata-only: LevelDB
existence checks would fetch full values. Local index damage and missing bytes
remain local availability failures, never consensus-invalidity findings.
Archive traversals require exact keys within their prefix. A malformed short or
trailing-byte key fails local recovery explicitly instead of ending the scan
early and committing incomplete counters as ready.
See [startup and repair](sharepool-archive-startup.md).

**The gate now reserves the real historical payout recipient space.** The first
100-miner workload acknowledged 300 proofs, then failed because batching sized
one placeholder output while native preparation added many recipients. A new
bounded native query supplies the historical output size, including recipients
rounded to zero. The gate adds selected own-pool recipients and vector-prefix
growth, and checks both snapshot and dependency budgets before signing.
Tip/difficulty binding prevents using a reservation in a changed context.
The conservative bound can refuse a locally small budget that a more expensive
exact fit might satisfy; receipts remain durable. See
[payout reservation](sharepool-payout-reservation.md).

**Repeated journal parsing is bounded and reused safely.** A 4,096-entry cache
stores only immutable canonical identity/height/parent metadata. Every lookup
hashes fresh actual bytes; journal reads still compare stored metadata, and
native validation and dispatch authorization still run. Raw bodies and native
validity are not cached by this optimization. Corruption, failed parsing,
eviction and native-rejection tests cover the boundary.

## Native capacity evidence

The new [capacity harness](sharepool-capacity-calibration.md) uses two native
regtest nodes and 100 logical miners with separate signers and durable gates.
Across three epochs it builds 300 distinct fee-paying transaction sets and
collects 900 actual native proofs. Independent rational accounting checks the
winning coinbase outputs; reconnection checks native follower validation and
recovery into a new gate.

The [quiet paced run](../contrib/sharepool/results/capacity-native-100-interleaved-quiet.json)
passed: **900/900 proofs admitted, nine blocks, zero expired work and zero final
backlog**, in 689.45 seconds overall. The source received scheduled offers at
two per second and published a block after each 100 durable acknowledgements.
Ingress lasted 152.87, 155.75 and 155.83 seconds for the three 300-proof epochs.
Recorded client queues peaked at 33, 10 and 11 and cleared; initial reconnection
caused the largest pause. The fixed local snapshot policy was 154,350 bytes.

| Measured operation | Samples | Median | 95th percentile | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Source proof admission | 900 | 225 ms | 336 ms | 363 ms |
| Settlement job creation | 9 | 2.92 s | 3.84 s | 3.84 s |
| Native `submitblock` | 9 | 343 ms | 454 ms | 454 ms |

These are observations, not latency guarantees. Preparing fresh origins paused
offers for 20.3, 64.1 and 69.0 seconds before each ingress period; the separate
follower-gate recovery took 50.2 seconds. The controlled approximately 50-second
publication cadence differs from random Bitcoin block intervals. This establishes
finite queue-service and settlement behavior, not two proofs per second of
guaranteed mainnet admission or uninterrupted long-duration stability.

The [corrected burst run](../contrib/sharepool/results/capacity-native-100-small.json)
also admitted 900/900 proofs over eight blocks without expiry. It used an earlier
native archive-read implementation and the pre-cache Python helper while other
CPU work ran. Its 928.47-second time is not an isolated before/after performance
comparison. The original failed run is retained alongside it; partial progress
has not been relabeled as a pass.

The [larger-body run](../contrib/sharepool/results/capacity-native-100-large.json)
adds 64 ordinary outputs per transaction. Its 100 origins range from 3,184 to
285,433 bytes, totaling 14.43 MB of expanded bodies. All 300 proofs settled over
three blocks with exact payouts, no expiry and no final backlog under a fixed
360,900-byte snapshot policy. The run took 438.92 seconds with concurrent CPU
model work; its 17.73-second maximum settlement-job time has only three samples.
This checks a larger body dimension, not 100 independent full-size blocks or
an isolated throughput ceiling.

## Archive and regression evidence

The final native build passed **145 C++ SharePool cases and 141,630 assertions**,
including the archive/store tests. A 65,540-small-record fixture verifies the
zero-scan restart path and resumable index work structurally. It is not a
multi-GiB archive or a fixture containing 65,540 valid mining proofs.

Seven native scenarios passed: v4 builder, v5 ledger, v6 payouts/rejections,
one-satoshi and zero-subsidy histories, software-miner transport, and archive
recovery. The archive scenario rebuilds 11 signed snapshots with unchanged
counts and charges; normal restart scans zero records and bytes. Its additional
1,030 opaque transport records test pagination only. Quota changes, repair,
restart and reindex checks passed. The software-miner transport was repeated
after the final Python cache change and passed again.

The final Python regression passed **135 hash/gate tests, 74 TIDES/model tests
and six capacity-metric tests**. The seven-scenario native regression preceded
the Python metadata cache; the paced and larger-body capacity runs and repeated
software-miner transport include it. Those native runs use their recorded binary
from before the final malformed-key traversal fix. That fix receives a new C++
regression and native archive rerun; ordinary capacity timings are not rewritten
as measurements of a later build. A final sampler cleanup fix records failed
process sampling without skipping report/fixture cleanup; its mocked unit check
does not alter recorded passing measurements. No physical miner was rerouted
during this pass; the earlier Goldshell capture remains separate.

## Variance and the remaining capacity constraint

The [variance analysis](sharepool-variance-contract.md) compares cumulative
rewards on coupled proof/block traces against both an arrival-ordered SHIFT14
reference and the stationary infinitely dense limit on the same pool blocks.
It preserves overlapping-window dependence, issued-job cutoff and block luck.
The 128-trace-per-case labeled sweep evaluates eleven scenarios. These are
standard-library CPU simulations, not GPU mining or native validation throughput.

The proposed engineering criteria are at most 10% excess payout variance and a
paired mean difference within 2% of expected rewards. Those criteria have not
been accepted as a universal regular-pool definition or activated as rules.
Finite SHIFT14 closely matches the equally dense arrival reference, but that
alone cannot establish negligible sampling variance for arbitrarily small miners.
The [conditional analysis](../contrib/sharepool/results/tides-v6-conditional-variance.json)
integrates recipient labels on each work trace to separate sampling variance
from accidental labeled covariance. Its 64 traces per case support the proposed
variance bound for a miner with 0.1% of its pool at SHIFT14:

| Pool fraction of network | SHIFT12 variance ratio | SHIFT14 ratio (95% interval) |
| --- | ---: | ---: |
| 10% | 1.205 | 1.051 (1.035–1.087) |
| 1% | 1.235 | 1.059 (1.042–1.088) |
| 0.1% | 1.216 | 1.054 (1.043–1.075) |

These ratios compare total cumulative payout variance with the ideal dense split
on the same pool blocks, before integer rounding. All SHIFT12 intervals exceed
the 1.10 target for this miner size. Even SHIFT14 fails for the tested miner with
0.01% of its pool. Stationary, recipient-neutral difficulty/admission, complete
work reception and uncongested modeled capacity are essential assumptions.
Changing hashrates and adversarial work selection are not certified by these
numbers. The statistical sweep uses the fixed target `0x17034219`; it does not
certify every target-rounding position or a retarget trajectory.
The second calculation uses a subset of the labeled sweep's traces,
not an independent replication whose sample count can be added to the first.
For that 0.1%-of-pool miner at SHIFT14, the labeled paired-mean 95% intervals
also lie within the proposed 2% tolerance in all three pools. Conditional mean
allocation error is zero under the model before flooring; satoshi-rounding
bounds are reported separately from the pre-rounding variance estimate.

The capacity constraint is independent of that statistical comparison. At the
illustrative target `0x17034219`, SHIFT14 generates about 20,114 proofs per
expected native block; target rounding can bring its mean density close to
32,768. The current 512 MiB expanded-template budget allows only 134 full
4,000,000-byte origins, even if their non-coinbase transactions share wire
encoding. Sixteen proofs per such origin still exceed that budget by a wide
margin. Completely disjoint transactions can hit the wire bound earlier.

In the optimistic 134-origin global overload control, only 0.67% of eligible
SHIFT14 proofs were admitted; 87.16% expired and 12.17% remained pending at the
end. Retaining an acknowledgement cannot create admission capacity before the
existing proof-age deadline. An easier global difficulty is therefore not
activated by this pass.

Production needs a declared workload covering miner size, origin reuse, body
size and job churn, plus native resource headroom under random block intervals.
Shared transaction-sequence storage and lazy origin reconstruction are possible
follow-up designs, but they require bounded native validation and cannot make
arbitrarily many disjoint full blocks cost-free. Long-duration storage/initial
sync measurements, slow disks, WAN partitions, censorship/data availability and
reviewed public activation remain in the [gap register](sharepool-production-gaps.md).
