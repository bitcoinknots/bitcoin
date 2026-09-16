# Native collector benchmark for DATUM cadence

This benchmark compares a caller that rebuilds a settlement job after every
acknowledged share with the `HashJobScheduler` introduced in commit
`33a38366c6cc818ba53b8122979235f34a658628`. The old gate's freshness predicate
did not itself request jobs; rebuilding on every acknowledgment is the explicit
comparison policy used here.

## Measured results

Both paired captures passed. Every arm admitted all 100 proofs in its final
native block, paid the exact expected coinbase outputs and reopened its journal
with all receipts confirmed. The timed inputs were one proof per second and
small, precomputed templates. These are measurements of the collecting gate,
not a mainnet qualification or a mining-revenue comparison.

| Metric | Per-ACK, run first | DATUM, run second | DATUM, run first | Per-ACK, run second |
| --- | ---: | ---: | ---: | ---: |
| Replacement jobs | 100 | 3 | 3 | 100 |
| Total measured CPU seconds | 582.73 | 33.93 | 34.00 | 582.21 |
| Busy-operation wall seconds | 584.30 | 33.97 | 34.06 | 583.75 |
| Paced wall seconds through final dispatch | 589.18 | 147.41 | 147.38 | 588.66 |
| Offer-due to ACK p95, seconds | 422.11 | 5.08 | 5.04 | 421.57 |
| ACK service p95, milliseconds | 55.70 | 86.50 | 86.33 | 55.11 |
| ACK to first job inclusion p95, seconds | 11.80 | 52.11 | 52.12 | 11.80 |
| Slowest fresh-job operation, seconds | 12.39 | 12.42 | 12.44 | 12.42 |

There is one initial job in addition to the replacement counts. Across the two
captures, cadence reduces total measured CPU by **94.16–94.18%**, busy-operation
wall time by **94.17–94.19%**, and paced wall time by **74.96–74.98%**. It avoids
**97% of replacements**. Those ranges describe two observed pairs, not confidence
intervals. Separately subtracting JSON byte-accounting CPU changes the CPU
reduction to 94.17–94.18%, so that instrumentation does not explain the result.

The same body counts and RPC counts appear in both captures:

| Work or retained data | Per-ACK | DATUM | Reduction |
| --- | ---: | ---: | ---: |
| Published template plus snapshot body bytes | 5,844,831 | 257,038 | 95.60% |
| Native RPC calls in timed arm | 16,341 | 3,332 | 79.61% |
| Reconstructed RPC JSON bytes, approximate | 86.01 MB | 6.02 MB | 93.00% |
| Final journal bytes recorded in its authenticated head | 6,548,879 | 932,180 | 85.77% |

Actual logical gate-file growth was 7.56–7.66 MB versus 2.76–2.77 MB; native
snapshot-directory growth was approximately 5.00 MB versus 0.50 MB. These include
storage overhead and differ from authenticated journal payload accounting.
Populated journal reopening took 2.07–2.09 seconds versus 0.61–0.62 seconds.
Neither comparison exercises long-lived cold rollover.

## What the measurements identify

The avoided cost is predominantly Python job processing. In the first baseline,
the driver consumed 542.71 CPU-seconds, the native backend 29.35 and signing
children 10.67. Fresh-job operations accounted for 580.11 of 584.30 busy wall
seconds; accepting the 100 shares itself took 4.19 seconds. JSON re-encoding used
only 0.27 driver CPU-seconds. These counters identify the broad bottleneck, but
do not attribute Python time to individual functions without a profiler.

Fewer builds do not make the remaining builds faster. A fresh job still takes
up to **12.44 seconds** and blocks this owner's share processing while it runs.
The DATUM arm's offer-to-ACK p95 is therefore still about **5 seconds**, despite
individual receive calls having p95 below 87 milliseconds. Reducing preparation
cost and providing responsive block-event/transport cancellation remain the
first latency gates. Moving an existing sole-owner gate into an arbitrary
thread pool is not a valid fix.

Publication delay is also real: the maximum ACK-to-job delay is **52.4 seconds**
in these captures. The 40-second interval starts after the previous publication;
the next job must then be built. This is not a 40-second delivery guarantee or a
measurement of time until payment. Jobs keep their exact issued cutoffs and
later work enters a subsequent job.

All four idle probes published zero extra jobs. Fifty context checks took
approximately 87–93 milliseconds and exactly 300 RPCs: roughly **1.8 ms and six
RPCs per poll** here. That is another workload to measure across many gateways,
larger openings and slower RPC links, not a constant-cost assumption.

The [summary](../contrib/sharepool/results/cadence-benchmark-summary.json) contains
both paired measurements. The [verification manifest](../contrib/sharepool/results/cadence-benchmark-verification.json)
checks raw artifacts, exact sources, binaries and preserved earlier evidence.

## Workload and measurement boundaries

Each paired capture prepares 100 real signed origins, 100 different payout
identities and 100 different cumulative transaction sets. One actual regtest
proof is solved against each authorized origin. The origin bodies range from
432 to 10,233 bytes; these small, simple-script transactions are not a full-size
production block workload. Two native backends start from
the same parent, receive the exact same transactions and origin evidence, and
restart before the timed arms. They remain disconnected during measurement and
settlement. The collecting gates begin with identical evidence and zero receipts.

Both arms receive the same ordered proofs at fixed one-second due offsets using
real monotonic time. Slow service accumulates a client queue; it does not move
the due offsets. Both publish an initial empty-receipt job. The eager caller then
rebuilds after each acknowledgment. The DATUM arm polls after acknowledgments
and at its ordinary 40-second deadlines. After the last receipt it waits for the
next normal deadline if the active job still omits any of those receipts.

The runs use opposite arm orders on fresh disposable test directories. This
reduces one ordering concern, but does not control OS file caches, thermals or
other host load. The existing native binary is a Debug build. Two captures do
not establish a confidence interval or a saturation limit.

Source-template preparation, proof solving and initial collector reopening are
outside the timed comparison and reported separately. The measured operation
cost includes share validation, durable acknowledgment, job construction,
signing, authorization and publication to the local native backend. Every fresh
job uses the same full-operation timing boundary in both arms. This is one
collecting scheduler for 100 miner origins, not 100 concurrent gateways or
100 full validating nodes.

CPU is recorded separately for the Python driver, signing children and the
native backend. Driver CPU includes instrumentation. The cost of reconstructing
JSON byte counters is measured separately, allowing an approximate subtraction.
The sum of process CPU seconds is not elapsed wall time. Paced wall time includes
deliberate waiting for the next published cutoff; busy-operation wall time does
not include that wait.

Publication byte counts are exact authorized template and snapshot body lengths
passed to a local callback. RPC byte counts reconstruct JSON method/parameters
and results, excluding HTTP, authentication, envelope IDs and transport framing.
Neither quantity measures WAN relay or a deployed Stratum connection. RSS is
sampled at boundaries, not continuously; disk sizes are logical lengths rather
than physical allocation.

## Correctness and additional probes

Each arm must preserve its initially issued bytes, acknowledge every proof,
eventually publish all 100 proof IDs, and settle a real native block with exact
coinbase payouts checked by an independent rational-arithmetic oracle. Stored
block bytes, native chain verification, all `confirmed_admitted` receipt states,
zero eligible backlog and zero expired/unknown receipts are checked. Populated
collector reopening must retain the exact journal head and confirmed receipts.

A separate 50-operation idle probe measures repeated context checks after final
publication. Accepted captures must report zero extra publications during that
probe and a publication-trace length equal to the timed job count. Otherwise
the probe has crossed a refresh deadline and cannot be treated as idle cost.
Reopening is a separate finite-history measurement; no cold archive rollover
or lifetime startup scaling claim follows from it.

Native height and block time remain fixed while the real offer clock advances.
There are no timed block arrivals, reorgs or proof-age expirations in this
experiment. Refreshed collector jobs are actually built and validated, but the
precomputed incoming proofs do not reference those new jobs. Recursive
later-job dependency growth and live feedback are therefore outside the test.
The final blocks are deliberately solved after all work appears; acknowledgment
to publication measures waiting for inclusion eligibility, not payout latency,
reduced orphan losses or additional mining revenue.

The [harness](../test/functional/feature_sharepool_hash_cadence_benchmark.py) is in
the extended functional-test list. A 10-miner, five-second preflight precedes
the two 100-miner captures. Exact commands and results are retained in
[the comparison report](../contrib/sharepool/results/cadence-benchmark-summary.json).

## Remaining production gates

The [source audit](sharepool-production-gate-audit.md) records the remaining
integration, latency, admission, variance, payout-recipient and archive gates.
This experiment does not exercise timed source-template churn, new-block
interruption during construction, a full-size production mempool, later-round
history, multiple concurrent collectors, WAN recovery or physical mining
transport. Runtime and consensus code are unchanged by this benchmark.
