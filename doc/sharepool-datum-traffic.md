# DATUM cadence and payload planning

The baseline is one transaction-template stream per gateway, refreshed every
40 seconds, with an early refresh when the native tip changes. The interval is
configurable from 5 to 120 seconds. It does not issue a new transaction template
for every mempool transaction or multiply that stream by the number of ASIC
clients using different extranonces. These defaults follow the upstream DATUM
[configuration](https://github.com/OCEAN-xyz/datum_gateway/blob/master/src/datum_conf.c)
and [template loop](https://github.com/OCEAN-xyz/datum_gateway/blob/master/src/datum_blocktemplates.c)
consulted on 2026-09-13. The upstream links follow `master`, which can change.

The local scheduler's refresh deadline starts after a successful job publication.
Synchronous preparation therefore adds time to the renewal interval. The model
below assumes negligible preparation time; it measures payload demand, not whether
our present implementation can meet the requested cadence. A changed native tip
still requires fresh validation before a new job can be published. Scheduled
refresh does not alter consensus, share difficulty, evidence availability or the
admission deadline for work.

## Preserved measurements and assumptions

The [encoder evidence](../contrib/sharepool/results/datum-traffic-encoder.json)
is an unchanged copy of the earlier measurement against commit
`6e3f869a46f7f174330eb248ceec5dbb61150c62`. It uses the 3,546 noncoinbase transactions
of mainnet block
[`00000000000000000002343c98a0a0fe829590dd95565138f56ac940bf36f940`](https://mempool.space/block/00000000000000000002343c98a0a0fe829590dd95565138f56ac940bf36f940).
Every synthetic job has a unique coinbase and 100 P2WPKH payout outputs. Each job
contributes one synthetic proof record. The measurements are:

| Payload | Serialized bytes |
| --- | ---: |
| One expanded origin template | 1,644,881 |
| One-job snapshot | 1,664,368 |
| Shared 100-job snapshot | 3,056,407 |

These are actual encoder lengths, not authenticated or proof-of-work-valid jobs,
observed mainnet traffic, or a throughput benchmark. All noncoinbase transactions
are identical across jobs in a batch. The 100 recipients are fixed fixture
geometry, not derived from the number of ASICs in the scenarios.

Grouping multiple ASICs behind one template stream assumes they share that
gateway's authorized owner and payout identity. Separately accountable owners
or payout identities can require separate authorized jobs even when their
transaction sets are shared. Count those separate job producers as gateways
in this model; the count is a logical workload input, not necessarily a count
of physical computers.

An independent gateway can choose different transactions. Such divergence reduces
the assumed sharing. Independently timed gateways also need not produce jobs
together, so fully occupied 100-job batches are an optimistic planning scenario.
There is no assumed transaction reuse between different snapshot versions.
Residual gateways outside complete 100-job batches are conservatively charged as
separate measured one-job snapshots; this avoids inventing an unmeasured partial
batch size. The cost consequently has discontinuities at batch boundaries.

## Forty-second traffic scenario

With a Poisson native-block rate of `lambda = 1 / 600` per second and a timer
`T = 40` seconds that resets after each refresh, the steady-state refresh rate is
`lambda / (1 - exp(-lambda * T))`. This gives about **2,232.80 refreshes per gateway
per day**. It is a steady-state estimate, not an exact count starting from a cold
gateway. For simple conservative planning, adding 2,160 timer refreshes and 144
expected block arrivals gives **2,304 refreshes/day**. This allowance double-counts
some timer resets; it is not a hard upper bound on random block arrivals.

The following table uses that conservative additive allowance and counts one
received copy over 24 hours. Units are decimal GB and Mbps.

| Gateways | ASICs per gateway | Total ASICs | Changed jobs/s | Shared snapshot GB/day | Shared snapshot Mbps | Separate origin GB/day |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 100 | 100 | 0.027 | 3.835 | 0.355 | 3.790 |
| 100 | 1 | 100 | 2.667 | 7.042 | 0.652 | 378.981 |
| 100 | 10 | 1,000 | 2.667 | 7.042 | 0.652 | 378.981 |
| 1,000 | 1 | 1,000 | 26.667 | 70.420 | 6.520 | 3,789.806 |

The first shared row uses the one-job snapshot; the others use full 100-job
batches. Separate origin sizes omit snapshot evidence and framing, whereas shared
snapshot sizes include their fixture's one proof per job. These columns are
different payload scenarios, not two currently interchangeable relay modes.

Under the renewal expectation rather than the allowance, the 100-gateway shared
case is **6.824 GB/day at 0.632 Mbps**, and separate origins are **367.269 GB/day at
34.006 Mbps**. Serving an entire stream to eight peers would add eight times its
incoming payload rate in outbound traffic. Actual request patterns determine
replication; block notifications also synchronize bursts that averages conceal.

More ASIC clients increase share submissions and can increase unique payout
recipients without increasing the gateway's transaction-template refresh rate.
The model separately reports an illustrative eight submissions per minute per
client. At 100 clients that is 1,152,000 submissions/day, and at 1,000 clients it
is 11,520,000/day. This illustrates DATUM-style variable-difficulty client traffic;
it does **not** change the active SHIFT10 proof difficulty or predict eligible
proof arrivals. Additional share records are excluded from the template payload
table. The one synthetic proof per job in the measurement is not a production
submission-rate assumption.

## What these numbers do not establish

The current native evidence channel relays full canonical snapshots containing
selected origin jobs. A local template refresh does not cause every unworked job
to be broadcast to every node. Live incremental template transport, cross-version
transaction reuse, actual job batching and share submission handling must be
measured separately. Dependencies, prior history, additional share records,
transport framing, duplicate requests and outbound relay are excluded here.

Neither a NIC speed nor this mean update rate proves that a node can keep up.
Native validation, preparation latency, durable writes, burst recovery and archive
startup still need sustained measurements with representative distinct transaction
sets. These projections do not assign a CPU/RAM minimum or a retention budget.
Settlement pruning cannot remove data still needed for the active payout window,
dependencies, reorganizations or historical validation; retaining only a hash
cannot reconstruct its opening.

The [reproducible report](../contrib/sharepool/results/datum-traffic-40s.json)
records source hashes, assumptions, both refresh-rate treatments and gateway/ASIC
comparisons. To regenerate it from the repository root:

```sh
python3 -B contrib/sharepool/datum_traffic_model.py --output /tmp/datum-traffic.json
python3 -B -m unittest discover -s contrib/sharepool -p test_datum_traffic_model.py
```

The eleven tests check exact sample lengths, independent gateway/client scaling,
partial-batch accounting, arithmetic, interval limits and the renewal expression
against numerical integration. Extreme numeric inputs that would overflow the
reported rates or totals are rejected. These are model tests, not native node
capacity tests.
