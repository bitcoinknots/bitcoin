# Finite native capacity calibration

`test/functional/feature_sharepool_hash_capacity.py` measures a bounded workload
against two disposable native regtest nodes. It repeatedly creates distinct,
fee-paying transaction sets, builds and externally signs each exact native job,
authorizes it through a durable gate, and checks proofs against its complete
origin. Native blocks admit the work, and an independent rational-arithmetic
oracle verifies the actual coinbase payouts. The settlement commitment remains
the flat hash of the complete external snapshot.

The default workload has 100 logical miners, three fresh-origin epochs and
three proofs per origin: 300 distinct native origins and 900 native proofs.
Each epoch spends a separate funding output for each miner. Transactions enter
the mempool one at a time, producing 100 different transaction sets and Merkle
roots. The next epoch spends those transactions' surviving outputs after the
previous epoch has drained. These are actual consensus-valid transaction
bodies, not opaque snapshot bytes or invented PoW counters. There are two
native nodes, not 100 native nodes; the 100 logical miners each have their own
external signer and durable local gate.

## Reproduce

Use a build containing the experimental v6 profile and its signer. For example:

```sh
python3 test/functional/feature_sharepool_hash_capacity.py \
  --configfile=/path/to/build/test/config.ini \
  --tmpdir=/private/tmp/sharepool-capacity-small \
  --portseed=1000 --miners=100 --epochs=3 --shares-per-origin=3 \
  --results=/private/tmp/sharepool-capacity-small.json --nocleanup
```

Use a fresh directory and unused port seed for each run. `--padding-outputs=64`
adds 64 ordinary positive P2WSH outputs to every transaction; its fee increases
accordingly. This produces a larger, still native-valid template case without
changing script policy. `--miners=10` provides a smaller distinct-origin case;
`--shares-per-origin` controls proof reuse per exact origin. `--epochs` is bounded
at 10, miners at 100, proofs per origin at 16 and padding outputs at 128. A
runtime deadline is checked between bounded operations; this is not an
unbounded stress test, public-network traffic test or physical-miner reroute.

The collector's byte policy is fixed when its durable journal opens. By default
it is 75% of the first epoch's complete proposal size, deliberately below that
batch. Each epoch offers a finite precomputed burst, waits for native validation
and durable acknowledgements, then stops offering while native blocks drain
the selected prefix. The report separately records the client queue waiting for
gate service and acknowledged work waiting for canonical admission.

`--offer-interval-ms` replaces the instantaneous burst with scheduled offers.
The driver still services one RPC at a time. A late operation leaves subsequent
scheduled offers in the measured client queue; it does not invent additional
RPC concurrency. Reported acknowledgements per second are observations of this
driver, not a concurrent saturation maximum or an inferred mining hashrate.
The driver also deliberately schedules native settlement publication. At easy
regtest difficulty some qualifying proof headers can already satisfy the native
block target; they are not all immediately published. This is a validation and
queue-service workload, not an honest-mining block-arrival or payout-luck model.

`--settle-every=100` changes a 300-proof epoch into interleaved ingress: the gate
publishes a settlement after ACKs 100, 200 and 300. The next offers remain queued
and are actually validated and acknowledged after the previous publication.
The option requires exactly three publication points per epoch. Each subsequent
epoch constructs fresh current-parent jobs, preserving the real admission-age
bound. The same gate owner thread services offers and builds settlement jobs;
there is no unsafe concurrent journal access.

For paced interleaving, select `--offer-interval-ms` from measured service times
and state that choice in the evidence. The report records lateness relative to
each scheduled offer, client queue before/after settlement, future offers not yet
due and offers still unacknowledged. Job/origin preparation occurs before that
epoch's measured ingress period. Consequently this remains a finite repeated
stream with explicit preparation pauses, not proof of indefinite stability under
continuous arrivals during every template-refresh operation.

## What is checked and measured

- Offered, acknowledged and canonically admitted proof counts, with bounded
  receipt pages recording expiry or unresolved history instead of assumed pay.
- Initial deferred work, selected native admissions and remaining backlog at
  each block, under the same pinned byte policy throughout the run.
- p50, p95 and p99 wall time for gate admission, origin jobs, settlement jobs,
  individual native RPC methods, and follower block/snapshot availability.
  Percentiles use the nearest observed rank; their sample counts are included.
- Five-second samples of native-node and driver RSS, cumulative `ps` CPU time,
  and logical file lengths for both node directories and gate journals.
  Native snapshot-store subdirectories are also reported separately; they are
  subsets of the node totals and should not be added to them. Whole-node totals
  include the functional test's verbose debug logs and ordinary block files.
  These are sampled RSS maxima, not exact peak RSS, physical disk allocation or
  CPU accounting for every short-lived external signer process.
- Actual total native P2P bytes sent/received, including ordinary Bitcoin
  traffic. These totals do not isolate sharepool message framing.
- Disconnection during the first origin burst, reconnection for the first
  settlement, full native follower validation, and bounded inventory ingestion
  into a fresh follower gate. Stored bytes alone do not count as gate ACKs.
- Exact native coinbase payouts for each block, no duplicate proof admission,
  all offered work admitted before its age deadline, empty final backlog and
  full chain verification on both nodes.

The report stores the exact command, host platform, rule hash, binary hashes,
harness hash and relevant Python-source hashes. A failed workload is retained
as a failed report, not relabeled as passing because earlier phases succeeded.
Use `--host-load=concurrent` when other build, simulation or test work is active.
After that work stops, repeat a passing envelope with `--host-load=quiescent`
for more comparable timing. This is an operator declaration; the harness does
not certify machine isolation or control other applications.

## Interpreting a supported envelope

A passing finite run establishes only its recorded miner/origin count, template
sizes, proof burst, history length, byte policy and local hardware behavior.
Larger historical payout sets can change later template size and service cost;
one successful initial batch is insufficient. The origin-age admission bound
continues to apply during overload. Deterministic carry preserves evidence but
cannot manufacture enough block capacity to admit unlimited work before expiry.

Payout reservation uses the complete native historical recipient set plus
selected new recipients as a conservative upper bound. A recipient present in
both may be reserved twice. If historical payouts alone exceed a local byte
policy, the gate may refuse it even when enough new work could evict that history
from the window. This is a local policy liveness tradeoff; it preserves the byte
bound and does not change consensus payouts or silently discard receipts.

Capacity planning must compare sustained offered work and bytes with measured
service and admission rates, including tail latency and the workload's actual
origin reuse. These runs do not establish WAN delivery, long-duration leak
freedom, competing-node resource fairness, production proof difficulty or a
mainnet activation plan. The production variance calculation must use its own
explicit sampling target rather than treating these easy regtest proofs as
measured mainnet hashrate.

## Recorded native results

The first 100-miner calibration exposed a fitting bug: local v6 batching reserved
one placeholder payout while native preparation produced many recipient
outputs. All 300 proofs had been acknowledged, but the first prepared snapshot
exceeded the pinned local budget. Native historical payout reservation now
includes zero-rounded recipients, selected new recipient slots and vector-count
growth. The original 154,350-byte policy subsequently drained all 900 proofs
across three epochs without expiry. A bounded gate cache also removes repeated
canonical-metadata decoding while still reading and authenticating each body;
it stores neither native validity nor mutable decoded payout objects.

| Evidence | Workload | Result and interpretation |
| --- | --- | --- |
| [Original fitting failure](../contrib/sharepool/results/capacity-native-100-small-before-payout-budget-fix.json) | 100 origins, 300 ACKs | Failed before the first settlement; retained as failed evidence. |
| [Corrected, contended burst](../contrib/sharepool/results/capacity-native-100-small.json) | 300 origins, 900 proofs, 3 epochs | Passed in 928.47s; 8 blocks (2/3/3), zero expired, no remaining backlog. Concurrent builds/tests/simulation and a pre-final availability implementation make timing diagnostic only. |
| [Quiet paced ingress](../contrib/sharepool/results/capacity-native-100-interleaved-quiet.json) | 300 origins, 900 proofs, 3 epochs at scheduled 2 proofs/s | Passed in 689.45s total; 9 controlled blocks, all 900 admitted, zero expired. Measured native binary `657c66e8…` and bounded metadata cache; other agents' CPU-heavy work paused. |
| [Larger-body case](../contrib/sharepool/results/capacity-native-100-large.json) | 100 origins, 300 proofs, 64 padding outputs per transaction | Passed in 438.92s; 3 blocks, all 300 admitted, zero expired, no remaining backlog. Concurrent simulation/build work; one burst-and-drain epoch with bodies up to 285,433 bytes. |

The quiet run used 500ms scheduled offers and a settlement after every 100 ACKs.
That is a **controlled nominal 50-second publication cadence**, with construction
and peer-delivery pauses. It is distinct from random roughly 600-second mainnet
blocks. These observations establish source-validation service and accounting
for the declared workload; they do **not** establish a 2-proofs/s mainnet
canonical-admission guarantee under a 154KB policy.

| Quiet measurement | p50 | p95 | p99 | Samples |
| --- | ---: | ---: | ---: | ---: |
| Source proof receive and durable ACK | 225ms | 336ms | 344ms | 900 |
| Exact origin job build/sign/authorize | 487ms | 546ms | 579ms | 300 |
| Settlement job build/sign/authorize | 2.924s | 3.845s | 3.845s | 9 |
| Native submitblock RPC | 343ms | 454ms | 454ms | 9 |

The three measured ingress windows lasted 152.87, 155.75 and 155.83 seconds.
Initial peer recovery caused a recorded queue of 33 offers; later epochs peaked
at recorded queues of 10 and 11. At subsequent publication entry the queues were
0–2 offers, and each epoch ended with zero queued or unadmitted work. Median
scheduler lateness stayed about 10ms. The first epoch's p95/p99 lateness was
9.75/14.81s because of the initial recovery pause; later epochs' p95 lateness was
2.78/2.97s. These are observed finite queue traces, not a claim of indefinitely
bounded delay.

Preparation before those ingress windows took 20.33, 64.14 and 69.05 seconds.
The separately measured first-epoch follower-gate import took 50.20 seconds.
No new offers were scheduled during these preparation/recovery periods. Native
node sampled RSS maxima were 84.3 and 76.8 MiB; driver maximum was 159.5 MiB.
The report contains CPU, native P2P traffic and disk-growth details, including
snapshot-store growth separately from verbose functional-test logs.

The larger-body run used a separate fixed 360,900-byte snapshot policy. Its
100 native bodies ranged from 3,184 to 285,433 serialized bytes, with native
weights up to 1,140,124 units. The initial batch deferred 87 acknowledged proofs;
three blocks admitted 213, 81 and 6, preserving all 300 before expiry. The largest
prepared snapshot was 357,690 bytes, within both its conservative reservation
and the pinned policy. Source ACK p50/p95/p99 was 252/484/509ms; the three
settlement jobs took 2.70–17.73s, and full follower-gate recovery took 123.04s.
This run overlapped simulation and build work, so it establishes the tested
larger-body accounting and drainage, not an isolated throughput comparison.

The candidate denser share profile can require approximately 27–55 network
proofs/s depending on work rounding. A passing 2-proofs/s local service case
does not establish capacity for that global demand, larger origins, WAN peers,
random block timing or continuous traffic during all job-refresh operations.
The before/after runs also change host contention and code, so their timing
differences must not be attributed solely to one optimization.

The measured `657c66e8…` binary predates the later malformed-LevelDB-key
traversal hardening. These capacity fixtures used ordinary valid archive keys;
the malformed-key behavior is checked by separate archive regressions. Keep the
recorded binary/source hashes when comparing these runs with subsequent builds.

The final metrics helper also handles sampling failure during shutdown or before
its background thread starts, so such a failure cannot prevent cleanup and
saving the test result. Its six unit tests cover those failure paths. The native
run reports retain the helper hashes actually used during measurement; that
later change affects failure cleanup only, not the successful sampling path or
any recorded metric.
