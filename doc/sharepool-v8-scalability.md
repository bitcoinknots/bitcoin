# V8 cadence and scalability follow-up

The gateway now targets **10 shares per minute per miner**, a six-second mean
interval. The default minimum observation window is 24 seconds; adjustments
take effect at normal job preparation. Initial work remains explicitly assigned
per miner, and old jobs keep their original target and credited work.

For 100 miners the intended aggregate is 16.67 proofs/s, or 1.44 million proofs
per day. These are workload counts, not measured mainnet traffic or capacity.
Template updates, transaction sizes, replication and settlement add separate
costs. The native profile remains opt-in regtest with unchanged v8 consensus
rules and resource limits.

## Changes

- The gateway retains bounded immutable origin facts keyed by the complete
  body digest, length and profile. Each access still reads current evidence;
  witness changes cannot reuse another job's facts. The cache holds at most
  1 MiB of charged objects and 1,024 entries per gate, not full template bodies
  or native validity decisions. This is not a service-wide RSS bound.
- Native validation prepares an opening's owner digest once per validation
  walk, after verifying its complete canonical snapshot hash and dependency
  budgets. Repeated references reuse that digest. This new owner-digest memo
  retains no authorization or missing-data verdict across validation calls.
- Share receipt attempts native validation before republishing retained
  snapshots. Only an explicit missing-data response triggers bounded recovery
  and one retry. Non-missing rejection cannot trigger that recovery or an ACK.
- Explicit template registration now retains the fully validated native origin
  before the first proof arrives, eliminating predictable missing-origin recovery.
  Speculative job checks keep their non-admitting overlays. Native evidence and
  the local gate journal are separate stores: a later local failure can leave
  valid native evidence without a local registration or acknowledgement. Retained
  evidence alone grants no mining authorization.
- Chain-state capture retries an observed tip change rather than confusing
  an old height and a new tip with an invalid profile. Invalid configuration
  still fails closed, and repeated chain movement cannot create an unbounded
  retry loop.

An initial optimized live run exposed the chain-state race when block 102
arrived between RPC reads. It stopped after 67 admitted proofs. This was a
gateway/test interruption, not a rejected settlement or a competing consensus
result. The failed capture is retained with the successful follow-up evidence.

## Measurement scope

The finite live fixture uses two loopback Debug native nodes, real easy proofs,
different signed jobs, changing mempool transactions and an independent rational
oracle for actual work-weighted coinbase payouts. The source and collector use
separate gate owners and RPC connections. Work continues during settlement.

The source serially services its logical miners. Its lateness and RPC time are
reported separately from collector ACK time and native peer verification.
This can reveal a workload-generation bottleneck; it cannot establish the
capacity of distributed gateways or a maximum native service rate. The v8
assignments are fixed synthetic exponents 2, 4 and 6; the cadence is an offered
schedule, not a physical miner or adaptive-controller measurement.

The fixed 60-second phase excludes later catch-up and draining. A last batch
waiting for its settlement opportunity is distinct from shares the source has
not produced or the collector has not acknowledged. A successful run requires
every acknowledged proof to appear in a verified settlement with the correct
payout; the small-budget overload run below did not meet that requirement.

Optional FIFO origin deduplication sends a full job once and then references it
for later proofs on that job. This is a fixture transport option. Its logical
payload savings are reported separately from actual native P2P counters and
must not be presented as measured mainnet bandwidth savings.

## Paired 20-miner result before the final registration fix

Both runs scheduled 200 proofs over 60 seconds, refreshed 60 jobs, and settled
the same batch counts of 67, 69 and 64. Origin deduplication was disabled in both.
The baseline used commit `f19e054`; both were configured for six seconds per
miner. The optimized run includes the origin cache, digest reuse, missing-only
replay and context fix; it predates the explicit-registration change. This is
one matched workload pair, not a statistical performance study.

| Measurement | Before | After |
| --- | ---: | ---: |
| Offered / acknowledged within 60 seconds | 200 / 200 | 200 / 200 |
| Admitted and peer verified within 60 seconds | 136 | 136 |
| Unacknowledged or unproduced at cutoff | 0 | 0 |
| Shares awaiting the last settlement at cutoff | 64 | 64 |
| Total share-admission service time | 21.043 s | 17.539 s |
| Share-admission p95 | 271.1 ms | 230.7 ms |
| Collector snapshot-write RPC calls | 1,240 | 843 |
| Total settlement service, three blocks | 3.354 s | 2.557 s |
| Live phase plus final drain | 62.136 s | 61.691 s |
| Node 0 CPU time | 22.56 s | 17.93 s |

Share-admission service time fell 16.7%, and snapshot-write calls fell 32.0%.
The source still offered at the same fixed cadence, so these savings did not
increase the scheduled share count. All 200 proofs eventually settled, with
zero rejected or expired acknowledgements and exact weighted payouts on both
nodes. The remaining writes include job registration and other preparation
paths; the change specifically removes unconditional replay during `receive`.

The native compact dependency-graph case took 115.692 seconds before and 99.786
seconds after (13.75% less). The baseline was a standalone case; the follow-up
ran within the full 106-case suite. Suite order, caches and host noise limit
that comparison. It does not measure a live RPC rate or mainnet capacity.

Raw captures: [before](../contrib/sharepool/results/v8-scalability-before-20.json),
[after](../contrib/sharepool/results/v8-scalability-after-20.json), and the
[initial race failure](../contrib/sharepool/results/v8-scalability-initial-race-failure.json).

## 100 miners with a 64 KiB settlement budget: failed

This run scheduled 1,000 proofs in 60 seconds with origin deduplication enabled.
At the cutoff, the source had offered 267, the collector had acknowledged 265,
and both nodes had admitted 131. The remaining 733 scheduled requests had not
yet been produced; 134 acknowledged proofs were waiting for admission.

After about 579 seconds including catch-up/drain, all 1,000 were acknowledged
but only 904 had settled across 26 blocks. The next proposed settlement was
empty, so the test failed. Read-only inspection confirmed that all 96 remaining
receipts were still durably stored, canonically encoded and target-valid, with
exact origins and canonical parents. They had expired before admission: their
origins were heights 103–123, while attempted settlement 128 required origins
at least 125 under `MAX_SHARE_AGE=3`.

This is an admission-capacity failure, not evidence of incorrect payouts or
peer disagreement. Preserving a receipt on disk does not preserve its consensus
eligibility. It exposes the need for deadline-aware backpressure before new
work is dispatched and explicit reporting of approaching/expired admission.
Simply carrying an acknowledged queue forward cannot guarantee confirmation
under an undersized budget, random block arrivals or reorgs.

A five-second driver stack sample was taken during drain, after the fixed
measurement phase. It showed substantial RPC socket waiting, plus GIL and
signer-related waits. Python method names were unresolved; the sample does not
attribute all delay to local job construction. Full-run timings include that
brief instrumentation. The source's serial design and the 64 KiB budget are
separate constraints, so this result is not a maximum native capacity estimate.

[Capture](../contrib/sharepool/results/v8-scalability-100-small-budget.json) ·
[Receipt forensics](../contrib/sharepool/results/v8-scalability-100-expiry-forensics.json)

## 100 miners with a 1 MiB budget: all work settled, cadence missed

Two further runs used the same 100-miner schedule, origin deduplication and an
already-permitted 1 MiB local snapshot budget. This did not raise a consensus
limit. The first run preceded the explicit-registration fix; the second used
the final code. Both produced 903 jobs and settled all 1,000 acknowledged proofs
with exact work-weighted payouts and zero rejected or expired receipts.

| Measurement | Before registration fix | Final code |
| --- | ---: | ---: |
| Offered / acknowledged within 60 seconds | 236 / 232 | 236 / 236 |
| Admitted and peer verified within 60 seconds | 229 | 229 |
| Scheduled requests still unproduced at cutoff | 764 | 764 |
| Acknowledged shares awaiting admission at cutoff | 3 | 7 |
| Proof-validation RPC attempts / missing-data failures | 1,903 / 903 | 1,000 / 0 |
| Collector snapshot-write RPC calls | 10,792 | 5,885 |
| Total share-admission service time | 445.880 s | 309.147 s |
| Share-admission p95 | 714.9 ms | 500.5 ms |
| Total source service time | 593.903 s | 572.878 s |
| Source service p95 | 942.0 ms | 924.4 ms |
| Live phase plus catch-up and drain | 617.883 s | 594.959 s |
| Settlement blocks | 27 | 26 |
| Node 0 CPU time | 594.48 s | 465.21 s |

Explicit registration removed all 903 routine missing-origin retries. Total
share-admission service time fell 30.7% and snapshot writes fell 45.5%, but
end-to-end runtime fell only 3.7%. This is one comparison with matching workload
settings; live timing changed the number and contents of settlement batches.
Service timings overlap across threads and include nested RPCs, so they must
not be added together or described as CPU time.

The final run offered only 236 of 1,000 scheduled proofs during its first minute.
It therefore **failed the requested live cadence**, despite passing eventual
settlement and conservation checks. The serial source remains a bottleneck:
all 764 catch-up offers required fresh jobs as block/context changes overtook
the per-miner loop. Faster receipt processing alone does not resolve repeated
job/history preparation. These measurements do not establish how distributed
gateways would perform.

[Before registration](../contrib/sharepool/results/v8-scalability-100-large-budget-before-registration.json) ·
[Final capture](../contrib/sharepool/results/v8-scalability-100-final.json) ·
[Independent event comparison](../contrib/sharepool/results/v8-scalability-100-comparison.json)

## Verification

The final code passed 315 Python tests and 106 native C++ cases. The paired v8
Stratum regression proves two origins were initially missing, then verifies
that explicit registration lets their first proofs use one native validation
call each with no template or snapshot replay. Ten actual wire submissions
likewise use ten fresh proof checks. The standalone runner test omits the
cadence override and verifies the six-second default and 24-second window.

The final native regressions also passed: 100 v8 miners with distinct payouts,
assignment mutations, late work, competing forks, restart and reindex; v7
compact settlements with 128 proofs, missing evidence and recovery; and the
legacy Stratum connection/acknowledgement race checks. These are correctness
runs, separate from the capacity measurements above.

[100-miner v8 report](../contrib/sharepool/results/v8-scalability-vardiff.json) ·
[V7 compact report](../contrib/sharepool/results/v8-scalability-compact.json) ·
[V7 Stratum report](../contrib/sharepool/results/v8-scalability-legacy-stratum.json) ·
[Python log](../contrib/sharepool/results/v8-scalability-python-tests.txt) ·
[Native log](../contrib/sharepool/results/v8-scalability-native-unit-tests.txt) ·
[Stratum report](../contrib/sharepool/results/v8-scalability-vardiff-stratum.json)

## Remaining production gates

The existing 32,768-proof block limit is an independent ceiling. At ten shares
per minute, 100 miners contribute 10,000 proofs per average ten-minute interval;
1,000 miners contribute 100,000 and cannot fit. Even ignoring every other
constraint, the count limit allows only about 328 miners at this cadence on
average even if every block settles their pool, with no headroom for block luck
or bursts. Faster validation alone
cannot remove that limit. Raising it requires a separately justified protocol
resource budget; this follow-up does not raise it.

Per-gate caching does not bound aggregate permissionless admission, in-flight
CPU, memory or disk. Full-template canonicalization, provenance traversal,
history preparation, durable journal I/O, simultaneous payout outputs, WAN
recovery and lifetime archive startup still require sustained-load evidence.
Neither this cadence nor a finite passing run qualifies the system for mainnet.
