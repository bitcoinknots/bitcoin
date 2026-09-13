# Reusing verified history and removing duplicate template validation

This update addresses two remaining sources of repeated work after
`c9eb79b1898e2061ddba3c2693abb5075b6609d7`: rebuilding shared recent accounting
history for different jobs, and validating an origin template immediately
before a native proof endpoint that checks the same origin again.

## Exact history prefixes

Each gate has a bounded cache of successful v7 state calculations. The key
contains the activation height, profile and exact canonical bytes of the native
snapshot sequence, including its left boundary. Different jobs can reuse their
common historical prefix and apply their own delta. An identical target can
reuse its complete calculation. A shifted age window uses a different key;
state is recomputed with the required expirations.

Every lookup still obtains the required native headers and snapshot bytes,
authenticates the ancestry and commitments, charges dependency bytes and proof
counts, and invokes inventory observers when configured. Missing, corrupted or changed evidence
cannot be supplied by a cached calculation. Current-tip checks and native
validation remain mandatory.

Intermediate entries preserve their computed history head. The committed
ancestor head is restored only when extending that prefix. A complete target
always compares the computed head against its actual commitment. Failed
materializations publish no entries. Successful sub-calculations can remain in
bounded memory if a later graph, native or job-policy check rejects the enclosing
job; they do not become acknowledged work or durable journal evidence.

Cache limits are 8 MiB estimated retained memory, 8,192 combined current-proof
and state records, and four entries per gate. Accounting includes exact raw
keys and nested immutable records. Oversized calculations are returned without
retention. At most the penultimate and final computed results are candidates
for insertion. These limits exclude temporary materialization allocations,
caller-held references and whole-process RSS. Nothing is persisted as a native
approval; closing the gate discards the cache.

## One native proof check on the warm path

The gate binds its exact local origin body, including witness bytes, to the
signed job commitment before calling `validatesharepoolhashshare`. Matching a
header or template ID alone cannot identify witness variants. The native proof
endpoint still validates the full origin, dependencies, work and native context.
Successful responses must bind the exact proof, pool, payout script and native
parent, and pass the final tip check.

Only the structured native error `(-25, sharepool-hash-data-missing)` permits
one bounded repair: recheck the journal seal, current context, eligibility and
exact origin; restore the bounded retained dependency set; register the full
historical template without an overlay; then retry the proof once. Native
rejection, changed-tip errors, malformed responses and timeouts do not trigger
this repair. A second missing-data result escapes to the caller. No proof is
acknowledged until native validation and durable journal sealing succeed.

Recovering one origin does not restore unrelated missing jobs. The native
regression explicitly checks that a replacement backend refuses incomplete
settlement, then successfully settles after the remaining retained origin is
recovered. The fast path performs no archive-wide recovery scan.

## Verification and isolated measurements

314 Python tests and seven native regtest scenarios pass. The new native test
uses real RPCs to verify warm calls, missing-body recovery, same-tip restart,
fresh header reads, witness substitution rejection, incomplete-settlement
refusal and actual 3:2 coinbase payouts. The six existing scenarios retain
payout, fork, replay, archive/reindex and older-profile coverage. Native C++
source and the previously verified Debug daemon are unchanged.

The [prefix benchmark](../contrib/sharepool/results/state-v7-prefix-benchmark.json)
uses the same runtime with caching disabled or enabled, 100 distinct signed
jobs with no new shares and three historical snapshots containing 300 proofs. Each of three
enabled sweeps starts with an empty cache. Median CPU time falls from 4.147 to
1.553 seconds. Replay and signature-verification calls fall from 400 to 103:
the three shared historical steps run once, followed by each job's own step.
Both modes still make 300 ancestry callbacks and 400 snapshot observations,
covering identical bytes and producing identical heads, state and certificates.
This excludes native validation, proof-of-work verification, network/archive I/O
and fixture creation.

The separate gate profile records 21 native proof calls and one template call
for 20 arrivals, including one initial missing-template repair. The earlier
adapter made 20 proof calls and 20 template calls. These counters describe the
fixture's RPC double; the new native regression independently confirms the
warm and recovery call sequences against actual nodes.

Reproduce the prefix benchmark with:

```sh
PYTHONPATH=contrib/sharepool:test/functional python3 -B contrib/sharepool/benchmark_hash_state.py --output /tmp/sharepool-state.json
```

## Native 100-miner workload

The [fresh capacity capture](../contrib/sharepool/results/state-v7-capacity-100.json)
uses the same configuration and unchanged Debug daemon as the
[preceding run](../contrib/sharepool/results/latency-v7-capacity-100.json):
100 simulated miners, three rounds, three actual low-difficulty proofs per
distinct origin, 20 ms scheduled offers and a pinned 72,750-byte batch budget.
All 900 proofs are acknowledged, admitted and verified by both native peers in
eight blocks, with correct direct coinbase payouts, zero expiry, zero unresolved
receipts and zero final backlog. Batch sizes remain 219/81, 120/111/69 and
129/117/54. The separate follower-gate receipt import covers the first 300
proofs; native peer verification covers all 900.

| Observed wall time | Previous run | This run |
| --- | ---: | ---: |
| Complete three-round workload | 951.35 s | 686.97 s |
| Round 2 preparation of 100 origins | 113.14 s | 103.79 s |
| Round 3 preparation of 100 origins | 156.97 s | 138.33 s |
| Round 3 acknowledgment of 300 proofs | 167.77 s | 114.65 s |
| Preparation of all eight settlement jobs | 142.85 s | 72.79 s |
| First-round follower-gate receipt import | 108.30 s | 62.81 s |
| Individual receive-call p95, 900 calls | 0.567 s | 0.549 s |

Origin preparation includes building and signing jobs, solving fixture proofs,
and registering their snapshots and templates with the collector. Receive-call
latency excludes waiting in the client queue. Local block acceptance with
evidence available takes 0.25–1.09 seconds; initial disconnected-peer recovery
takes 33.17 seconds. These native wall measurements have unknown competing host
load and are not a controlled speedup experiment. The controlled prefix
microbenchmark above isolates its smaller calculation only.

Five-second samples show driver peak RSS increasing from 285.4 MB to 447.6 MB
across the many miner gates. Each gate has its own cache, so retained memory
adds up; a per-gate bound is not a process-wide bound. Native node sampled peaks
are 78.8 MB and 74.2 MB. These samples do not establish a hard ceiling or stable
long-run memory use. The final round acknowledges about 2.62 proofs per second
against 50 scheduled offers per second: this finite burst drains, but it does
not demonstrate sustained capacity at that offered rate.

Commands, frozen source hashes, raw logs and preserved historical captures are
linked from the [verification manifest](../contrib/sharepool/results/state-v7-verification.json).

## Production limits

Distinct jobs still require their own transaction, signature and payout checks.
Snapshot reads, canonical captures, native job construction and resource
accounting still cost work. Cache eviction or a changed history window can
require rebuilding state. Ten minutes is an average block interval, not a
verification deadline or a validity rule.

Consensus rules, v4/v5/v6/v7 wire commitments, SHIFT10 and admission budgets are
unchanged. This remains opt-in regtest code. Sustained offered-load capacity,
production sampling variance, large-history/archive startup and WAN recovery
still require qualification.
