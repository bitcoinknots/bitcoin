# V7 verification latency

Ten minutes is an average block interval, not an available verification period.
Blocks can arrive close together. Nodes need to receive and check evidence as
work arrives, keep admission queues bounded, and minimize the remaining work
when a block arrives. Taking less than 600 seconds on a finite fixture does not
establish that these requirements hold at production load.

Wall-clock performance targets must remain separate from validity rules. A slow
machine or delayed snapshot cannot make an otherwise valid block invalid.
Missing evidence remains pending; native validation determines acceptance once
the required data is available. A signed job commits its exact snapshot. Later
work belongs in a later job or settlement, without editing the winning header's
commitment after the miner has worked on it.

## Changes

The Python adapter now computes immutable proof-header facts once for each
exact byte string. Graph checks capture each external snapshot's canonical bytes
once per operation, then reuse hashes and authorization preimages from that
capture. Captured payouts are immutable and detached from caller-owned outputs;
a new operation sees edits and checks their new commitment. The derived native
parent cache still holds at most four entries, plus the operation's top
certificate parent.

A gate-owned decode cache uses exact bytes and profile as its key. It has
independent limits of 8 MiB estimated retained memory, 8,192 shares and 32
entries. Accounting includes nested decoded objects and immutable header facts.
Oversized snapshots can be decoded without retention. The limit covers retained
entries, not transient decoding, caller-owned objects or process RSS.

Cache hits still read and authenticate evidence, charge inventory observations,
and call native snapshot storage, template validation and proof validation.
Mutable payout outputs are copied on every return. A decode is never a native
approval, an availability guarantee or a reusable mining authorization. Invalid
native work is not acknowledged or added to the durable journal.

Consensus code, v4/v5/v6/v7 wire commitments, difficulty and admission budgets
are unchanged. Public-network activation remains disabled.

## Focused measurements

The baseline is commit `782e352151f71fdff26c97ba643d6012810da4c1`.
Synthetic fixtures isolate Python work and exclude native throughput claims.

| Workload | Before | After |
| --- | ---: | ---: |
| Serialize, hash and construct owner message; 1,024 proofs, one job; median CPU | 109.66 ms | 3.47 ms |
| Same operations; 1,024 proofs, 16 jobs; median CPU | 113.10 ms | 3.85 ms |
| Graph check; 16 alternate jobs, 96 inherited and 16 current proofs; median wall time | 787.10 ms | 276.76 ms |
| 20 gate arrivals over 100 prior proofs; profiled receive cumulative time | 5.812 s | 1.196 s |

The graph fixture preserves all exact opening hashes, 21,229 charged dependency
bytes, 112 charged proofs and all 17 materializations/33 state applications.
The gate fixture still calls native template and proof validation 20 times
each through its RPC test double. Snapshot serializations fall from 1,020 to
400 and decodes from 220 to 120; no native validity check is replaced by the
cache. Profiling instrumentation affects timings, and these are finite
measurements on one host.

Reproduce the gate workload with
`python3 -B contrib/sharepool/benchmark_hash_gate.py --output-prefix /tmp/gate-profile`.
The codec benchmark is available through
`PYTHONPATH=contrib/sharepool python3 -B contrib/sharepool/test_hash_codec_latency.py --benchmark /tmp/codec-profile.json --label local`.
The graph fixture is defined in `contrib/sharepool/test_hash_graph_latency.py`.

## Fresh native pipeline

The [900-proof capture](../contrib/sharepool/results/latency-v7-capacity-100.json)
passes on two loopback Debug nodes with 100 simulated miners. Each of three
rounds uses 100 distinct cumulative, overlapping native transaction sets and
300 actual proofs. The fixed 72,750-byte local snapshot policy carries work
across eight blocks: 219/81, then 120/111/69, then 129/117/54 admissions.
Both native peers verify all 900 admissions, the independent payout oracle
checks actual coinbase outputs, and no acknowledged work expires or remains
unresolved. Final admission and peer-verification backlogs are zero.

| Round | Prepare 100 origins and proposal | Acknowledge 300 proofs | Through settlement and receipt checks |
| --- | ---: | ---: | ---: |
| 1 | 20.08 s | 7.95 s | 86.68 s |
| 2 | 113.14 s | 113.16 s | 309.54 s |
| 3 | 156.97 s | 167.77 s | 431.05 s |

The full run takes 951.35 seconds. Round times include their preparation and
admission stages; they exclude post-round diagnostics and the separate first
round follower-gate import, which takes 108.30 seconds. Categories are nested
and must not be added as independent costs. Follower-gate receipt import is
tested for the first 300 proofs; native peers verify every round.

For the 900 live gate arrivals, acknowledgment latency has p95 0.567 seconds and
maximum 0.653 seconds. The eight local `submitblock` calls take 0.251–1.088
seconds with evidence already available. Settlement-job construction takes
4.74–30.96 seconds per job. The follower block-and-snapshot readiness waits total
37.71 seconds; the deliberately disconnected first recovery accounts for 32.63
seconds. These values distinguish live verification, job preparation, local
block acceptance and missing-data recovery.

The fixture offers a finite burst at 50 proofs/second and stops offers before
draining. Later-round admission does not keep up with that offered rate. All
three finite rounds finish within 600 seconds, but the test establishes neither
a deadline guarantee nor sustainable production capacity. Competing host load
is declared unknown; earlier native captures used different host-load labels,
so their wall times do not establish a controlled speedup ratio.

Five-second samples report peak RSS of 78.8 MB and 74.7 MB for the native nodes
and 285.4 MB for the driver running many miner gates. These are sampled process
measurements, not hard memory ceilings or a long-run stabilization result.

## Verification

283 Python tests and six native regtest scenarios pass, including payout
mutation isolation, corrupted warm-cache evidence, same-tip snapshot loss,
native rejection without acknowledgment, old wire profiles, actual coinbase
payouts, competing forks and archive/reindex recovery. The native Debug daemon
is unchanged from the preceding verified build; this update does not rerun or
claim a new C++ test count.

Exact commands, source hashes and measurements are linked from the
[verification manifest](../contrib/sharepool/results/latency-v7-verification.json).

## Remaining requirements

Production qualification still needs sustained offered-load tests, growing
history and archive startup measurements, realistic transaction/script mixes,
WAN delays and data-withholding recovery. Measure arrival-to-acknowledgment
latency, block-plus-evidence readiness, tail latency and queue growth separately.
Repeated current admission deltas, dependency proof work, direct recipient
outputs and archival availability still limit capacity. Production difficulty
and payout variance under admission pressure remain open.

The [next update](sharepool-v7-state-reuse.md) reuses exact historical state
prefixes and removes the duplicate template check before native proof validation.
Its measurements are recorded separately; the results above describe this
earlier implementation.
