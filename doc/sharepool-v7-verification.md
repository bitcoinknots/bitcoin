# V7 compact snapshots: verification and capacity limits

V7 adds compact proof records and derives recent state from committed native
ancestry. A persistent local per-pool index accelerates eligible history reads.
The block still commits one flat hash of the complete snapshot, and nodes still
verify exact jobs, proofs, native bodies and direct coinbase payouts.

This is an opt-in regtest profile. V4/V5/V6 wire commitments remain unchanged;
SHIFT10 and public-network activation settings are unchanged.

## Measured encoding

The native v7 correctness fixture reconstructs 128 proofs from four signed jobs
in two independent pools. Its proof vector uses 4,225 bytes and its shared job
dictionary 1,397 bytes: 5,622 bytes together, versus 65,536 bytes for the same
standalone full proofs. That is a 91.4% reduction for these sections. The whole
snapshot is 7,598 bytes. This is a measured encoding comparison, not a throughput
or whole-process memory reduction claim.

## Resource hardening

Compact records retain explicit per-snapshot and dependency proof-count budgets.
The native session cache now charges decoded shares, scripts, transaction and
witness allocations, references and state vectors; available oversized items are
verified without retention in that cache. Python graph preflight separates raw
openings from derived arrays, retains at most four recent parent states plus its
top certificate parent, and releases alternative-job state before recursion.

The history index authenticates branch-scoped coverage, rechecks selected
snapshots and falls back to bounded scans if its key, records or quota are
unavailable. The 100-block sparse-history unit fixture needs one selected
snapshot fetch on a warm restart. This saving requires unrelated admissions to
be absent from the selected pool's history; it is not a universal startup bound.
Cold construction still processes the full validated prefix from activation.

## Verification scope

The final Debug build passed:

- 177 SharePool C++ cases and 143,437 assertions (695 unrelated cases unselected).
- 252 Python cases: 147 hash/gate, 83 TIDES, 15 capacity and seven resource-model tests.
- Six native scenarios: v7 compact, v4 builder, v5 ledger, v6 TIDES, v4 retry worker
  and v6 archive recovery.

Exact commands, source and artifact hashes are recorded in
[the verification manifest](../contrib/sharepool/results/v7-compact-verification.json).
The native scenarios exercise exact Python/C++ bytes, actual payouts,
independent pools, mutated authorization/history/payout rejection, replay,
missing-data P2P recovery, restart, forks, index loss, reindex and profile
isolation. Earlier-profile native regressions use the final daemon too.

The model tests compare the real codecs at CompactSize boundaries. The
[serialization model](../contrib/sharepool/results/v7-compact-resource-model.json)
uses unchanged historical variance inputs and explicitly declares exact job
openings and recent native suffixes. It does not activate its illustrative
SHIFT14 candidate or establish payout variance under admission pressure.

## Fresh 100-miner pipeline on the final build

The [final native capture](../contrib/sharepool/results/v7-final-capacity-100.json)
uses 100 simulated miners, 100 distinct cumulative (overlapping) native
transaction sets and 300 actual
proofs on two loopback nodes. A frozen 72,750-byte local batch budget forces
deterministic carry: 219 proofs settle at height 102 and the remaining 81 at
height 103. Both peers verify every admission and the independent payout oracle
checks the actual coinbase scripts and amounts. No proofs expire; the final
receipt and peer backlogs are zero.

The full run takes 371.19 seconds on the declared concurrent-load host. Serial
ingress takes 11.97 seconds, settlement-job construction 30.72 seconds in total,
and the follower gate's evidence/receipt import takes 240.49 seconds. That last
step includes local import and validation; it is not a measurement of P2P wire
propagation alone. The two block-and-snapshot readiness waits total 32.75 seconds.
Timing categories may be nested and must not be added as independent costs.

Nominal five-second samples report peak resident sizes of 72,400,896 bytes for the
producer, 71,548,928 for the follower and 88,997,888 for the driver. These sampled
values are not hard memory ceilings or a saturation test. This fresh one-epoch
run verifies the final cache changes; it does not establish sustained capacity.

The separate longer capture started before the final native and Python cache
retention fixes. Its original binary and source hashes remain attached to the
artifact. A targeted diagnostic measured nearly one Python CPU core while the
two native nodes were mostly idle; exact Python source-function attribution was
not available. Its second 300-proof ingress took 225.02 seconds versus 8.12 seconds
for its first. Those timings must not be presented as final-source benchmarks.
The capture acknowledged all 900 proofs but was interrupted at 1,852.23 seconds
after exceeding its configured 1,800-second budget between cooperative deadline
checks. Its first two epochs settled 600 proofs in five blocks, verified by both
peers. The remaining 300 were acknowledged and waiting for the third epoch's
settlement job. The preserved result is **failed/incomplete**, with
`KeyboardInterrupt` in settlement-job construction; it is not a consensus
rejection or a passed sustained-capacity test. No expiry was recorded at the
captured point. The framework saved the report and cleaned up its node processes.

## Remaining production limits

Repeated current admission deltas across exact job openings still multiply
proof processing and dependency bytes. Cold or uncertified origin suffixes can
exhaust the proof budget even when compact bytes fit. Every positive direct
payout remains a real coinbase output; no new recipient admission policy or
deferred payment scheme is introduced.

The longer capacity capture also exposes significant Python adapter latency
once native history is populated. These Debug, loopback, finite tests do not
establish sustained service capacity, WAN propagation, large-disk initial sync,
archival availability, production share difficulty or readiness for activation.
No physical miners were used in this update.
