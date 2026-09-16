# Production gate follow-up

This change addresses measured construction cost, transport withdrawal, archive
read amplification and native snapshot preparation. It keeps the existing v7
rules, exact signed job, flat settlement hash and direct coinbase payouts.
Public-network activation remains disabled.

## Construction cost and bounded loading

The preceding 100-proof native job profile performed 1,308 Python BIP340 checks.
Most were repeated checks of exact public inputs while selecting and checking
batch prefixes. They consumed 13.09 of 16.49 profiled seconds. Native RPC time
was approximately 0.69 seconds.

The gate now keeps a separate successful-signature memo, limited to 1,024 entries
and one MiB of conservatively charged retained objects. Keys contain the exact
immutable public key, signature and message. No snapshot body, ancestry result,
accounting verdict or native approval is inferred from a signature-cache hit.
Evidence reads, resource accounting, observers, state calculation and native
validation still execute. The cache is discarded on gate close.

Batch selection first tries the complete bounded prefix after checking the empty
batch. If it does not fit, deterministic binary search still selects the maximal
fitting prefix. Each trial reserves the new job's own origin and incrementally
charges origin count, expanded bodies, transaction references and a deduplicated
transaction-wire lower bound before loading later sources. Fetched origin bodies
are local to a trial, so a rejected full trial cannot leave an oversized origin
memo behind. Full snapshot, dependency and payout checks remain authoritative.

The same 100-proof job profile subsequently took **2.72 seconds**, with four
batch trials instead of sixteen. Incoming proof validation had warmed its exact
signature memo. This is a profiler comparison including instrumentation overhead,
not an individual-operation deadline or a production capacity guarantee. The
rebuilt native backend also includes the predecode change described below.

The subsequent [full cadence capture](../contrib/sharepool/results/production-gaps-cadence-comparison.json)
passed both arms, including all 100 proofs, exact native coinbase payouts and
journal reopening. Comparing its DATUM arm with the previous recorded DATUM arm:

| Collector measurement | Previous | Hardened |
| --- | ---: | ---: |
| Total measured CPU | 33.93 s | 10.57 s |
| Elapsed time through final publication | 147.41 s | 123.90 s |
| Slowest fresh-job operation | 12.42 s | 1.72 s |
| Offer-to-ACK p95 | 5.08 s | 0.094 s |
| ACK-to-job publication p95 | 52.11 s | 40.59 s |

The hardened per-ACK arm used 85.69 CPU-seconds and completed final publication
in 113.99 seconds. At this finite one-proof-per-second load it now finishes
earlier than the scheduled arm, which waits for its final refresh; cadence still
uses about eight times less CPU. Both use the same immutable-cutoff rules.

This is one new paired capture against historical results, not a simultaneous
before/after experiment or a confidence interval. Independent build/transport
checks occurred during the capture, and the host was not isolated. The workload
uses small precomputed origins, fixed native height and a deliberately solved
final block. It does not measure ASIC efficiency, real WAN relay or a sustainable
production share rate.

## Later-round capacity regression

The [three-epoch capacity run](../contrib/sharepool/results/production-gaps-capacity-comparison.json)
admitted **900/900 proofs across eight blocks**, with exact payouts, both native
peers verified, zero expired work and zero final backlog. Its test-measured
elapsed time was 640.51 seconds, versus 686.97 in the preceding capture with the
same workload configuration. The surrounding process took 641.89 seconds.

This is a much smaller improvement than the short collector comparison. Third
epoch preparation still took **137.35 seconds** for all 100 source jobs, proposal
sizing and collector registration, versus 138.33 previously. Its 300-proof ingress
still took 114.47 seconds versus 114.65. Driver CPU fell from 217.95 to 173.03
seconds; native node CPU was nearly unchanged. These measurements identify work
outside repeated collector job building as a remaining capacity constraint.

Offers stop while the test drains each finite burst, and the harness schedules
the blocks. This verifies deterministic carry and later-round correctness; it
does not demonstrate sustained overload safety or guarantee admission before
expiry under real block timing.

## Transport withdrawal and real work submission

The [v7 loopback adapter](sharepool-v7-stratum.md) connects the sole-owner gate
and scheduler to Sia Stratum requests. Socket handlers use a bounded owner queue;
they never call the gate concurrently. Full snapshot publication and a fresh
dispatch check precede handing the exact authorized job to a client.

A separate native observer and socket watchdog can withdraw advertised work
while the owner is blocked in construction, signing or RPC. A changed observation
generation cannot revive an old handoff, even if the native parent later returns
to the same hash. Observation failure or expiry closes sockets. Gate operations
resume on their original owner with fresh authorization.

This is a finite, loopback-only regtest integration with synthetic clients. It
does not cancel the construction calculation, prove that disconnected ASICs
stop hashing, implement remote authentication or establish deployed DATUM/ASIC
compatibility. The standalone runner requires an isolated v7 node and matching
native binaries; the earlier Goldshell bridge uses a different path.

## Archive verification

Startup verification streams each cold segment and checks proof-origin bindings
while its proof body is already in hand. Every record, protected checkpoint,
segment boundary and exact origin remains authenticated. Rollover reuses the full
verification it just completed, while freshly checking exported records and the
sealed endpoint; it no longer performs a second lifetime verification first.

In the [final-source archive comparison](../contrib/sharepool/results/production-archive-startup-scaling-final.json),
5,000 receipts occupied 3,305,963 journal bytes. Median full verification fell
from **2.130 to 1.389 seconds** and rollover from **2.174 to 1.222 seconds**.
Cold-file opens fell from 20,002 to 10,001. This measures authenticated archive
I/O with an RPC test double, not native proof validation or WAN recovery.

Full startup still reads lifetime history. Repeated full verification during
rollover remains a scaling gate; this change removes duplicate work rather than
introducing a trusted persistent validity cache.

## Native snapshot preparation

P2P admission and the snapshot-submit RPC now hash and decode owned bytes outside
`cs_main`. Prepared content is an opaque object; callers cannot change its bytes,
hash, profile or decoded metadata. Commit rechecks the selected profile, durable
record, current quota and index state under the store's existing lock.

P2P retains its existing global download reservation during preparation and
rechecks peer, transfer and live-store ownership before commit. No extra unbounded
queue is introduced. Wrong requested hashes fail before decoding; hash-bound
malformed preimages retain their existing native-validation semantics. Missing
data, exhausted quota and storage failure do not prove a block invalid.

The [native verification record](../contrib/sharepool/results/production-native-predecode-verification.json)
contains 86 C++ cases and the native relay regression. This removes hashing and
decoding from one chain-lock critical section. P2P still holds the message-loop
mutex, and durable store/index I/O remains under `cs_main`; worst-case global
pause bounds are not established.

## Remaining release gates

The final [verification manifest](../contrib/sharepool/results/production-gaps-verification.json)
ties these captures to source and binary hashes. All 254 Python hash-protocol
tests passed, along with native worker, compact-state, state-reuse, DATUM-cadence
and archive regressions, the separate Stratum integration, 86 C++ cases and the
relay regression. Cadence, capacity and archive captures also passed their
correctness checks. These suites overlap in coverage; their counts are not a
production acceptance threshold.

- Sustained admitted work rate with live template churn, recursive later-job
  dependencies, bursts and multiple producers, before provisional proofs expire.
- Production share difficulty and payout variance within that measured capacity,
  including an explicit supported population of direct coinbase recipients.
- Production mining transport, real hardware and independently changing gateways;
  incremental live data dissemination and actual replicated WAN traffic.
- Bounded lifetime startup/rollover, archival provisioning, partitions, withheld
  evidence, reorg recovery and worst-case disk/global-lock pauses.

Faster successful operations do not remove these gates or make all acknowledged
work unconditionally payable. Native admission and rolling reward eligibility
remain distinct from a provisional local acknowledgment.
