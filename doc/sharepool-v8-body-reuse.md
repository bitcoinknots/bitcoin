# Template body and dependency capture reuse

This follow-up to `1f7b010e425186800bc65472062e03007c5a1f87` removes
repeated canonical body processing and the second dependency walk used to
initialize admission accounting. Consensus, proof targets, payout rules and
the default ten shares per minute per miner are unchanged. Mainnet remains
disabled.

## Reused work

The native standalone share path now obtains a typed, owned canonical template
capture. Its factory retains the original full-body wire checks, including
witness serialization, normalized search fields, transaction count, Merkle root
and byte bounds. A successful capture supplies the immutable body and exact
job digest on subsequent requests. The node retains at most 256 captures under
a 32 MiB charged-memory budget. The key includes the actual header and ordered
witness transaction IDs. Changed coinbase, witness, parent, time or commitment
cannot use another body's capture. A verifier-local digest memo also avoids
hashing the same exact job again during origin and settlement checks.

Every share request still obtains its template through the authenticated native
evidence store before consulting that cache. The capture is not proof of
availability, owner authorization, valid transactions or valid work. The node
continues to check its current chain context, share target and binding,
settlement dependencies and payout rules. A store corruption or missing opening
cannot become a successful proof merely because a capture remains in memory.

The Python gateway separately retains immutable compact template records under
an 8 MiB charged-memory budget and 32-entry limit. Every request first reads and
authenticates the actual stored bytes; their full witness-body digest selects
the decode. Within one receive operation, its freshly read template and
snapshot bytes are shared by provenance and native-binding checks. The durable
commit still compares existing evidence against the journal. No cached body
can grant an acknowledgement or survive as an authorization after restart.
These memory charges are local retention accounting, not hard process RSS caps.

Batch selection can return the immutable canonical captures from its successful
dependency walk. Admission-accountant initialization consumes those captures
instead of walking and serializing the graph a second time. The complete
captured evidence still enters the operation's staged snapshot set before any
durable acknowledgement. The accountant retains scalar resource totals and
hash identities only. Rejected trial captures are discarded; a smaller trial
performs its own bounded checks. Changed tips, journal revisions and policies
retain their existing freshness checks.

## What still runs

This change does not cache an entire recursive validation result across share
requests. Native and Python dependency checks still authenticate the evidence
required by each new operation. Native template storage still reconstructs and
authenticates a template before finding its capture. New bodies require full
canonical decoding. Other remaining costs include context RPCs, separate
admission-status and job selection, exact-fit fallback, durable journal sealing,
and archive scans. Payout, origin, proof and dependency limits are unchanged.

## Verification and measurement

The new Python cases check repeated-body decode counts, witness/header changes,
cache bounds and disabling, corrupt evidence between requests, corruption during
the native RPC, identical durable receipts, exact dependency-walk counts,
failed-trial release, missing evidence, tip changes and reorgs. The full gateway
suite passes 403 tests, plus ten capacity-fixture tests. The 17 new Python
cases cover body reuse and dependency capture handling. The 158 distinct
native C++ cases include four new cases for owned-body isolation, invalid
proofs and signatures, missing snapshots, malformed templates, and cache
identity, retention and eviction. One new test initially reused the fixture's
existing parent when expecting a changed-parent cache miss; correcting that
test and rerunning it passed without a production-code change. The native
manifest preserves the initial failure and focused rerun.

Four real-node integration fixtures also pass: admission pressure and refused
winning shares; loopback Stratum with per-miner assignments and late shares;
archive-only provenance recovery; and 100 distinct miners with exact weighted
payouts, rejected mutations, competing forks, restart and offline reindex.

The paired native measurement uses 20 miners, four source owners, 200 scheduled
proofs over 60 seconds, a six-second target per miner, a 1 MiB snapshot budget,
20-second settlement opportunities and 40-second template refresh. Both sides
use the same runner, easy assigned targets, separate frozen source/binary copies
and two loopback Debug nodes. Builds and other tests do not overlap either
timed run. This light workload measures service cost and correctness; it does
not establish sustainable miner capacity, production variance or WAN behavior.

| Measured cost | Before | After |
|---|---:|---:|
| Collector registration and ACK, 200 calls | 10.236 s | 9.921 s |
| Native proof RPC, 200 calls | 3.182 s | 3.189 s |
| Native template RPC, 63 calls | 1.437 s | 1.363 s |
| Settlement, three calls | 2.253 s | 2.248 s |
| Main native node CPU | 11.10 s | 11.10 s |
| Driver CPU | 10.18 s | 9.61 s |

Both runs acknowledge, settle and peer-verify all 200 scheduled proofs, with
zero rejected/refused shares or expired ACKs. Each creates 60 jobs and three
settlements containing 67, 69 and 64 proofs. There are 60 full-origin transfers
and 140 references in each run. At the 60-second cutoff 136 proofs have settled;
the remaining 64 settle during the final drain. Live time plus drain is 61.534 s
before and 61.523 s after. Main-node peak sampled RSS is 70.24 MB and 70.66 MB.

The observed admission-service reduction is 3.1%; native proof time is effectively
unchanged. These are single captures with tiny templates and no confidence
interval, so they do not demonstrate a reliable throughput increase. Nested RPC
time is included in admission service time and must not be added to it. Unit
tests establish that the repeated work was removed; this workload does not
establish how much that will help larger transaction bodies or saturated pools.
The earlier 100-miner capacity shortfall remains unresolved.

[Verification manifest](../contrib/sharepool/results/v8-body-reuse-verification.json)
records test commands, source/binary hashes and artifact checksums.
[Paired comparison](../contrib/sharepool/results/v8-body-reuse-comparison.json),
[baseline capture](../contrib/sharepool/results/v8-body-reuse-baseline-results.json)
and [final capture](../contrib/sharepool/results/v8-body-reuse-final-results.json)
retain timings, event identities and payout-oracle checks. Source manifests and
launch records accompany both captures. The saved tracked-file patch supplements
the source hashes; new files are present in this commit and the frozen source
manifest, not in that patch. Consensus rules and ten-shares-per-minute defaults
are unchanged.
