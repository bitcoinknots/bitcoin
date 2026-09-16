# Resource accounting and bounded native workloads

This follow-up reduces repeated codec/cache work, exposes exact snapshot costs,
and corrects the production capacity model. It retains v6 rules revision 2,
SHIFT10, the flat snapshot commitment and every consensus resource limit.
Mainnet and public-testnet activation remain disabled. Passing the fixtures below
does not establish a production service envelope.

## Implementation

- A snapshot operation builds its witness-transaction dictionary once and reuses
  it for sizing and writing. Each unique transaction is sized once; every template
  occurrence still counts toward expanded bytes and transaction references.
- Canonical decoding compares serialization directly against the received span,
  avoiding a second complete transaction or snapshot byte buffer. Frozen old
  writer fixtures verify unchanged v4/v5/v6 bytes and hashes.
- Process-local native cache keys bind the exact serialized header and ordered
  witness transaction IDs. Immutable transaction hashes avoid rehashing shared
  payload bytes at each lookup. Native context checks remain required; the key
  is neither a consensus commitment nor evidence of validity by itself.
- `getsharepoolhashresources` reports exact canonical component sizes, unique
  transaction bytes, expanded template bytes and reference counts. It is an
  explicitly enabled regtest-profile RPC, runs parsing/sizing outside `cs_main`,
  and neither stores nor authorizes evidence. Its two validation flags are always
  false: it does not open the dependency graph or validate native transactions,
  signatures or payouts.
- Mining preparation reserves coinbase payouts against the candidate's contextual
  native weight limit, including RDTS. Oversized payout reservations fail before
  block assembly. This does not change the payout calculation or native limits.
- Hash-only snapshot requests are paced when served. A valid request may wait in
  the existing single request slot for credits instead of disconnecting its peer.
  The 32-request burst and 32-services/second allowance, byte budget, frame/offset
  checks and original retry deadline remain enforced. Throttled requests do not
  trigger a disk lookup; conflicting requests remain malformed.

The following independent limits remain in effect:

| Resource | Existing limit | Accounting scope |
| --- | ---: | --- |
| Canonical snapshot | 16 MiB | Complete encoded object |
| Individual full template | 4,000,000 bytes | Header and full witness transactions |
| Expanded templates | 512 MiB | Repeated bodies charged for every occurrence |
| Transaction references | 2,000,000 | Ordered references in all declared templates |
| Distinct origins | 2,048 | Dependency graph, with local mining reservation |
| Dependency bytes | 64 MiB | Unique exact snapshot openings in the graph |
| Dependency depth | 64 | Graph traversal, with local mining reservation |
| Certificates | 4 MiB | Encoded certificate vector |
| Native block weight | 4,000,000 or contextual 800,000 WU | Full native block validation |

Local queues, history-query limits and archive quotas are additional constraints.
Changing a local limit cannot relax a consensus bound. A low RPC snapshot count
does not imply that the dependency graph has room for another origin.

## Reproduced transfer failure

The [first shared-body run](../contrib/sharepool/results/resource-budget-shared-heavy-100-before-transport-fix.json)
created 100 distinct valid origins, each 3,441,453 bytes and 3,780,204 WU in an
ordinary 4M-WU context. It acknowledged all 300 actual proofs. The producer
accepted the first 201-proof settlement, with 99 deferred, but the follower
missed the existing 120-second readiness bound after being disconnected.
This run remains **failed**, including its original timing and source hashes.

The [captured request trace](../contrib/sharepool/results/resource-budget-shared-heavy-transport-failure-trace.json)
identifies receive-token exhaustion before the failing request's other checks.
Even granting a completely full bucket immediately before request 3, the
receiver had at most 0.824096 tokens when it rejected request 51. Independently
paced sender/receiver clocks and delayed processing do not ensure identical
arrival credits. Treating local credit shortage as malformed traffic interrupted
a valid transfer. The new service pacing keeps the same allowance and queues
the one bounded request. A C++ regression replays all 51 captured arrival times;
the last request waits for refill instead of causing a disconnect.

Failure reporting now saves local native acceptance before waiting for the peer,
and distinguishes acknowledged, locally admitted and peer-verified proof counts.
The original report's incomplete top-level counters are retained rather than
retroactively relabeled as a completed pipeline.

After the fix, [fresh-node replay](../contrib/sharepool/results/resource-budget-heavy-replay.json)
revalidated the captured native ancestry and first settlement. The follower
obtained and validated that exact 201-proof snapshot in **35.25 seconds**, within
the unchanged 120-second bound. A fresh signer and gate in the same pool then
verified the remaining 99 original receipts in ACK order and settled them at
height 103. Both nodes contained exactly the original 300 proof IDs, without
duplicates or eligible backlog. Independent rational-window checks matched the
actual coinbase outputs: 67 recipients in the first settlement and 33 in the
second, with only 42 and 17 satoshis of rounding residue left unclaimed.

This is recovery/replay evidence, not a newly generated quiet 100-origin
benchmark. The original public capture was authenticated and left unchanged;
its signing keys had already been deleted. An initial attempt to relocate copied
datadirs was refused by the existing block-directory profile binding. No marker
was edited: the successful replay started empty native chains and submitted the
captured public blocks and evidence for fresh validation. The opt-in replay
script requires the locally retained capture identified in its manifest.

## Fresh disjoint-template pipeline

The [fresh disjoint run](../contrib/sharepool/results/resource-budget-disjoint-heavy-100.json)
passed on the fixed build: 100 distinct native origins, 300 offered and
acknowledged proofs, two settlements containing 222 and 78 proofs, correct
coinbase payouts and no expiry or final backlog. Both nodes verified the chain;
the follower's gate independently validated all 300 receipts from native archive
data. The two snapshots measured exactly 2,705,636 and 966,294 bytes against a
fixed local selection budget of 2,733,158 bytes.

| Origin geometry | Shared capture | Fresh disjoint run |
| --- | ---: | ---: |
| Distinct non-coinbase transaction sets | 1 | 100 |
| Bytes per full origin | 3,441,453 | 34,744 |
| Native weight per origin | 3,780,204 WU | 39,013 WU |
| Expanded bytes across 100 origins | 344,145,300 | 3,474,400 |
| Complete unbounded proposal bytes | 3,644,151 | 3,632,251 |

Both use the same count and shape of native witness transactions. Shared origins
include all 100 transactions plus distinct coinbase tags; disjoint origins each
include one independent transaction. Selection uses temporary regtest mempool
fee deltas, restored before settlement. Witness-heavy fixtures explicitly enable
nonstandard transaction policy on disposable nodes and use 128 stack elements
of 256 bytes, followed by a valid dropping script. Consensus limits are not
relaxed. An initial 512-byte-element fixture was rejected and is retained in
the preflight evidence.

The fresh run took 221.74 seconds. Its finite serial ACK phase took 5.73 seconds;
first native peer convergence took 34.31 seconds and later follower-gate recovery
took 129.34 seconds. Those stages do different work and are not interchangeable
service rates. Sampled driver RSS was 162.8 MB here versus about 1.26 GB in the
failed shared capture: encoded-byte ceilings are not a whole-process RSS bound.
These workload observations are not a before/after optimization benchmark.

## Capacity implications

The corrected [resource model](sharepool-resource-model.md) accounts for repeated
recent state, certificates, exact job openings, distinct coinbase transactions
and cold history reads. Shared non-coinbase transactions reduce wire storage, but
do not remove these costs. The existing 512 MiB expanded limit still permits at
most 134 full 4,000,000-byte origins in one snapshot, before other limits.

At the illustrative SHIFT14 density, proof bytes plus the four-height recent
state can exhaust the snapshot before general full-template demand fits. Exact
origin job openings can also exceed the dependency budget even when the root
snapshot fits. A permissionless recipient population must still fit actual
positive direct-payout outputs in one coinbase. These are format/admission
constraints; codec optimizations do not solve them.

An easier production target therefore remains inactive. Further work needs a
versioned design that avoids repeated authenticated state and job payloads,
bounded per-pool history access, and an explicit recipient/admission envelope.
Any such design must preserve exact signed jobs, native validation and direct
coinbase payout checks, and be retested under burst arrivals and delayed data.

## Verification

Results and reproduction commands are recorded in the
[verification manifest](../contrib/sharepool/results/resource-budget-verification.json).
The final build passed 154 SharePool C++ cases with 142,203 assertions, 233
Python tests without skips, and six native regression scenarios covering v4/v5/v6
construction, payouts/forks, worker context changes, transport and archives.
Native fixtures use disposable local regtest nodes, the external native
owner signer and actual easy-target proofs. The Goldshell was not rerouted.
The build is Debug; timings are observations of finite fixtures, not a measured
maximum production rate or a before/after performance comparison.
