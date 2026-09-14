# Production gate audit after DATUM cadence

Read-only source audit dated **2026-09-13**, scoped to commit
`33a38366c6cc818ba53b8122979235f34a658628`.
The audited profile is opt-in **v7 regtest**. This report adds no runtime changes
and contains no new throughput measurements. The accompanying benchmark must
state its own workload and results; code inspection does not establish elapsed
time, supported miner count, WAN capacity or mainnet readiness.

The scheduler reduces unnecessary job replacement while preserving the issued
job's exact settlement cutoff. The remaining release gates concern integration,
latency, sustained admission and storage capacity. This review did not reproduce
a new consensus or dispatch-authorization bypass.

## Highest-priority release gates

### 1. Keep block-event handling responsive during construction

`HashJobScheduler.poll()` runs native construction, external signing,
authorization and transport publication synchronously on its sole owner thread
([scheduler, lines 91–121](../contrib/sharepool/hash_job_scheduler.py#L91-L121)).
A block notification bypasses the normal refresh timer only when the owner can
service it. There is no scheduler deadline or cancellation mechanism that
interrupts a blocked signer, RPC or callback. The refresh interval starts after
successful handoff, so preparation time also contributes to the time between
issued jobs ([lines 122–127](../contrib/sharepool/hash_job_scheduler.py#L122-L127)).

Existing mitigation: native context is checked during construction, before
dispatch and after handoff. These checks reject stale construction; they do not
guarantee prompt cancellation of work already advertised to miners. Normal
replacement intentionally preserves that old job while construction runs.

Next measurement: record preparation, authorization and publication separately,
plus block-notification service delay while each stage is busy. A subsequent
integration change should provide bounded cancellation or independently
responsive transport handling while preserving gate ownership and the final
context fence. Moving the existing gate into an arbitrary thread pool would
violate its ownership contract.

### 2. Connect the scheduler to a deployed mining transport

At the audited commit, the scheduler's callers are its
[unit tests](../contrib/sharepool/test_hash_job_scheduler.py) and the
[native cadence fixture](../test/functional/feature_sharepool_hash_datum_cadence.py#L109).
It is a library adapter, not a deployed DATUM or Stratum service.
The existing hardware capture imports and constructs the older `NativeMiningGate`
([hardware capture, lines 22 and 124](../contrib/sharepool/native_hardware_capture.py#L22));
that earlier hardware evidence does not exercise this v7 scheduler path.

The publication callback must arrange full snapshot availability, send the exact
authorized job and confirm the handoff
([scheduler, lines 77–81](../contrib/sharepool/hash_job_scheduler.py#L77-L81)).
Authorization uses a temporary native overlay and does not itself announce the
snapshot ([gate, lines 1376–1382](../contrib/sharepool/hash_mining_gate.py#L1376-L1382)).
The callback contract is therefore an integration obligation, not evidence that
remote miners received work or other nodes have the opening.

Existing mitigation: callbacks must confirm publication; failures trigger
withdrawal. A failed withdrawal latches `withdrawal_pending`, blocking further
construction and publication until withdrawal succeeds
([lines 66–72](../contrib/sharepool/hash_job_scheduler.py#L66-L72),
[94–95](../contrib/sharepool/hash_job_scheduler.py#L94-L95),
[130–135](../contrib/sharepool/hash_job_scheduler.py#L130-L135)).
Clearing local state cannot make a broken transport stop physical miners.

Next integration gate: exercise actual transport publication, native block
notifications, disconnects, partial publication, stale-work withdrawal, restart
and snapshot retrieval using this exact v7 path. Keep earlier hardware results
separate from that evidence.

### 3. Bound Python gate startup and archive rollover work

The Python gate constructor calls `_verify_store()`
([gate, line 131](../contrib/sharepool/hash_mining_gate.py#L131)).
That verifier reads every journal body and then revisits every acknowledged proof
and its origin ([lines 255–282](../contrib/sharepool/hash_mining_gate.py#L255-L282)).
Cold rollover calls the same verifier
([line 419](../contrib/sharepool/hash_mining_gate.py#L419)); quota-triggered
persistence invokes rollover before accepting more work
([lines 333–338](../contrib/sharepool/hash_mining_gate.py#L333-L338)).
Cold bodies are still retrieved and authenticated individually
([lines 390–407](../contrib/sharepool/hash_mining_gate.py#L390-L407)).

This differs from the native snapshot store's checkpoint startup and the native
pool-history index. Their improvements do not remove the Python gate's lifetime
verification scan. With repeated fixed-size rollovers, rescanning an ever-growing
prefix can produce quadratic cumulative reread work. That is a worst-case
consequence of repeated full scans, **not a measured runtime growth curve**.

Existing mitigation: immutable cold segments preserve complete acknowledged
evidence; quotas fail before acknowledging work that cannot be retained. Those
integrity properties must survive an optimization.

Next measurement: reopen populated gates and perform repeated quota-triggered
rollovers with cold history. A subsequent change needs authenticated incremental
verification or another bounded recovery design, with corruption, rollback and
missing-segment tests. Simply skipping integrity checks is insufficient.

### 4. Demonstrate sustained admission before provisional work expires

The gate selects a bounded deterministic prefix and retains deferred receipts.
Eligibility still uses the existing three-height proof-age window
([batch floor, line 917](../contrib/sharepool/hash_mining_gate.py#L917),
[consensus age, line 28](../src/consensus/sharepool.h#L28)).
V7 status can therefore become `expired_unanchored`
([gate, lines 1248–1249](../contrib/sharepool/hash_mining_gate.py#L1248-L1249)).
An acknowledged receipt is not an unconditional promise of eventual admission
or payment. Confirmed admission and rolling reward eligibility are separate.

Existing mitigation: local scheduling prioritizes origin age and durable receipt
order; foreign-pool work can enter the queue without changing its pool or payout
recipient. Confirmed history remains tied to the native branch. These controls
do not force another producer to admit work, establish a global reception order
or prevent expiry when service capacity is insufficient.

Next measurement: sustained offered and admitted work rates, queue age, deferred
work and expiry under bursts, multiple independent producers, partitions and
recovery. Any advertised service guarantee must state its load assumptions and
preserve provisional versus confirmed status.

### 5. Meet the variance objective within actual resource limits

The native target remains SHIFT10
([hash consensus constants, line 26](../src/consensus/sharepool_hash.h#L26)).
V7 retains independent snapshot, dependency, expanded-template, reference,
origin and proof-count limits
([lines 27–36](../src/consensus/sharepool_hash.h#L27-L36)).
The statistical candidate for denser shares is not an activated or supported
production target. The [variance contract](sharepool-variance-contract.md#capacity-is-a-separate-acceptance-condition)
and [v7 constraints](sharepool-v7-compact.md#serialization-model) distinguish
statistical results from capacity.

Existing mitigation: compact encoding removes repeated per-proof job fields and
inherited state arrays, and validation caches reduce repeated local work.
Different exact openings can still repeat a current admission delta; genuinely
different transaction sets still require bytes and native validation. Fewer
refreshes do not remove the obligation to validate every admitted proof.

Next gate: combine measured sustained capacity with an admission-aware payout
variance comparison for an explicit population, difficulty and payout horizon.
A passing uncongested variance model or a short easy-target benchmark alone
cannot establish that joint contract.

### 6. Define a supported direct-payout recipient envelope

Every positive direct payout needs space in the winning coinbase. The native
reservation rejects outputs exceeding contextual block limits
([mining budget, lines 24–33](../src/sharepool/mining_budget.h#L24-L33)).
The gate also reserves historical and newly introduced recipients against
snapshot and dependency budgets
([gate, lines 974–988](../contrib/sharepool/hash_mining_gate.py#L974-L988)).
Historical payout obligations can make even an empty new-admission batch unable
to fit ([lines 998–1000](../contrib/sharepool/hash_mining_gate.py#L998-L1000)).

Existing mitigation: construction refuses over-budget payouts rather than
silently dropping positive outputs. V7 adds neither deferred balances nor a new
recipient admission policy.

Next gate: test recipient growth, script sizes, payout-window populations and
contextual block limits. Specify the supported envelope and behavior at its
boundary without silently discarding acknowledged obligations.

## Additional latency and operational gates

### 7. Measure individual native admission pauses and idle polling

Native peer processing already has fair admission turns and elapsed-time pacing.
Nevertheless, `SendSharePoolHashMessages()` holds `cs_main` and
`g_msgproc_mutex` ([peer processing, lines 3929–3932](../src/net_processing.cpp#L3929-L3932))
when it invokes `store.Put()`
([line 4012](../src/net_processing.cpp#L4012)).
That call decodes the snapshot and performs a synchronous durable write under
`cs_main` ([store, lines 648–696](../src/sharepool/hash_store.cpp#L648-L696)).
Pacing between admissions does not bound the pause caused by one admission.

Origin script checks already run outside `cs_main`
([validation, lines 5508–5516](../src/validation.cpp#L5508-L5516)).
Coin-view preparation and the historical fallback still include synchronous
locked work ([lines 5500–5502](../src/validation.cpp#L5500-L5502),
[5812–5817](../src/validation.cpp#L5812-L5817)).
This is a remaining worst-case latency issue, not an absence of a validation
worker or fairness controls.

Separately, an idle scheduler poll authenticates the full block and snapshot
bytes ([dispatch MAC, lines 1453–1463](../contrib/sharepool/hash_mining_gate.py#L1453-L1463)),
reads the protected checkpoint and database, and checks native context
([lines 1488–1494](../contrib/sharepool/hash_mining_gate.py#L1488-L1494)).
The successful path performs six native RPC calls through `_context()` and
`_stable()` ([lines 139–155](../contrib/sharepool/hash_mining_gate.py#L139-L155)).
Avoid treating frequent polling across many independent gateways as free.

Next measurements: idle-poll latency and RPC volume, ordinary block/transaction
responsiveness during worst-case snapshot admission, cold storage and recovery
load. Preserve exact authorization and fresh native context if reducing repeated
checks or moving expensive work outside locks.

### 8. Complete live dissemination and retention operations

The v7 peer channel sends hash-addressed full snapshot chunks over existing
Bitcoin connections
([peer processing, lines 3956–3983](../src/net_processing.cpp#L3956-L3983)).
Gate receipt ingestion reads recent and archival snapshot inventories
([inventory adapter, lines 56–68](../contrib/sharepool/hash_gate_inventory.py#L56-L68),
[113](../contrib/sharepool/hash_gate_inventory.py#L113),
[194](../contrib/sharepool/hash_gate_inventory.py#L194)).
The cadence change does not add a deployed standalone live-template or
incremental-share gossip protocol.

Existing mitigation: transfers and ingestion are bounded; missing bytes or
exhausted local capacity remain unavailable/pending rather than proving that a
block is invalid. Native archive admission refuses exhausted storage
([store, lines 679–682](../src/sharepool/hash_store.cpp#L679-L682)).
Gate cold rollover and the native snapshot archive are separate storage systems.
A settlement hash authenticates supplied bytes but does not replace historical
data needed for validation, payout history, reorgs and recovery.

Next gate: measure actual replicated traffic and independently changing
templates over realistic links, including delayed/withheld data and recovery.
Define archival provisioning and authenticated retrieval before describing
settlement as permission to prune all underlying evidence.

## Safeguards already implemented

- Exact-job signatures, native transaction validation and exact payout checks.
- Issuer-bound dispatch capabilities; strict freshness for every new dispatch.
- Immutable issued-job cutoff, with later acknowledgements available to later jobs.
- Withdrawal failure latch and retry; ownership and reentrancy checks.
- Bounded deterministic batching, durable receipts and branch-aware recovery.
- Peer admission fairness, bounded ingestion and native script-validation worker.
- Missing-data and local-exhaustion outcomes distinct from consensus invalidity.

These are implemented protections with existing test evidence. They should not
be presented as missing features, nor as proof of sustained deployed operation.
Mainnet remains disabled at the audited revision.
