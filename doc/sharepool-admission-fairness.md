# V6 admission fairness and cross-pool relay

The revised experimental v6 rules treat each native admission height as a
complete pool-local batch. Numeric proof IDs remain canonical serialization
keys; they no longer give a proof priority at the oldest payout-window boundary.
These rules require a fresh regtest profile. They do not establish a globally
provable reception order or compel a block producer to include unknown work.

## Proportional boundary work

Newer native admission heights enter the pool's eight-network-work window first.
If only part of the oldest included height fits, every recipient in that height
keeps the same fraction of its assigned work. For example, if Alice and Bob have
1 and 2 work units in the boundary height, and only 1 unit fits, their included
weights are exactly 1/3 and 2/3. Swapping their proof IDs changes neither weight.

The history reader must return the complete boundary height, including every
proof for the selected pool. Stopping its scan after finding enough individual
proof work would preserve the original bias even with a proportional payout
loop. Work is aggregated by recipient across full newer heights and the partial
boundary before applying one downward satoshi rounding operation. Recipient
splitting cannot increase the combined rounded payout for a fixed work set.

The independent [arithmetic audit](../contrib/sharepool/tides_admission_audit.py)
and [recorded examples](../contrib/sharepool/results/tides-admission-audit.json)
use exact rational arithmetic. They reproduce the old hash-ranking dependence,
check proof relabeling and permutation invariance, and exercise large arithmetic
that requires more than 512-bit intermediates. They are not native proof or
transaction validation, payout-variance measurements, or profitability models.

## Stable local admission queues

V6 gates pin the `oldest-origin-receipt-v2` local scheduling policy in their
protected journal configuration. The queue orders eligible work by origin
height, then its durable receipt revision. New offers without a receipt follow
all acknowledged work of the same origin height. Only those unacknowledged
offers use numeric proof IDs as a deterministic tie-breaker.

A later disclosed low-ID proof therefore cannot overtake an existing receipt of
the same origin height. Older origins retain priority because their admission
deadline is earlier. The largest prefix fitting the configured byte and
validation budgets is selected; remaining receipts stay in the journal. A gate
refuses an offered job that omits its selected acknowledged prefix. V4/v5 retain
their prior local policy. Old journals cannot silently reopen under the new
scheduling configuration.

This receipt order belongs to one gate. Other gates may have received work in a
different order. A durable ACK is still provisional until a native block admits
the proof; finite capacity and its origin-age deadline can prevent admission.

## Cross-pool admission without cross-pool payment

A v6 gate accepts full, native-validated origins and shares from other pools
through the same bounded provenance, journal, archive and admission queue.
Native responses must name the proof's original pool and recipient. A foreign
origin does not change the gate's own exact pool/key/recipient dispatch policy.

For example, B can admit a valid A proof in B's block while B's reward pays only
B's work. A later A block can reward that old A proof after its original
admission-age deadline, because it was already admitted. A new A job signer or
job recipient cannot redirect that proof's original recipient. This removes a
gate restriction that otherwise prevented small pools from having their work
admitted by other pools before it expired.

`HashMiningGate.sync_native_receipts()` imports proof evidence from bounded
pages of the node's native P2P snapshot inventory. A separate bounded recent
insertion lane advertises new work without waiting for the full historical
archive scan; live and archival work receive alternating turns under one shared
one-message-per-second send allowance. Stored bytes are not a
validity assertion: each newly acknowledged proof is checked against its exact
full origin, ancestry, signature and native proof validation before one durable
write. The scan bounds pages, proof rows and source/dependency bytes, and returns
a cursor that can resume inside a large snapshot. It never imports a partial
proof or replaces its origin pool or payout script.

Callers must preserve the returned cursor between passes. Deferred inputs have
an explicit reason and exact `retry_cursor`; they remain unacknowledged and can
be retried directly. Finishing an inventory cycle resets its cursor so later
insertions below an older hash key are visited on the next pass. This is an
explicit bounded ingestion API, not an automatically running mining service.
An origin without any proof-bearing published snapshot cannot be discovered
through a snapshot inventory alone.

The native recent ring holds 4,096 insertion/repair events independently of
archive size. Its sequence cursor is separate from the canonical, sorted and
deduplicated P2P wire hash list. A reported gap means events were missed; the
archival lane remains necessary for reconciliation. A random store-instance
epoch makes a restart detectable even when its new insertion count already
exceeds an old cursor. Neither a ring nor finite polling throughput guarantees
admission before expiry under unlimited arrivals.

The [native cross-pool test](../test/functional/feature_sharepool_hash_tides_cross_pool.py)
exercises P2P proposal delivery, gate ingestion, protected archive recovery,
native admission by another pool, peer restart and the original pool's later
coinbase payout. The [gate tests](../contrib/sharepool/test_hash_tides_cross_pool.py)
also cover response rebinding, rejection without ACK, byte backpressure,
partial-snapshot cursors, receipt overtaking and unchanged v4/v5 policy.

## Remaining limits of the guarantee

The proportional rule removes hash-rank dependence for the same complete
admitted set. A producer can still omit work, delay eligible work into a later
native admission height, or withhold the bytes needed by other validators. The
audit includes a delayed-admission example where a later height changes the
reward recipient. It does not claim that this timing strategy is profitable
after accounting for all mining work and intervening rewards.

Neither a recipient address nor a coinbase tag proves an exclusive operator
identity. These rules do not prove that miners run DATUM software, enforce
exclusive pool affiliation, or provide a cryptographic proof that every miner's
unpublished work was included. Local byte budgets and retry cursors make work
bounded and failures observable; they do not guarantee fairness or liveness
under unlimited adversarial arrivals.
