# Measured capacity, share cadence and direct payouts

The [capacity report](../contrib/sharepool/share_difficulty_capacity.py) now combines
native capture evidence with explicit v7 workload scenarios. It reconciles the
actual admitted and peer-verified proof counts, keeps submission service separate
from whole-run throughput, and checks direct coinbase output space. It selects no
production difficulty and cannot return a mainnet-readiness result.

The no-argument command still reproduces the historical v4 report. The new
`--capacity-evidence` mode uses the existing [exact v6/v7 target calculation](../contrib/sharepool/tides_calibration.py):
power-of-two work assignment, compact-target rounding and the easy-target clamp
are included. A live capture is recognized by its `measured_phase` field.

## What the native evidence supports

The [September 14 finite-burst report](../contrib/sharepool/results/production-capacity-gate-burst.json)
consumes the existing [100-miner capture](../contrib/sharepool/results/production-gaps-capacity-100.json).
Its artifact hash is recorded in the derived report. All 900 proofs were offered,
durably acknowledged, admitted and verified by the second native node; eight
blocks settled them, with no final backlog or expiry.

The complete 640.51-second workload achieved **1.405 peer-verified proofs/s**.
Its ingress-only ACK rates were **40.26, 3.80 and 2.62/s** in the three epochs.
The faster first epoch does not describe the later state. Nested RPC durations
are not added to gate durations, and the ingress rate is not substituted for
native admission throughput. Offers stopped while each burst drained, so none
of these rates measures sustainable arrival capacity or a saturation maximum.

For a live capture, the report recomputes every phase counter and rate from the
timestamped proof events. Offers after the fixed cutoff, later ACKs, settlement
and peer verification count only in the completed-run result. The unfulfilled
source schedule, offered-but-unacknowledged queue, acknowledged admission backlog
and peer backlog remain separate. A phase with zero verified admissions remains
valid evidence; the report does not divide by zero or infer zero maximum capacity.
Native and peer block acceptance, the exact payout oracle, final accounting and
cleanup must all reconcile. A finite live experiment still does not certify
long-term queue stability.

The [live 100-miner report](../contrib/sharepool/results/production-capacity-gate-live.json)
recomputes the [continuous-offer capture](../contrib/sharepool/results/production-live-100.json).
During its fixed 120-second phase, the schedule requested 240 proofs at two
requests/s. Only 211 were offered, 205 acknowledged and **168 admitted and
peer-verified**. The remaining 72 scheduled requests reconcile as 29 not yet
produced, six offered but unacknowledged and 37 acknowledged but unadmitted;
there was no peer-only backlog. This workload **did not maintain two requests/s**.

The phase achieved 1.4 verified proofs/s. All 240 eventually settled across eight
native blocks after 158.82 seconds including catch-up and drain, with zero
rejection or acknowledged expiry. That later completion does not erase the
phase backlog. Neither 1.4/s nor the faster drain-inclusive average is a
sustainable rate or an upper capacity bound.

The phase verified at most 40 payout recipients simultaneously; the completed
capture reached 41. Its largest block weighed 22,470 units, with a maximum
coinbase weight of 5,524 units after including the drain. These exact native
checks cover small transaction bodies, not full production block weight.

## Explicit cadence scenario

The example uses **100 equal miners**, a pool expected to find one block per day
(`pool_fraction = 1/144`), one day of observation, and the fixed illustrative
native target `0x17034219`. No value is a live mainnet measurement. The node's
monitored fraction defaults to the entire network; `--monitored-network-fraction`
can narrow that declared workload, but does not change which data consensus
validation requires. Global difficulty implies proof traffic outside one pool.

| Target | Network proofs/s | Expected proofs per example miner/day | Proof-count relative standard deviation |
| --- | ---: | ---: | ---: |
| SHIFT10, unchanged | 2.095 | 12.57 | 28.20% |
| SHIFT12, analytical | 8.381 | 50.29 | 14.10% |
| SHIFT14, analytical | 33.524 | 201.14 | 7.05% |

There is no universal regular-pool submission cadence. The report accepts an
explicit reference interval per equal miner instead of inventing that standard:

| Declared reference interval | Smallest analytical shift meeting it | Resulting network proofs/s | Reference proof-count relative standard deviation/day |
| --- | ---: | ---: | ---: |
| 10 seconds | 20 | 2,145.52 | 1.08% |
| 30 seconds | 18 | 536.38 | 1.86% |
| 60 seconds | 17 | 268.19 | 2.64% |

Power-of-two assignment can exceed the requested rate. For example, the
30-second reference requires 480 network proofs/s at a single global target;
the next supported analytical assignment produces 536.38/s. Its compact proof
fields alone require at least **1.424 GiB/day** across that unique stream.
This uses 32 changing bytes plus a minimum one-byte job index, not the historical
512-byte full proof. Job descriptors, full templates, transactions, snapshot
framing, repeated publication, relay fanout, indexes and recovery are excluded.
It is not an estimated total traffic or disk requirement.

All three reference examples exceed the unchanged
[32,768-proof per-block ceiling](../src/consensus/sharepool_hash.h) even at their
mean network demand: the ceiling allows at most 54.61 admissions/s averaged over
600-second native block intervals, or **4,718,592/day**, before other limits bind.
Both the requested daily flow and this existing ceiling appear in the JSON.
Compact encoding
did not raise that verification-work budget. Under these declared full-network
assumptions, easier difficulty alone cannot deliver all that work before expiry.
A mean below the ceiling would still need burst and dependency headroom.

The report also compares required rates with the observed capture, applying an
explicit default factor of two for engineering headroom. Exceeding that observed
rate means the requested service is **not demonstrated by this capture**; it
does not establish a hardware impossibility or a measured maximum. Passing the
arithmetic screen cannot turn finite workload evidence into production approval.

These percentages describe Poisson **proof counts**, not payout variance.
Overlapping eight-work TIDES windows, pool block luck, admission delays, expiry,
fixed job cutoffs and satoshi rounding require the separate
[paired payout-variance contract](sharepool-variance-contract.md). The report
always leaves payout-variance equivalence unestablished.

## Direct coinbase recipient coverage

The report mirrors the conservative
[native construction reservation](../src/sharepool/mining_budget.h):
`4 × (379 + serialized payout output bytes) + 36` weight units. A P2WPKH payout
costs 31 serialized bytes, and a 34-byte witness-script payout costs 43. Users
can reserve additional non-payout transaction weight explicitly.

With no other transaction weight, the reservation ceilings are **32,245 P2WPKH
recipients** at four million weight units and **6,439** under the contextual
800,000-weight-unit limit. These are conservative construction screens, not
supported pool sizes or exact consensus output-count limits. They leave no
assurance about snapshot/dependency bytes, signature validation, history growth,
or useful transaction capacity.

The example 100-recipient reservation needs 13,952 weight units, but the existing
100-miner capture verified at most **73 simultaneous payout recipients** in one
block. Miner population and demonstrated recipient coverage are different. The separate
[heavy-template follow-up](sharepool-live-capacity-followup.md#one-large-block-with-100-direct-recipients)
subsequently verified 100 simultaneous recipients in one 3,379,600-weight block;
that finite run is not the input to these earlier burst/live reports. The
live report additionally records the maximum recipient count verified before
its fixed cutoff, separately from later draining.

## Reproduce and extend

```sh
python3 -B contrib/sharepool/share_difficulty_capacity.py \
  --capacity-evidence contrib/sharepool/results/production-gaps-capacity-100.json \
  --pool-fraction 0.006944444444444444 --miners 100 \
  --reference-share-seconds 10 30 60 --required-rate-headroom 2 \
  --output contrib/sharepool/results/production-capacity-gate-burst.json
python3 -B -m unittest discover -s contrib/sharepool -p test_share_difficulty_capacity.py -v
```

Use the same command with a live capture path to recompute its fixed-phase
screens. `--non-payout-weight`, `--payout-script-bytes`, `--observation-seconds`
and `--monitored-network-fraction` make resource and sampling assumptions explicit.
The focused tests cover target rounding/clamping, conservation, stale or edited
summary counters, drain exclusion, zero phase completions, recipient boundaries
and the distinction between an arithmetic screen and qualification.

The next supported decision requires a stated share/payout contract, sustained
native admission and peer verification at that load while jobs change, bounded
queues and expiry, and exact payouts at the intended simultaneous recipient
count. This report exposes those gates without silently choosing new consensus
rules.

## Options for the global difficulty bottleneck

The one-day-round, 100-equal-miner, 30-second-share example above is an
**illustrative screen, not a user-selected production contract**. It shows why
sampling and capacity need a joint design decision. Three routes deserve
separate evaluation; none is implemented or selected by this report.

1. **Separate frequent local monitoring shares from consensus-accounted work.**
   A gateway could use a finer local target for connection health and work-rate
   estimates while admitting only proofs meeting the existing consensus target.
   That bounds the globally accounted stream. The extra observations do not
   improve the sampling of consensus-enforced direct payouts: they cannot be
   treated as verified reward weight just because a coordinator observed them.
   This changes the sampling promise unless another settlement design accounts
   for them. It does not by itself meet a regular-pool payout-variance contract.

2. **Commit an explicit per-pool or per-job assigned target.** The exact hashed
   job and its authorization would bind that target before work starts, and
   each accepted proof would receive its verified inverse-probability work
   weight. The existing weighted TIDES boundary would need validation against
   the permitted range of individual proof weights. Signatures authenticate the
   assignment, not the fairness of choosing it. A new rules profile would need
   unbiased eligibility, no retrospective target selection, a minimum work per
   admitted proof and an aggregate permissionless resource policy; otherwise
   easier assignments merely recreate unbounded traffic. It also needs paired
   admission-aware payout analysis. This is a protocol change, not a scheduler
   configuration switch.

3. **Increase verified native capacity and only then consider raising limits.**
   Faster and more compact processing must be measured with sustained arrivals,
   changing real transaction sets, simultaneous payout recipients and continued
   peer verification. Proof-count, dependency, expanded-template, CPU, memory,
   disk and retention budgets must all hold with burst headroom and bounded
   expiry. Raising only the 32,768 count ceiling would change consensus resource
   rules and would not establish that the workload can be processed. Any such
   change needs its own evidence and review before a production target is chosen.
