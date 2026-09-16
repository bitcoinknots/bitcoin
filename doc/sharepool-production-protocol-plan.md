# Production accounting decisions and executable model

**Decision update, 2026-09-13:** separate pool rewards and a TIDES-style window are
selected. See the [v6 native experiment](sharepool-tides-accounting.md).
Payout scripts are recipients, not exclusive identities: v6 requires neither
proof of spending-key control nor a global pool-membership registry. A miner may
direct new work to another pool; old work keeps its original pool and recipient.
The membership locking and registration proposals below are superseded, as is
the confirmed-parent-only payout cutoff. They remain here as historical model
assumptions, not current requirements.
The experiment below is preserved with its original assumptions and results;
its largest-remainder allocation and confirmed-parent cutoff are not the newly
selected TIDES implementation.

This is a **proposal and finite executable model**, not a new consensus profile.
It follows the [v5 experiment](sharepool-confirmed-ledger.md). The model changes
neither native validation nor public-network activation. Its default assumption
is that **each pool funds its own miners from the blocks it finds**. One global
reward pool is an alternative contract, not an implementation optimization.

The immediate engineering fixes do not resolve the contract decisions below.
In particular, a locally accepted share, a confirmed rolling-window entitlement,
and a fixed number of owed satoshis are three different things.

## Stable accounting scope, tied to payout scripts

Changing a template tag must not create a new accounting identity. Address text
is first decoded into its exact canonical `scriptPubKey`; text formatting,
worker names, template tags and coordinator keys are not identity inputs.

Proposed records are:

| Record | Committed information and rule |
|---|---|
| Pool scope | Domain-separated hash of the chain ID and the pool's permanent anchor payout script. A display name and replacement coordinator key do not change it. |
| Member identity | Exact miner payout script, with its proof of control and registered signing/delegation policy. |
| Membership | The native-chain-confirmed assignment of that member identity to one pool scope. |
| Job | Exact template, contributor identity, accounting scope, membership-state reference and snapshot authorization. |
| Work | Exact authorized job, valid share proof, original payout script and accounting scope. These accounting fields cannot change later. |

The winning job's contributor must be a registered member of its declared scope.
Every admitted proof must satisfy the membership applicable to its original job.
The block's required payout window comes from that scope in the actual native
parent state. Thus the same registered payout script cannot select a fresh
arbitrary pool ID to escape its existing scope's payment rules. This requires
both stable scope derivation **and** membership validation; hashing an anchor
script alone does not close the loophole.

Proof of control must actually authorize the payout script. The current
independent owner public key is not, by itself, proof that its holder controls
an unrelated payout script. Production needs a specified, domain-separated
registration and delegation proof, including script types, signature rules,
revocation heights and replay protection. Registration must not let an attacker
lock someone else's address into an unwanted pool. The model assumes an already
authorized registration; it does not implement these cryptographic checks.

This is address accountability under the user's single-address identity
assumption. It does not identify physical ASICs or prove that separate signing
identities belong to separate people. Distinct exact templates prove distinct
authorized jobs, not independent transaction-selection decisions.

## Membership changes and abandoned pools

Key rotation within the existing authorized signing policy must retain the
accounting identity. Replacing a coordinator or display name also retains it.
Old proofs always retain their original payout script and funding scope.

An unrestricted membership switch recreates the escape: every member can leave
pool A for pool B while A's work remains unpaid. The conservative model therefore
rejects changing an existing identity's scope. That closes relabeling in the
model, but **permanent membership locking is not proposed as a complete product**.
A production release needs an explicit exit and shutdown contract.

Possible contracts, requiring a deliberate choice, include:

1. **Funded close:** a pool stops promising new work, settles the old contract,
   then releases members at a confirmed height. A predetermined reserve or bond
   can fund a monetary close only after the contract defines an amount owed.
   Rolling weights presently do not specify a fixed satoshi debt, so multiplying
   them by an expected reward is a new economic promise, not exact settlement.
2. **Affected-owner release:** the holders of the outstanding entitlements
   authorize their treatment before a close or migration. Unanimous release can
   be blocked by an unavailable owner; a majority vote would confiscate the
   minority's rights unless that authority was part of the original contract.
3. **Explicit rolling participation without an eventual-payment guarantee:** a
   member can leave, keeps its old window position, and receives later rewards
   if its former pool continues finding blocks. This matches the nature of an
   ordinary rolling pool, but deliberately does not guarantee that an abandoned
   pool funds every share. It must not be described as solving that guarantee.

No validation rule can make an offline pool perform future work. An independent
pool's nonexistent future rewards cannot fund a promised payment. Requiring
another pool to pay instead would change the selected funding arrangement.
Neither the model nor the current native code silently makes that change.

## Admission promises and deterministic carry

Use explicit receipt states:

- **Received/provisional:** validated and durably retained locally, but not yet
  part of the canonical admitted record. A receipt states its policy, exact
  proof, job and data references; it must not promise an unconditional payout.
- **Confirmed admission:** a native block anchors the proof and its immutable
  accounting fields. It is then subject to the agreed payment contract and
  native-chain reorganization rules.
- **Rolling eligible / outside window:** membership in a reward window changes
  as additional work is admitted. Leaving a rolling window is an agreed contract
  transition, not proof that the share has ever earned a reward.
- **Rewarded:** identify the particular confirmed blocks and amounts. A rolling
  share can be rewarded by several blocks; a recent proof tombstone is not a
  substitute for this record.

The actual native parent fixes payouts. A new block can anchor an admission,
but that admission affects only a later block's payout. Its own winning proof
cannot be inserted into the job that it solved; under this cutoff it requires
a later admission and a still later payout opportunity. Jobs refresh by creating
new commitments; solved headers and old authorizations remain immutable.

Carry already-confirmed work in canonical order without silently deleting it.
For new admissions, reserve the complete proof/template dependency budget before
an ACK, and select a deterministic prefix of the agreed eligible queue. An
on-chain queue has an objective order; two private queues can disagree about
their contents even when both sort by hash. Local reception time is not a
consensus timestamp or a proof of worldwide delivery.

No deterministic ordering rule forces a miner to anchor every undisclosed or
censored receipt. To promise service before confirmation requires a specified
mechanism, such as a funded reservation with an objectively verifiable release
condition, not just a stronger label on an ACK. PoW-priced admission and relay
fees can discourage flooding; neither guarantees inclusion during a partition or
against indefinite block-producer censorship. A finite admission window also
cannot guarantee acceptance under unbounded valid arrivals. The native v5
unanchored-origin age limit still exists; the model below deliberately has no
expiry and reports remaining backlog rather than hiding its loss.

## Fixed capacity cannot guarantee unlimited perpetual obligations

Consider a full state containing credits for pools that never find another
block. If unrelated pools must not fund them and confirmed credits must not be
deleted, every later admission requiring additional space must wait. Repeating
this state for more time does not free a byte. The model includes this exact
counterexample, including continuing blocks from an unrelated live pool.

Consequently these four guarantees cannot coexist without another mechanism:

- a fixed global byte bound;
- unlimited permissionless admission;
- permanent exact retention of every admitted obligation;
- independently funded pools that can stop indefinitely.

Raising 4 MiB delays saturation. Compacting weights by address can help ordinary
load, but an unlimited number of addresses/pools still consumes unlimited state,
even without attributing multiple addresses to a single operator. Each pool's
rolling history also needs ordered work to recover window boundaries; arbitrary
aggregation loses that information.

Production choices must specify what gives:

| Choice | What it does and does not provide |
|---|---|
| Bounded active state with funded reservations and backpressure | Makes resource accounting explicit; full capacity still refuses or defers new guaranteed admissions. Permissionless entry does not mean immediate unlimited entry. Perpetual reservations require a funding/lifetime policy. |
| Growing authenticated historical state with bounded blocks | Allows persistent obligations to outlive the working set; needs a real retrieval, indexing, archival-funding and initial-sync design. A small hash does not bound the data it authenticates. |
| Explicit rolling entitlements | Work falls outside the current reward window by the agreed rule; some valid shares can receive no reward. An abandoned pool's last window can still remain forever, and difficulty increases may need older history again. |
| One global rolling window | Removes independently abandoned reward scopes, but shares each participating block's reward across all pools. Still needs throughput, history and payout-output bounds. This is not selected by this proposal. |

An admission process is sustainable only when long-run admitted arrival work
fits the service and storage budgets, with enough burst capacity for the desired
service objective. No prefix scheduler can repair a sustained overloaded queue.

## Rolling payout contract and regular-pool comparison

The proposed reference is a per-pool rolling work window. It pays the same work
from multiple found blocks, instead of clearing weights after the first reward.
An independent duplicate-admission index prevents submitting the same proof
twice without prohibiting that legitimate reuse.

This changes v5's contract: a confirmed v5 weight remains pending until selected
for one settlement, whereas rolling work can leave its window **without ever
being paid**. The model includes a concrete example of that difference. A rolling
profile must therefore be selected explicitly; it cannot quietly convert
existing v5 credits into expiring window positions. Use a fresh regtest profile
for development. Any eventual migration needs a separately specified treatment
of all prior confirmed credits, including native-fork rollback, before activation.

OCEAN's TIDES describes a window of eight current network-difficulty units,
preserved share order, and a cutoff at the work issued to the winning miner.
Shares can participate in multiple rewards, and older history can become relevant
again after a difficulty increase. That is a useful direct-coinbase reference;
our confirmed-parent cutoff has additional admission delay.
[Primary specification](https://ocean.xyz/docs/tides).

Before implementing a new native profile, specify:

1. **Window order and units:** committed admission height and proof ID within
   the chosen objective queue; exact target-derived integer work, not elapsed
   submission time or an inferred physical hashrate cap. The model clips the
   oldest boundary share to the remaining window work. That is a stated model
   rule, not a claim of byte-for-byte equivalence with TIDES.
2. **Difficulty changes:** the window uses the winning block's native work
   requirement. Rising difficulty can bring older shares back into the window;
   permanently pruning the previous suffix would produce wrong payouts.
3. **Initial and empty windows:** an incomplete window divides by available
   work. With no admitted work, direct payout to the winner is an explicit
   illustrative model assumption. It is measured separately and is not an
   established unbiased production rule.
4. **Exact output allocation:** subsidy plus validated fees, deterministic
   integer-satoshi rounding, equal scripts aggregated, and explicit maximum
   output count/weight. Every required output must fit the native coinbase.
   Dust and below-one-satoshi fractions need a contract. Carrying satoshi balances
   changes state and funding; dropping fractions changes individual earnings.
   Neither can be hidden behind an implementation limit.
5. **Reorganization and availability:** restore the fork's admitted history,
   membership state and eligibility, then recompute all exact payouts. Missing
   bytes stay pending; they cannot establish an alternative local fork choice.

The block still commits the **flat hash of the complete canonical snapshot** in
`m_mm_rhs`; full data use the existing P2P connections. The model does not propose
a settlement Merkle root or in-block evidence. Compression, queues and archived
segments do not remove the obligation to retrieve and validate the data needed
to reproduce the complete agreed state.

“Same variance” requires the same hashrates, individual share targets, weighted
window, membership history, payout horizon, startup rule and cutoff process.
Blocks are a subset of successful shares from the same hash trials. Sampling
blocks independently from share counts loses that dependence. PPLNS also retains
overlapping history across rewards. Poisson proof-count error alone is not a
measurement of the resulting payout distribution.

## Reproducible finite experiment

The standard-library [model](../contrib/sharepool/production_protocol_model.py)
has three deliberately separate components:

- a script-derived scope and locked-membership example, assuming authorization;
- a bounded one-time credit queue that reproduces abandoned-pool saturation;
- coupled share/block traces, replayed through per-pool rolling windows with
  actual-native-parent admission cutoffs.

The rolling calculation scans backward by work. An independent comparator
calculates forward work-interval overlaps over the same admitted history. A
second, live comparator uses all earlier shares in submission order, modeling
immediate relay and refreshed jobs. It exposes both cutoff delay and admission
ordering differences. Winning work is excluded from its own solved job in every
case. Varying share difficulty uses nested target events on the same underlying
hash marks, preserving the same native block events.

Run from the repository root:

```sh
python3 -B -m unittest discover -s contrib/sharepool -p test_production_protocol_model.py -v
python3 -B contrib/sharepool/production_protocol_model.py --seed 7300 --trials 64 --intervals 64 --base-resolution 128 --output /tmp/sharepool-production-protocol-model-7300.json
```

The recorded run used 64 trials of 38,400 seconds per case. Pool A is 20% of
network hashrate (Alice 6%, Bob 14%); pool B is 80% (Carol 30%, Dave 50%). Initial
network work is 128 easiest-share units and the reward is a fixed 1,000,000
satoshis. The share difficulty and admission budgets are illustrative, **not
production target recommendations**. All cases start empty and include startup;
there is no warmup or claim of a steady-state distribution.
The 32-admission case is an intentionally overloaded model scenario. Native
settlement continues to use its existing byte/resource bounds.

| Case | Native blocks | Accepted proofs | Unanchored at end, summed across trials | Different payouts vs live comparator |
|---|---:|---:|---:|---:|
| Equal share targets, complete available admissions | 4,132 | 524,391 | 6,577 | 3,873 |
| Unequal targets, work weights 1/4/2/4 | 4,132 | 194,474 | 2,490 | 3,800 |
| Equal targets, only 32 admissions per native block | 4,132 | 524,391 | 392,450 | 4,106 |
| Equal targets, native difficulty doubles halfway through | 3,061 | 524,391 | 14,349 | 2,914 |

All **15,457** modeled block payouts agree exactly with the independent
same-admitted-cutoff comparator. **14,693** differ from the live comparator.
The overloaded case's largest individual end backlog is 6,744 proofs. Ordinary
end backlog also includes work waiting for the next block; it is not all a
capacity failure. The retarget case keeps constant physical hashrate, so native
block frequency falls after difficulty doubles.

For Alice, the finite-trial relative standard deviation of total payouts is
22.20% with the confirmed-parent policy versus 23.41% with the live comparator
in the first case; with admission overload it is 25.54% versus 23.41%. These
sample moments show that cutoff and service policy matter. They do not establish
that either policy has lower variance in production or that the variance is
equivalent. The JSON reports every miner, empty-window blocks, means, variance,
zero payouts, accepted/admitted counts, seed and assumptions.

The **18 model tests** cover weighted-window enumeration, exact satoshi
conservation, no cross-pool funding, same-address relabel rejection, immutable
old credits under saturation, deterministic prefix carry, coupled block winners,
late winning work, difficulty changes, cutoff differences and an unpaid share
leaving a rolling window. These tests are
separate from native consensus and networking tests. No node, GPU, ASIC, network
latency, real signatures, storage budget, output-count limit, censorship,
stale-job race, fee process or fork is exercised by this model.

## Next implementation after the selected choices

The engineering evidence supports retaining exact payout verification and
implementing additional accounting in a separately versioned regtest profile.
It does not justify activating it on a public network.

Separate pool funding and TIDES rolling rewards have now been selected. The
[follow-up specification](sharepool-tides-accounting.md) records the accounting
implementation and remaining membership, admission, bootstrap, output and
archive requirements. Implement the new profile with
native state-transition, restart/reorg and adversarial network tests. Only after
those definitions should a production share target be calibrated against
sustained WAN, disk, validation and real miner measurements.
