# Proposed rules for template work budgets and registry-bound payouts

This proposal records the requested rules. **5 TH/s and 600 seconds are examples,
not activated parameters.** The work-budget arithmetic has a test helper and is
used by the toy settlement model. The registry, authenticated job protocol, and
full node consensus integration described here remain to be implemented.

## 1. Bound aggregate credited work per stable template group

For each pool, template group `g`, and agreed accounting window `e`, define:

```text
w_i = floor(2^256 / (approved_share_target_i + 1))
W_g = sum(w_i for each distinct eligible share in group g in window e)
W_g <= maximum_hashes_per_second * window_seconds
```

All records for a group accumulate together, regardless of how many connections,
workers, or job refreshes produced them. No floating-point comparison or rounding
down an over-limit total is permitted. Every share must have a verified proof,
an approved target assigned before work, and a unique identity. A lucky share
earns credit from that assigned target, not its unusually low achieved hash.

An estimated average rate is `W_g / window_seconds`. With the example parameters:

```text
maximum_hashes_per_second = 5,000,000,000,000
window_seconds = 600
per-group budget = 3,000,000,000,000,000 work units
```

Equality passes; one extra work unit fails. This is an average over the window,
not a limit at every instant. The estimate concerns disclosed credited work,
not an exact count of hashes physically attempted. Share luck creates sampling
variation; intentionally withheld proofs can conceal excess hashing. Passing
this check cannot prove that hardware stayed below 5 TH/s.

Other groups' work does not change a group's allowance. There is no fixed minimum
group count: a single contributing group can pass when its eligible work fits
the budget. Empty input is insufficient evidence, not verified zero hashrate or
a payable settlement. The initial budget scope is `(pool_id, stable_group_id)`.
A group participating in two pools is checked separately in each. Enforcing a
global cross-pool budget would require additional identity aggregation rules;
this proposal does not require a global registry.

If a pool has 100 TH/s of *credited average work*, a 5 TH/s budget requires at
least twenty nonempty groups for that window. This arithmetic does not establish
twenty independently controlled miners.

## 2. Specify a common window; do not use local arrival time for validity

Share arrival times and difficulty can support a local dashboard estimate.
However, peers receive the same share at different times. A miner's header time
or a coordinator's signed receipt time does not prove when the work happened.
A signature authenticates a statement, including a timestamp; it does not make
that statement an independently verified clock.

For consensus, the ruleset must select a common window and objective eligibility
cutoff before any work is counted. An implementable candidate is a ledger/chain
epoch identified by agreed checkpoints with a protocol-defined nominal duration.
That creates a deterministic *work quota per epoch*. Converting the quota to
TH/s using the nominal duration does not prove the epoch lasted that many real
seconds. Base-chain timestamps also have permitted variation and cannot simply
be treated as exact share-submission times.

The arithmetic helper accepts an externally established positive window duration;
it does not establish that duration. Never let the candidate coordinator choose
a longer window just to make a concentrated batch fit. Do not divide by the
interval between the first and last submitted shares: that interval is
submission-dependent, can be zero, and is easy to distort by delaying shares.

Eligible proof records need a common ledger position/cutoff rule, not just a
timestamp. Freeze that eligible prefix for the job; later accepted contributions
belong to a later eligible snapshot under the rules. Rolling windows, epoch
boundaries, minimum sample sizes, late-share treatment, and initial accounting
state still require agreed parameters. A fixed epoch allows bursts within or across its
boundaries; it does not imply a sliding-window or instantaneous cap.

Do not silently discard over-budget shares to make the evidence pass. That turns
the cap into an accounting filter and hides the behavior it was intended to
measure. An over-budget snapshot fails the proposed check. Gateways can manage
future work assignments, but a cap cannot prevent someone from physically
hashing, and changing an ordinary job must not reset accumulated group work.

## 3. Distinguish registered miners, stable groups, and exact jobs

Use three identifiers with different purposes:

| Identifier | Proposed meaning |
| --- | --- |
| `miner_key` | Registered key authorizing jobs and a payout destination. It identifies a key, not a person or ASIC. |
| `group_id` / stable coinbase tag | The accounting bucket for a template family throughout the window. |
| `job_id` | A commitment to one approved mining job and its precisely permitted mutations. |

Different registered miner keys must use different registered coinbase tags;
several workers mining jobs with the same stable tag contribute to one bucket.
Bind the tag and owner key to the actual mined coinbase or an unambiguous mined
commitment. A label or signature supplied beside otherwise identical work cannot
change its ownership or group. Reject reattribution of an existing share.

For the first registry design, each miner key has one active stable group per
window, and each group has one owner key. Ordinary nonce/extranonce/time changes,
transaction refreshes, reconnects, and new payout/snapshot commitments create new
jobs in the same group. Register distinct logical miners/tags when a deployment
intentionally divides work among multiple groups. The protocol must define
registration activation and key rotation so a replacement key cannot reset
credited history mid-window. This one-group-per-key rule is a proposed registry
choice, not a claim that one physical machine equals one key.

Under the user's definition, different tags make templates different even when
the selected non-coinbase transactions match. No rule here forces artificial
transaction differences. One operator can still create many keys and tags, and
multiple devices can share a key. These checks cannot prove independent miners,
DATUM execution, or exclusive use of a template by particular hardware.

Every credited share must be work on an eligible reward-mining job. Validate the
template, chain context, payout requirements, approved target, and predecessor
settlement that the share actually commits to. Separate balanced evidence jobs
do not establish distribution of reward mining. The current synthetic fixtures
still have this limitation.

## 4. Make the local registry a replica of a specific committed state

The payout coinbase must match each node's independently reconstructed copy of
the **registry version named by the winning job**, rather than whatever entries
the node has most recently received. Proposed registry entries record:

```text
network, ruleset, pool, registry version, predecessor registry root
miner public key, stable group/tag, payout script
registration activation, permitted key/payout updates
authenticated job registrations and approved target assignments
```

The same accepted state-transition history must produce the same canonical root.
Unknown history is a retrieval/validation dependency. Invalid signatures,
unauthorized payout changes, conflicting ownership, duplicate registrations,
and incorrect predecessor references are invalid state transitions under the
eventual registry rules. Registration gossip by itself does not decide which
conflicting history is canonical. A root and sequence number alone cannot allow
the coordinator to substitute any convenient registry.

The protocol still needs to choose how that history is accepted and anchored:
for example, transitions committed by the preceding base-chain state, or an
explicit share-ledger consensus with defined fork choice and base-chain anchors.
A coordinator-only sequencer can order signed registrations, but its censorship,
omission, and conflicting-history powers remain assumptions until those rules
are defined. Do not treat majority peer responses as a consensus certificate.

An eventual versioned settlement manifest should bind at least:

```text
network_id, ruleset_id, pool_id, base_parent
registry_root, eligible_ledger_checkpoint, window_rule_id, window_id
share_snapshot_root, share_count, predecessor_settlement_root
payout_rule_id, payout_outputs_commitment
```

The ruleset fixes the rate budget, window semantics, and payout rules;
the miner/coordinator cannot substitute easier parameters. Put a namespaced
commitment to this manifest in `m_mm_rhs` before hashing. It selects the exact
states to validate without depending on the finished job's own hash. A job ID
may commit to the manifest afterward; the manifest cannot recursively include
that same final job ID.

## 5. Derive and check the winning coinbase locally

For the job's committed registry and eligible-share snapshot, each node:

1. Validates the registry's accepted predecessor history, registrations, ownership,
   and payout destinations; verifies all share eligibility and attribution.
2. Recomputes the work budget for each pool/group from the complete
   protocol-eligible share set.
3. Computes payments to the registered payout scripts using the published
   reward allocation, pool/finder fees, rounding, and output-order rules.
   The available reward must reflect this candidate's valid subsidy and actual
   transaction fees. Distinct transaction selections can change those fees.
4. Compares the candidate coinbase's required payment outputs, including amounts
   and scripts, with the result. Rejects omitted, diverted, excessive, or
   unauthorized extra payments. Handles required witness/other commitments under
   explicit output rules; do not confuse permissible coinbase nonce/tag changes
   with permission to change payment outputs.
5. Checks the resulting coinbase is bound to the actual block Merkle root and
   verifies all ordinary base-chain rules.

Registration alone does not earn a payout; eligible credited work determines
entitlement under the payout rule. The registry authorizes recipients, while the
snapshot and reward rule determine amounts. A correct snapshot root beside an
incorrect coinbase is insufficient.

The coordinator supplies the proposal; it cannot override the nodes' recomputed
result. The coinbase and manifest are fixed before hashing. The winning proof
cannot be added afterward to the very snapshot its hash commits to. Specify
finder rewards in advance and any later accounting transition explicitly.

For example, node A may already know registry version 43 while node B has only
version 41. If the winning job validly references version 42, both validate and
use version 42. B retrieves its missing history. A retains version 42 instead of
replacing the winning job's recipient with an update activated in version 43.
The accepted-history and job-eligibility rules determine whether version 42 is
still allowed; an old root is not automatically eligible forever.

## 6. Disagreement and implementation boundary

Missing referenced registry/share data leaves a job or block pending. A wrong
peer response is discarded without poisoning block validity. Authentic committed
data that fails the agreed rules invalidates the block on enforcing nodes.
Different personal registries, blacklists, receipt times, or rate limits cannot
be independent consensus inputs without risking a chain split. Local admission
preferences can still decide which jobs a miner accepts.

Both registry and settlement state must follow branch-specific history. Reorgs
undo departed registrations and provisional payouts before applying the selected
branch. Re-delivering a block must not pay it twice.

The current settlement simulator tests a toy payout mapping and fixed snapshot,
not this authenticated registry. The new work-budget helper checks exact integer
arithmetic over supplied credited records, not timing, signatures, complete
disclosure, physical hashrate, or a live node. This proposal does not activate
new Knots validity rules or establish trustless total-pool work disclosure.

## Primary references

- [Knots work calculation at the requested tag](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/chain.cpp): basis for target-derived integer work credit.
- [DATUM Gateway template/share requirements](https://github.com/OCEAN-xyz/datum_gateway#templateshare-requirements-for-pooled-mining): existing requirements bind submitted work to pool-provided generation outputs, tags, identifiers, and targets. They do not implement this proposal.
- [Stratum V2 mining protocol](https://stratumprotocol.org/specification/05-mining-protocol/): jobs, per-channel targets, and distinct device search spaces. Search-space assignment does not authenticate independent ownership.
