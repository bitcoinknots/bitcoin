# Proposed rules for template work budgets and registry-bound payouts

This proposal records the requested rules. **5 TH/s and 600 seconds are examples,
not activated parameters.** The work-budget arithmetic has a test helper and is
used by the toy settlement model. The registry, authenticated jobs, and live update path now have an
[executable reference](sharepool-live-protocol.md). Full node consensus integration
and the production protocol remain outstanding.

The current [permissionless reference](sharepool-pow-ledger.md) selects a PoW
checkpoint history instead of coordinator seals. It measures quotas per
checkpoint-height epoch, admits ancestral jobs within a fixed checkpoint age,
and lets anyone mine empty checkpoints to advance an exhausted epoch. The
nominal seconds below convert an illustrative allowance; they are not a verified
epoch duration. The earlier signed reference remains a separate baseline.

## 1. Aggregate the work budget by registered payout script

For each pool, registered payout script `p`, and agreed origin epoch `e`, define:

```text
w_i = floor(2^256 / (approved_share_target_i + 1))
W_p = sum(w_i for each distinct eligible share assigned to script p in epoch e)
W_p <= maximum_hashes_per_second * window_seconds
budget_basis = "payout-script"
```

The budget key is `(pool_id, origin_epoch, payout_script_bytes)`. The script is
the destination authorized by the registry version committed by each share's job;
it is not the address's display spelling. All miners and tags registered to the
same payout script share one allowance. Extra tags, miner IDs, connections,
workers, or job refreshes do not create additional allowance. No floating-point
comparison or rounding down an over-limit total is permitted. Every share must have a verified proof,
an approved target assigned before work, and a unique identity. A lucky share
earns credit from that assigned target, not its unusually low achieved hash.

An estimated average rate is `W_p / window_seconds`. With the example parameters:

```text
maximum_hashes_per_second = 5,000,000,000,000
window_seconds = 600
per-payout-script budget = 3,000,000,000,000,000 work units
```

Equality meets the budget; one extra work unit exceeds it. The continuous
reference uses the credit-preserving policy explained below, so exceeding the
budget does not itself discard accepted work or invalidate its settlement.
This is an average over the window,
not a limit at every instant. The estimate concerns disclosed credited work,
not an exact count of hashes physically attempted. Share luck creates sampling
variation; intentionally withheld proofs can conceal excess hashing. Passing
this check cannot prove that hardware stayed below 5 TH/s.

Other payout scripts' work does not change this allowance. There is no percentage
rule or fixed minimum number of miners, templates, or payout scripts. One
recipient can meet the budget. The same script participating in two pools is
checked separately in each; this proposal does not impose a global cross-pool
budget. Empty evidence is not measured zero hashrate. The continuous reference
has an explicit finder-payout bootstrap for jobs with no unpaid claims.

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

Do not silently discard over-budget shares to make the evidence appear compliant.
The continuous reference commits `inflight_policy = "credit-and-stop"`: it keeps
accepted in-flight work payable and refuses a new job when that job's verified
prefix has exhausted its payout script's allowance. The honest gateway uses its
latest verified prefix. An older eligible job can still win, and Engine validation
does not impose globally latest-prefix freshness. A strict rejection of excess
credit or blocks would be a separate policy. Changing an ordinary job or paying
a claim must not reset the accumulated work for its original script and epoch.

## 3. Distinguish payout budgets, miner tags, and exact jobs

Use these identifiers for different purposes:

| Identifier | Proposed meaning |
| --- | --- |
| `miner_key` | Registered key authorizing jobs and a payout destination. It identifies a key, not a person or ASIC. |
| `payout_script` | The registered destination whose exact bytes identify the shared work-budget bucket within the pool and origin epoch. |
| Stable coinbase tag | Binds a template to its registered miner and payout history; it does not grant a separate allowance. |
| `job_id` | A commitment to one approved mining job and its precisely permitted mutations. |

Different registered miner keys must use different registered coinbase tags.
Different tags pointing to the same payout script accumulate in the same bucket.
Bind the tag and owner key to the actual mined coinbase or an unambiguous mined
commitment. A label or signature supplied beside otherwise identical work cannot
change its ownership or payout bucket. Reject reattribution of an existing share.

For the first registry design, each miner key has one active stable tag and each
tag has one owner key. Ordinary nonce/extranonce/time changes,
transaction refreshes, reconnects, and new payout/snapshot commitments create new
jobs without moving previously credited work. A claim retains the payout script
from its job's historical registry even after an authorized payout or key update.
New jobs use their own committed registry version. Adding another miner/tag with
the same payout script therefore leaves the shared allowance unchanged.

Under the user's definition, different tags make templates different even when
the selected non-coinbase transactions match. No rule here forces artificial
transaction differences. These checks cannot prove independent miners,
DATUM execution, or exclusive use of a template by particular hardware.

Every credited share must be work on an eligible reward-mining job. Validate the
template, chain context, payout requirements, approved target, and predecessor
settlement that the share actually commits to. Separate balanced evidence jobs
do not establish distribution of reward mining. The earlier synthetic fixtures still have this limitation. The continuous
reference now requires all credited proofs to come from its authenticated
reward-job structure; full production template validation remains outstanding.

## 4. Make the local registry a replica of a specific committed state

The payout coinbase must match each node's independently reconstructed copy of
the **registry version named by the winning job**, rather than whatever entries
the node has most recently received. Proposed registry entries record:

```text
network, ruleset, pool, registry version, predecessor registry root
miner public key, stable coinbase tag, payout script
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

The ruleset fixes `budget_basis = "payout-script"`, the rate budget, window
semantics, and payout rules; the miner/coordinator cannot substitute easier parameters. Put a namespaced
commitment to this manifest in `m_mm_rhs` before hashing. It selects the exact
states to validate without depending on the finished job's own hash. A job ID
may commit to the manifest afterward; the manifest cannot recursively include
that same final job ID.

## 5. Derive and check the winning coinbase locally

For the job's committed registry and eligible-share snapshot, each node:

1. Validates the registry's accepted predecessor history, registrations, ownership,
   and payout destinations; verifies all share eligibility and attribution.
2. Recomputes work for each pool, original payout script, and origin epoch from
   the protocol-eligible share set, aggregating all corresponding tags and miner
   IDs. Applies the declared in-flight policy without moving historical claims.
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

The earlier settlement simulator tests a toy payout mapping and fixed snapshot.
The [continuous reference](sharepool-live-protocol.md) implements authenticated
registries, eligible reward jobs, and delayed-work accounting within its bounded
model, including an explicit credit-preserving in-flight budget policy. The new work-budget helper checks exact integer
arithmetic over supplied credited records, not timing, signatures, complete
disclosure, physical hashrate, or a live node. This proposal does not activate
new Knots validity rules or establish trustless total-pool work disclosure.

## Primary references

- [Knots work calculation at the requested tag](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/chain.cpp): basis for target-derived integer work credit.
- [DATUM Gateway template/share requirements](https://github.com/OCEAN-xyz/datum_gateway#templateshare-requirements-for-pooled-mining): existing requirements bind submitted work to pool-provided generation outputs, tags, identifiers, and targets. They do not implement this proposal.
- [Stratum V2 mining protocol](https://stratumprotocol.org/specification/05-mining-protocol/): jobs, per-channel targets, and distinct device search spaces. Search-space assignment does not authenticate independent ownership.
