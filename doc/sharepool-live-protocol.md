# Continuous commitment updates and delayed-work settlement

This is the implemented reference flow for the requested registry, authenticated
reward jobs, continuously refreshed share snapshots, and settlement of work that
arrives after a job's commitment. The implementation uses real synthetic BLAKE2b
proofs and real signatures from the upstream **test-only** secp256k1 library.
It does not activate Knots consensus rules or connect to DATUM/ASIC hardware.

## The timing rule

**A winning header settles the verified prefix committed before hashing. Later
acknowledged shares remain pending and are paid by a later eligible block.**

Every job binds a registry root, signed ledger checkpoint, count-bound Merkle
snapshot, payout allocation, miner identity, approved share target, origin epoch,
parent block, and ruleset. A hash of that manifest occupies `m_mm_rhs`. A share
receipt can only refer to a job whose ledger checkpoint precedes that receipt.
The ledger therefore grows without a circular commitment.

```mermaid
sequenceDiagram
    participant M as Miner gateway
    participant C as Coordinator
    participant N as Other validating replicas
    C->>M: Signed job J0 with ledger L0 and commitment M0
    M->>M: Verify registry, snapshot, payouts and target; authorize J0
    M->>C: Proof S1 on J0
    C->>M: Signed append receipt L1 for S1
    C->>N: Receipt L1 and supporting job/registry data
    M->>M: Verify L1; pause the old assignment
    M->>C: Request job for exactly L1 and selected registry
    C->>M: Replacement job J1 with new Merkle snapshot and commitment M1
    M->>M: Check state has not changed; authorize and activate J1
    Note over M,N: An in-flight solution on J0 can still win
    M->>N: Winning block W0 containing original M0
    N->>N: Settle L0; preserve S1 and W0's own proof as pending claims
    C->>M: Signed seal of old-parent submissions, preserving acknowledged tail
    C->>M: Next-parent job includes pending claims and updated payments
    N->>N: Next winning job pays its included claims once
```

The root never changes inside an existing job. The gateway keeps old authorized
jobs to verify delayed shares and winning solutions. Rewriting a solved header
to contain the latest root is rejected as a change to the authenticated job;
it would also require rechecking PoW. The winning proof itself cannot be a leaf
under its own pre-mining commitment. It becomes a mandatory pending claim derived
from the validated block, even if the coordinator never issues it a receipt.

This accounts for verified proofs. It does not measure every hash attempted
between shares or prove when undisclosed work was performed.

## Implemented pieces

| Component | Behavior |
| --- | --- |
| `signed_registry.py` | Self-authorized registration, unique active keys and tags, stable miner IDs, dual-authorized key rotation, versioned payout scripts, canonical bounded serialization. |
| `live_protocol.py` | Signed reward jobs, exact coinbase/header checks, real share PoW, causal signed receipt prefixes, Merkle snapshots, parent seals, pending claims, deterministic payouts, branch state, replay and save/restore. |
| `job_gateway.py` | Locally verified receipt events trigger fresh jobs; exact registry/checkpoint requests; stale-response detection; retained old jobs; conflict pause; public cursor persistence. |
| `live_protocol_peer.py` | Bounded loopback HTTP transfer of public signed objects between three independent replicas in one process. |

The coordinator creates and signs a proposal. The miner gateway independently
validates its complete contents before signing it and exposing it as active
work. The coordinator key stays with the proposal callback; it is not given to
the gateway. Private keys are not exported in snapshots, peer messages, or saved
gateway cursors. Fixture keys and the Python cryptography are for tests only.

These shares use the same eligible reward-job structure as candidate blocks.
They are no longer separate zero-payout evidence jobs in this implementation.
Their header retains the base-chain target, while the manifest fixes the easier
protocol-approved share target. The reference supports coinbase-only templates,
not arbitrary mempool transactions or full Bitcoin script/UTXO validation.
The ruleset commits `budget_basis = "payout-script"`. Tags bind each template to
its miner and registered payout history; several tags paying the same script
share one work allowance.

## Update races and old-job winners

`Gateway.receive_and_refresh(receipt, callback)` validates an incoming receipt,
advances the verified checkpoint, pauses the previous assignment, and requests a
replacement job. Receipt ancestors and duplicates cannot rewind the cursor.
Invalid receipt signatures leave the current assignment untouched. Missing
dependencies must arrive and be verified before the receipt can advance it.

The callback runs outside the gateway lock. A generation counter binds its
response to the requested parent, ledger root, registry root, miner, and serial.
If another receipt, registry update, active parent change, or job activation
occurs meanwhile, the stale response is discarded without a miner signature.
The caller never activates a proposal containing an older checkpoint merely
because it arrived last. A valid signed receipt fork pauses job issuance until
an anchored branch choice resolves it.

Local freshness controls assignment of future work. It is not a rule that
invalidates a received block merely because a node knows a newer checkpoint.
An old same-parent job can still win; it keeps its original coinbase and root.

The coordinator seals old-parent submissions with a signed receipt identifying
the winning block. Receipt order decides whether an ordinary share was
acknowledged before the seal. Further ordinary submissions for that closed parent
are rejected rather than retroactively acknowledged. This is an explicit
coordinator ordering policy, not a trustworthy physical submission timestamp.
A delayed full block solution remains subject to normal competing-branch
validation through its retained job.

## No double payment and no silent tail deletion

The model maintains separate objects for acknowledged claims, paid proof IDs,
pending proof IDs, and validated block winners. Proof identity comes from the
actual header hash. If a winner also has a share receipt, it is one claim, not
two. All unpaid eligible claims in the selected prefix and inherited winner
claims must appear in the next job's deterministic payout calculation.

An old-root winner does not erase the newer acknowledged ledger suffix. A
compatible suffix is preserved through the parent seal and included in the next
fresh job. Its contributions keep their original miner, payout script, target,
and work epoch. Paying a claim, refreshing a job, or rotating a signing key does
not reset the work counted for its original payout script and epoch. An authorized
payout update does not move past credit into the new destination's bucket.

Registry versions must belong to one compatible history. A later authorized
payout update does not redirect a claim already bound to an earlier script.
Shares from conflicting sibling registry histories cannot be mixed into one
settlement, and a seal cannot commit an unusable conflicting-registry tail.

Paid sets, implicit winner claims, balances, and registry/checkpoint anchors are
branch-specific. Reorgs select the corresponding reconstructed state. Work whose
job parent or registry belongs only to an orphaned branch is retained as archived
evidence; it is not automatically payable on a conflicting branch. This prototype
does not implement a separate stale-work/uncle compensation scheme.

Acknowledgement does not guarantee eventual confirmation: a coordinator can
still withhold unanchored receipts, fail to seal, or stop issuing jobs. Once a
prefix is anchored, successors cannot rewind it or omit its unpaid obligations.
There is no claim that an unknown privately submitted share must have existed
or that every public receipt is instantly available to every node.

## Work budgets and the in-flight policy

The reference ruleset explicitly commits `budget_basis = "payout-script"` and
`inflight_policy = "credit-and-stop"`. It sums work under the exact key
`(pool_id, origin_epoch, payout_script_bytes)`, using the registered destination
committed by each claim's original job. All tags and miner IDs paying that same
script share one allowance. A tag or miner registration is not a fresh budget.

The reference retains credit for valid shares already in flight, reports a budget
violation when they exceed the limit, and rejects new jobs whose committed prefix
has exhausted their payout script's allowance. Other payout scripts can continue
creating valid jobs and settling the recorded claims.
This is the credit-preserving default used while the policy question remains
open; it is not a guarantee that total in-flight work stays below the quota.

Before issuing a job, the gateway checks that the payout script's counted work plus
one approved share's work fits the budget. Existing hardware assignments can
produce several proofs concurrently, so that check cannot reserve every future
hash. Excess work is visible through `Engine.budget_violations()`; it is not
silently deleted to make the audit appear compliant. A strict admission cap
would require the alternative policy of refusing excess credit, with its own
miner-facing terms. Neither policy proves an upper bound on physical hashing.

The restriction is relative to a job's committed prefix. The honest gateway
requests its current verified checkpoint and does not reactivate an older one.
Engine validation still permits an eligible older prefix, including in a new
signed job; it does not establish a globally latest checkpoint. Previously
anchored usage cannot be rewound. Changing the budget grouping does not close
that freshness or disclosure gap.

There is no percentage-of-pool rule or fixed minimum number of recipients or
templates. Epochs are defined by block
height and a nominal configured duration; the code does not treat that duration
as measured wall-clock time. Carried work keeps its original epoch rather than
being relabeled to obtain fresh allowance. A new origin epoch gets its configured
allowance; the current policy does not deduct a previous epoch's excess from it.

## Explicit reference assumptions

The initial empty registry is an anchor for authenticated registrations. Each
block anchors its chosen valid registry history and receipt prefix; authorized
conflicting updates remain possible branches until chain selection resolves
them. Signatures prove authorization, not an independent globally agreed order.

For bootstrap, or any job with no unpaid claims, the fixed model reward goes to
the registered finder. This permits actual reward jobs without fabricated seed
shares. Otherwise the fixed reward of 100,003 units is divided by credited work,
using largest-remainder rounding with payout-script ordering to break ties.
These are explicit laboratory economics, not production subsidy, fee, maturity,
or spendability rules. Production fee/finder policy still needs a specification.

The experiment uses one pool, a fixed base target, public XOR keys, and bounded
history. Height represents chainwork ordering only because every candidate has
the same target. It does not implement a permissionless sharechain, production
peer discovery, pruning, crash-safe database transactions, or hidden-key PoW.
History bounds deliberately stop the experiment instead of pretending it can
operate indefinitely with no pruning design.

## Verification and reproduction

The payout-script aggregation implementation passes **124 unit tests**:
65 fixed-snapshot/accounting regressions, 14 registry tests, 29 authenticated
live-protocol tests, and 16 gateway tests. All **6 real loopback HTTP replication
cases** also pass, with every listener closed and thread joined afterward. These
are three replicas in one process, not three Knots daemons. The fixed-snapshot
runner separately passes **12 scenarios**, including combined budgets for
distinct tags paying the same script.

From the repository root:

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/live_protocol_peer.py --run-smoke
```

The peer script creates three loopback listeners, transfers only public objects,
and closes listeners and joins threads at the end. Missing object dependencies
remain uncredited; the sender must resend after supplying the missing data.
Import is incremental: valid objects before a bad item may already be stored,
but the invalid item is not credited or cached as valid.

Recorded output: [combined unit tests](../contrib/sharepool/results/unit-tests.txt)
and [loopback replication cases](../contrib/sharepool/results/live-peer.json).
Tests include live Merkle inclusion/tampering, forged signed roots, concurrent
refresh responses, old-job winners, sealed-parent races, registry forks, tail
carryover, winner deduplication, origin-epoch budgets, replay, and restoration.
Shared-payout regressions cover combined allowances across miner IDs and tags,
registration and key rotation without fresh same-script credit, paid work and
implicit winners, excess-work reporting, gateway pauses, and rejection of stores
whose rules omit or change the payout-script budget basis.

The previous [fixed-snapshot tests](sharepool-test-report.md) remain as regression
coverage. Actual stock Knots acceptance was tested separately; it still does not
enforce this reference protocol. C++ validation/activation, real mining-protocol
integration, full transaction validation, multi-pool aggregation, and durable
production state remain outstanding. The accounting race is handled for the
verified eligible proofs in this implementation; unknowable final physical work
and universally complete share disclosure cannot be repaired by updating a root.
