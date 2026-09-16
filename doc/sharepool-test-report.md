# Share-pool settlement and disagreement test report

Updated and tested on 2026-09-11 against a checkout based on Knots tag
`v29.4.1.knots20260508` (`8c85b1585dac23f964e2dd32045624de7f02aa58`).

**The settlement model behaves deterministically for the tested inputs, including
fork rollback and delayed data. Stock Knots accepts the commitment without
checking settlement. These earlier tests did not implement mandatory native
settlement validation.** The later [native regtest profile](sharepool-native-enforcement.md)
adds actual enforcement for its separately specified snapshot and payout rules.

This report describes the earlier fixed-snapshot model. The
[coordinator-signed ledger baseline](sharepool-live-protocol.md) adds authenticated
registries, reward-job shares, automatic snapshot updates, and tail settlement.
The current permissionless reference is documented separately in
[Proof-of-work share ledger](sharepool-pow-ledger.md). It is not wired into the
baseline gateway or HTTP replication flow, and it introduces no native Knots
consensus changes. The measurements and tables below retain their earlier scope.

The linked unit-test log contains the combined regression suite. The payout-script
grouping change updates both earlier models: tags remain template/miner
attribution, while work for all tags sharing a payout script accumulates in one
allowance. The model and unit results below were rerun with that change; the
stock-node results are from the separate prior run of the unchanged
header-commitment smoke test.

## What was executed

| Layer | Recorded result | What it establishes |
| --- | --- | --- |
| Fixed-snapshot/accounting unit-test subset | 65 passing tests, including 50 seeded delivery permutations | Hash/tag/payout-script binding, shared-destination budgets, Merkle inclusions, validation states, payout checks, rollback, and replay within the stated model. |
| Settlement model scenarios | 12 passing scenarios | Reproducible node disagreement, shared-address accounting, data recovery, chain selection, and examples exposing unresolved protocol rules. |
| Two actual stock Knots processes, prior run | 6 passing regtest cases | Header commitment behavior, actual block acceptance, equal-work branches, and explicit local rejection/reconsideration. |

Recorded outputs: [unit tests](../contrib/sharepool/results/unit-tests.txt),
[model scenarios](../contrib/sharepool/results/simulation.json), and
[actual-node run](../contrib/sharepool/results/regtest.json).

The actual nodes both reported `/Satoshi:29.4.1/Knots:20260508/`. Binary provenance
was checked by version self-report, not a reproducible build. The script used
temporary datadirs, loopback RPC, manual block relay, no P2P, and no wallets.
Both processes stopped and their temporary datadirs were removed. This was not a
P2P propagation, live-miner, or network-performance test.

## How settlement works in the model

1. Supporting share proofs bind a pool, parent block, height, approved share
   target, a stable tag, and a payout script inside the coinbase. The script is
   the actual zero-value supporting output, not a destination inferred from the
   tag. The coinbase transaction binds to the header Merkle root, and the header
   must satisfy the approved share
   target. Header `nBits` retains the base-chain target.
2. A coordinator selects an immutable snapshot. Canonically sorted records and
   metadata produce a domain-separated, count-bound Merkle root. Metadata binds
   network, pool, parent, height, proposal sequence, predecessor settlement root,
   the model's fixed reward, and the payout-script budget grouping/version.
3. Before solving the candidate header, the builder puts that root in `m_mm_rhs`
   and constructs the deterministic payout coinbase. Changing either afterward
   requires checking PoW again. A changed hash is not guaranteed to fail an easy
   target; the actual-node mutation test deliberately chose one that failed.
4. Each model node obtains the referenced snapshot and checks its root, context,
   share proofs, duplicates, absolute work budgets, and exact coinbase allocation.
   The cap is `payout_script_work <= cap_hashes_per_second * window_seconds` for
   every distinct script, aggregating all tags that pay it. There is no relative
   percentage limit or minimum recipient/template count. Empty
   evidence remains insufficient to calculate the model's work-based payouts.
   Credit is `floor(2^256 / (approved_target + 1))` per accepted share.
5. Valid blocks compete by cumulative valid chainwork. The node derives its
   provisional payout balances and consumed shares from the selected branch.
   A reorg removes the old branch's entries and applies the new branch's entries.

The model uses a toy reward of 100,003 units and deterministic largest-remainder
rounding, with payout-script-byte order breaking ties. Recipient scripts are synthetic;
the balances are expected outputs, not matured or spendable balances. This is
not a sidechain withdrawal or custody implementation.

The model's default budget is 2 work units per payout script: rate 1 times nominal
duration 2. Each default share contributes 2 units, so a second share for the
same script exceeds this intentionally tiny illustrative budget even under a
different tag. These are not production parameters or measured submission times. The separate arithmetic
tests exercise 5 TH/s over 600 seconds, yielding exactly 3,000,000,000,000,000
work units. One recipient containing all pool work passes if under budget.

Unlike the fixed-snapshot checker, the continuous reference commits
`budget_basis = "payout-script"` and `inflight_policy = "credit-and-stop"`. It
uses authenticated historical registry destinations, aggregates all associated
miner IDs/tags per pool and origin epoch, and retains accepted in-flight excess
for payment. Its new-job restriction is relative to the proposed prefix; an
honest gateway requests its current verified prefix, but eligible older-prefix
jobs can still win or be newly signed. Neither model measures a hard upper bound
on physical hashing. Updating a registry payout destination does not reassign
previous claims or their counted work.

The fixtures deliberately avoid a circular commitment: supporting proofs are
separate zero-payout evidence jobs, and the reward candidate commits to them.
That makes the mechanics testable but leaves a central eligibility requirement
unproved: those proofs must eventually demonstrate work on the actual eligible
reward-mining jobs, including their previously issued settlement commitments.

## What happens when nodes disagree

| Disagreement | Tested behavior | Consequence |
| --- | --- | --- |
| Same records arrive in different orders | Canonical encoding produces the same root and payouts. | No consensus disagreement. |
| One node has additional or newer local shares | The winning job's issued snapshot is used. | Local inventory alone does not invalidate the block. |
| Snapshot or parent has not arrived | Block and dependent descendants remain pending and contribute no active-chain settlement. | Validation resumes when correct data arrives; indefinite withholding can stall a node. |
| A peer supplies bytes that do not match the committed root, or an unbound coinbase variant | Reject that response without poisoning the header's validity. | Another peer can supply the authentic data. |
| Matching-root snapshot contains a duplicate, forged tag, replay, work above its absolute budget, or wrong context | Reject the block under the model rules and exclude descendants. | Additional work on that ancestry does not cure the violation. |
| Correct snapshot accompanies diverted or incorrectly rounded payouts | Reject the candidate even though its PoW and snapshot root are correct. | Commitment alone does not authorize incorrect payment. |
| Two valid blocks extend the same parent with equal work | Nodes can retain different first-seen tips. | A branch with more valid cumulative work reunites nodes; old provisional settlement is undone. |
| A budget bucket has 4 work units; one node permits 2 and another 4 | The strict node rejects that branch while the relaxed node can follow it and its descendants. | A split can persist while work extends rejected ancestry. |
| A branch valid under both absolute budgets becomes heaviest | Both nodes adopt it. | Different rules do not guarantee permanent divergence; acceptance overlap and chainwork matter. |
| Operator explicitly invalidates an ancestor in stock Knots | That node rejects descendants with `bad-prevblk`, even when the other node extends the branch. | Explicit reconsideration restored convergence in the actual-node test. |

Nodes do not vote on whether a root is acceptable. A root differing from a local
proposal can still be valid. Conflicting proposals at the same pool, parent, and
sequence are recorded in the model, but it has no coordinator signatures and
cannot establish authenticated equivocation. A production invalidity rule must
define which conflicts matter without depending on which message arrived first.

Missing data and invalid data must remain separate. The model's pending state is
not an implemented Knots consensus state. A production implementation needs
retrieval, retention, synchronization, and activation rules so nodes can obtain
the same validation inputs. Local timeouts cannot establish that a committed
snapshot violates the content rules.

## Inclusion and template checks

The tests verify inclusion proofs for every snapshot leaf and reject altered
leaves, indexes, counts, proof lengths, and malformed odd-leaf duplication.
Context changes alter the root. Duplicate share identities remain detectable
even when records are relabeled. Reordering the same records preserves the root.

Share tests reject a tag declaration that differs from the coinbase, a coinbase
not bound to the header, wrong parent/height/pool, altered approved target,
unsupported fields, and insufficient PoW. Nonce and extranonce/job refreshes
do not reset work under the same payout script. Different tags naming that script
share its allowance, while still distinguishing their templates. Distinct tags
can use identical non-coinbase transaction selections. Fixtures contain only a coinbase;
arbitrary transaction sets and general coinbase Merkle branches are not tested.

Separate arithmetic and proof tests exercise unequal approved share targets.
The integrated model uses a common approved share target and one pool. A pool
cannot gain extra credit merely because a submitted share happens to have an
especially low hash. Targets must be assigned before work, but authenticated
historical target assignment is not implemented here.

## Protocol gaps exposed by the tests

**A valid inclusion proof does not establish complete disclosure.** In the
recorded omission scenario, one tag's synthetic destination has 2
committed work units, equal to its budget. The observed inventory contains ten
extra shares for that same destination, making its
observed work 22 units. The committed sample still passes the current model.
Thus the check enforces a cap over disclosed eligible records, not yet over
all verified work assigned to that payout destination. Rejecting based on each node's private
inventory would instead make validity depend on message arrival. A common
eligible-share ledger, window, cutoff, and omission policy must be specified.

**Evidence work is not yet tied to actual reward mining.** An operator could
mine balanced supporting evidence jobs while concentrating reward mining
elsewhere. The fixture checks do not exclude this. Real job eligibility, payout
binding, and predecessor snapshots need to be validated for the supporting
shares, not only for the eventual settlement candidate.

**Work budgets require an agreed window and have sampling effects.** One or
more payout scripts can meet the budget; there is no percentage or fixed minimum
recipient/template requirement.
An empty snapshot still cannot derive work-based payouts. Random share arrivals
can exceed a budget without a matching change in actual hashrate. Work shares
are probabilistic evidence, not a measurement of every attempted hash. The
duration used by nodes must be defined by shared rules, not local receipt times
or a coordinator-chosen interval. A nominal epoch quota does not establish
elapsed real time. The work-budget helper checks arithmetic, not these time or
eligibility assumptions.

**Tags bind template attribution, not an independent allowance.** The binding
prevents relabeling an existing proof. All tags sharing a payout script contribute
to its combined work budget. A tagged proof does not establish DATUM execution
or independent control.

**Stock nodes do not validate settlement.** Both actual nodes accepted a tagged
coinbase with a nonzero Merkle commitment without receiving its snapshot, and
also accepted an arbitrary root with no snapshot. Adding the field alone does
not make these rules mandatory. Matching validation logic and an activation
plan are necessary for the proposed enforcing network.

## Robustness fixes and remaining scope

Testing and review found and fixed malformed-wire handling, mutable snapshot
metadata after caching, and an uncommitted coinbase-witness variant that could
poison the cache entry for a valid header. Regression tests now cover recovery
with the authentic payload. Cached snapshot roots are rechecked during validation.

The work-accounting API contains no percentage acceptance predicate. The budget
helper and fixed-snapshot simulator apply absolute payout-script limits. The
grouping update binds snapshot `budget_grouping = "payout-script"` and uses
store format 3; older stores are rejected rather than silently interpreted under
the new grouping rule. Regression tests cover shared-script aggregation, script
binding, ordinary job refreshes, and historical destination retention.

Fifty seeded permutations deliver competing blocks, parents, children, snapshots,
and duplicates in different orders. Once all required data arrives and one
valid branch is heaviest, tips, balances, and consumed shares agree. Save/restore
tests revalidate stored objects and avoid duplicate settlement. These are bounded
model tests, not a proof for every asynchronous execution.

The model does not implement authenticated coordinator/miner messages, P2P
transport, multiple-pool aggregation, full script/UTXO/transaction validation,
reward fees and maturity, hidden XOR-key verification, complete share-history
availability, or pruning. File replacement is used for snapshot persistence;
power-loss durability, concurrent writers, storage corruption, resource exhaustion,
and long-running performance have not been tested. It reconstructs active-branch
accounting rather than exercising a production database with undo records.

## Reproduce

From the repository root:

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/run_settlement_scenarios.py
python3 contrib/sharepool/regtest_commitment_smoke.py --bitcoind /absolute/path/to/bitcoin-knotsd
```

The last command needs a compatible Knots binary and permission to bind loopback
RPC ports. The tested executable was named `bitcoin-knotsd` and reported
`/Satoshi:29.4.1/Knots:20260508/`; its build provenance was not independently verified.
Each runner exits unsuccessfully if an assertion or required operation fails.
See [the experiment README](../contrib/sharepool/README.md) for file roles and
[the protocol draft](sharepool-design.md) for integration decisions still needed.
