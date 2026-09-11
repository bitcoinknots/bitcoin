# Share-pool settlement and disagreement test report

Tested on 2026-09-11 against a checkout based on Knots tag
`v29.4.1.knots20260508` (`8c85b1585dac23f964e2dd32045624de7f02aa58`).

**The settlement model behaves deterministically for the tested inputs, including
fork rollback and delayed data. Stock Knots accepts the commitment without
checking settlement. Mandatory settlement validation remains unimplemented.**

## What was executed

| Layer | Recorded result | What it establishes |
| --- | --- | --- |
| Python unit tests | 48 passing tests, including 50 seeded delivery permutations | Hash/tag binding, work accounting, Merkle inclusions, validation states, payout checks, rollback, and replay within the stated model. |
| Settlement model scenarios | 11 passing scenarios | Reproducible node disagreement, data recovery, chain selection, and examples exposing unresolved protocol rules. |
| Two actual stock Knots processes | 6 passing regtest cases | Header commitment behavior, actual block acceptance, equal-work branches, and explicit local rejection/reconsideration. |

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
   target, and a stable tag inside the coinbase. The coinbase transaction binds
   to the header Merkle root, and the header must satisfy the approved share
   target. Header `nBits` retains the base-chain target.
2. A coordinator selects an immutable snapshot. Canonically sorted records and
   metadata produce a domain-separated, count-bound Merkle root. Metadata binds
   network, pool, parent, height, proposal sequence, predecessor settlement root,
   and the model's fixed reward.
3. Before solving the candidate header, the builder puts that root in `m_mm_rhs`
   and constructs the deterministic payout coinbase. Changing either afterward
   requires checking PoW again. A changed hash is not guaranteed to fail an easy
   target; the actual-node mutation test deliberately chose one that failed.
4. Each model node obtains the referenced snapshot and checks its root, context,
   share proofs, duplicates, work concentration, and exact coinbase allocation.
   The cap is `total_work > 0` and `10 * group_work <= total_work` for every tag.
   Credit is `floor(2^256 / (approved_target + 1))` per accepted share.
5. Valid blocks compete by cumulative valid chainwork. The node derives its
   provisional payout balances and consumed shares from the selected branch.
   A reorg removes the old branch's entries and applies the new branch's entries.

The model uses a toy reward of 100,003 units and deterministic largest-remainder
rounding, with tag-byte order breaking ties. Recipient scripts are synthetic;
the balances are expected outputs, not matured or spendable balances. This is
not a sidechain withdrawal or custody implementation.

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
| Matching-root snapshot contains a duplicate, forged tag, replay, excessive concentration, or wrong context | Reject the block under the model rules and exclude descendants. | Additional work on that ancestry does not cure the violation. |
| Correct snapshot accompanies diverted or incorrectly rounded payouts | Reject the candidate even though its PoW and snapshot root are correct. | Commitment alone does not authorize incorrect payment. |
| Two valid blocks extend the same parent with equal work | Nodes can retain different first-seen tips. | A branch with more valid cumulative work reunites nodes; old provisional settlement is undone. |
| A group has 15.38% of work; one node enforces 10% and another 20% | The strict node rejects that branch while the relaxed node can follow it and its descendants. | A split can persist while work extends rejected ancestry. |
| A branch valid under both the 10% and 20% rules becomes heaviest | Both nodes adopt it. | Different rules do not guarantee permanent divergence; acceptance overlap and chainwork matter. |
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
under the same tag stay in the same concentration group. Distinct tags can use
identical non-coinbase transaction selections. Fixtures contain only a coinbase;
arbitrary transaction sets and general coinbase Merkle branches are not tested.

Separate arithmetic and proof tests exercise unequal approved share targets.
The integrated model uses a common approved share target and one pool. A pool
cannot gain extra credit merely because a submitted share happens to have an
especially low hash. Targets must be assigned before work, but authenticated
historical target assignment is not implemented here.

## Protocol gaps exposed by the tests

**A valid inclusion proof does not establish complete disclosure.** In the
omission scenario, a committed snapshot has ten equally weighted tags, so each
has 10%. The observed inventory contains ten extra shares for one tag, making
that tag 55% of observed work. The committed sample still passes the current
model. Thus the check enforces a cap over disclosed eligible records, not yet
over all verified work of the pool. Rejecting based on each node's private
inventory would instead make validity depend on message arrival. A common
eligible-share ledger, window, cutoff, and omission policy must be specified.

**Evidence work is not yet tied to actual reward mining.** An operator could
mine balanced supporting evidence jobs while concentrating reward mining
elsewhere. The fixture checks do not exclude this. Real job eligibility, payout
binding, and predecessor snapshots need to be validated for the supporting
shares, not only for the eventual settlement candidate.

**A strict per-round cap has bootstrap and sampling effects.** Zero work is
invalid, nine groups cannot pass, and exactly ten groups pass only with equal
credited work. More than ten groups do not guarantee compliance. Random share
arrivals can push a group over the threshold without a matching change in its
underlying hashrate. Work shares are probabilistic evidence, not a measurement
of every attempted hash. A rolling window, activation history, or another
explicit bootstrap design needs evaluation before enforcing this rule.

**Tags cannot establish DATUM execution or independent control.** One operator
can assign many tags and contribute real PoW to each. The binding prevents
relabeling an existing proof; it does not prevent creating new tagged jobs.

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
RPC ports. The tested binary was
`/Users/jeronimolopez/Library/Application Support/m1n3/bin/bitcoin-knotsd`.
Each runner exits unsuccessfully if an assertion or required operation fails.
See [the experiment README](../contrib/sharepool/README.md) for file roles and
[the protocol draft](sharepool-design.md) for integration decisions still needed.
