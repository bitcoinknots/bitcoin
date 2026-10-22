# Draft: next-block-gated TRUC sibling eviction

This document records the original design. The updated draft also includes a
miner-configuration guard and a separately enabled shared-anchor experiment.
See [current scope and testing](truc-sibling-research.md) for the effective rules,
validation results and remaining work; the original scope below is historical.

This is an **opt-in policy experiment**, disabled by default. It is separate
from changing the default TRUC mode. Enable with both `-mempooltruc=enforce`
and `-trucsiblingnextblock=1`. Neither consensus nor transaction formats change.

## Question for review

Can a narrowly scoped exception to the absolute replacement fee requirement
improve recovery without allowing unacceptable relay/validation abuse?
An existing child can carry more total fees than a much smaller sibling even
when the smaller sibling has a better child and parent-package feerate.
Normal sibling eviction requires the replacement to cover those old fees.

This draft implements a concrete, deliberately restrictive comparison point.
It does not claim that pinning is eliminated, that fees reserve bandwidth, or
that the exception is ready to enable on production nodes.

## Eligibility

The normal replacement checks run first. Only a failure of `PaysForRBF` can
enter the exception. Existing individual-feerate, standardness, minimum fee,
signature, topology, and finalization checks remain in place.

- Explicit experimental option and enforced TRUC mode; replacement not disabled.
- Single-transaction acceptance, no package submission or policy bypass flags.
- Exactly one policy sibling removed; no directly conflicting input, additional
  conflict, or descendant eviction.
- Exactly one shared unconfirmed v3 parent, with no ancestor of its own.
- Existing 10,000-vB parent and 1,000-vB child limits remain enforced.
- The replacement child must be strictly smaller than the old child.
- At least 25% improvement in both actual child and parent-package feerates.
- No fee deltas on the parent, old child, or replacement; the candidate pays
  at least its minimum relay fee plus incremental relay fee. This floor is NOT
  the usual incremental *absolute fee increase* and does not prove cumulative
  relay costs are covered.
- Neither the old parent nor child is selected in the before projection.
- Both parent and replacement child are selected in the after projection.

All failures fall back to the original rejection. Ordinary RBF and package RBF
are unchanged. The exception can only remove the old child; it cannot close a
channel, transfer value, or authorize an otherwise invalid spend.

## Meaning of next block in this prototype

Two read-only projections use the same locked mempool snapshot, before and
after substituting the candidate. Selection repeatedly chooses the best
remaining ancestor package by actual fee / sigop-adjusted vsize, updates the
remaining dependencies, and checks weight and sigops. Txid breaks equal-rate
ties. Local fee deltas are not counted.

The capacity follows the next height/parent MTP: 4,000,000 weight normally,
800,000 during RDTS. Reserve 4,000 weight and 400 sigop cost for block overhead.
It does NOT reproduce arbitrary miner choices, priority space, blockmintxfee,
blockmaxsize, private transactions, or other nodes' mempools. It is a fee-based
policy projection, not a promise of inclusion or a complete block template.

The research selector uses an ordered package index and updates only affected
descendants. It is bounded to 10,000 entries and 2,000,000 work
steps across both views, and refuses the exception on exhaustion. It uses no
historical fee estimate, stale cached threshold, or temporary mempool mutation.
Runtime and lock contention still need adversarial assessment before deployment;
these caps are experimental resource bounds, not new mempool admission limits.

## Cases that should not use the exception

Empty/underfull mempool, already-selected parent or child, candidate outside
the projection, insufficient feerate improvement, same-size or growing child,
more than one conflict, direct double spend, unconfirmed grandparents, oversized
child, local fee-delta manipulation, and exhausted projection budget.

## Unresolved review requirements

1. Repeated grow/shrink cycles alternating ordinary RBF and this exception;
   a 1,000-vB cap bounds one child, not total lifetime relay traffic.
2. Congestion manipulation and a moving next-block boundary. "One-shot" is not
   a permanent per-parent counter or a guarantee that the exception fires once.
3. Miner revenue effects, including displaced transactions and partial blocks.
4. CPU/memory/lock bounds under adversarial submissions, including invalid scripts.
5. Different mempool views, mixed-policy propagation, reconnect/restart and reorgs.
6. Real CLN/LND commitment/HTLC and Ark exit fixtures. The supplied synthetic
   transactions do not establish an end-to-end recovery or theft result.
7. Whether the 25% factor, strict shrinking, parent exclusion, projection resource
   limits, and explicit opt-in are the right initial constraints.

## Testing

**Deeper testing of the original draft found material limitations:** shared-anchor conflicts remain
excluded, the fee-only projection can disagree with the default miner, and its
work budget can be exhausted at roughly 1,755 entries in the stress fixture.
See [the detailed test report](truc-sibling-nextblock-testing.md) before drawing
conclusions about L2 safety or deployment readiness.
This research branch optimizes the selector without broadening eligibility;
see [research results](truc-sibling-research.md) for current performance coverage.

`mempool_truc_nextblock.py` tests empty/congested cases, feature-disabled behavior,
direct conflict exclusion, fee deltas, native and core policy, repeated shrinking,
ordinary funded replacement, and accept-mode isolation. Its `--rdts` variant
uses the reduced block-weight limit. Existing TRUC/RBF/package suites should
also pass with the feature disabled.

Initial isolated regtest results: both new functional variants passed, as did
`mempool_truc.py`, `mempool_package_rbf.py`, `mempool_package_limits.py`, and
`feature_rbf.py`. All four `rbf_tests` unit cases passed. These results validate
the synthetic policy cases above, not production safety or adversarial CPU bounds.

## Prior work

- [BIP 431: TRUC](https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki)
- [One-shot replace-by-feerate](https://petertodd.org/2024/one-shot-replace-by-fee-rate)
- [Mempool incentive compatibility](https://delvingbitcoin.org/t/mempool-incentive-compatibility/553)

This draft adapts existing next-block-gating ideas to a restricted sibling-only
experiment. It does not claim to introduce replace-by-feerate or next-block gating.
