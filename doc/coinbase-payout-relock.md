# Experimental coinbase payout relock

This proposal adds a one-time, 1,000-block maturity period to outputs created
by an early coinbase spend. It is based on `v29.4.1.knots20260508` and leaves
activation unscheduled on every network by default. Regtest can enable the
rule with `-testactivationheight=coinbaserelock@HEIGHT`.

## Motivation and limits

The intended incentive is to discourage custodial pool payout transactions
and encourage paying participants directly in the block's coinbase. An
operator who receives a coinbase and redistributes it early would create
payout outputs that recipients cannot spend for another 1,000 blocks.

**This rule cannot identify a pool operator.** It applies equally when a solo
miner or a miner paid directly in the coinbase spends that output early.
Direct coinbase payment removes one intermediate transaction; it does not
exempt the miner's subsequent early spend from this rule. Merchants receiving
such a spend would also receive relocked outputs. This proposal does not
establish that the incentive will reduce pool participation.

An operator can avoid the second lock by waiting until the coinbase reaches
age 1,000, or can pay miners using separate, already-liquid funds. Ownership
changes or internal/off-chain transfers are not observable by this rule.
Fees are not payout outputs: they join the block's coinbase and follow the
ordinary coinbase rules. The rule therefore restricts an on-chain transaction
shape, rather than proving the provenance or beneficial ownership of value.

## Consensus rule

Let `C` be a coinbase output's creation height, `S` the block height of its
spending transaction, and `A` the configured activation height.

1. Existing coinbase maturity remains `S - C >= 100`.
2. For a non-coinbase transaction in a block at `S >= A`, if **any** input is
   an original coinbase output and `100 <= S - C < 1000`, mark **every
   spendable output** of that transaction as a relocked coinbase payout.
3. A marked output created at `S` can be spent in block `H` only when
   `H - S >= 1000`. This is a fresh 1,000-block period after the payout, not
   the remaining time until the original coinbase reaches age 1,000.
4. Spending a marked ordinary output after it matures does not propagate the
   marker. Only original coinbase inputs can trigger rule 2.

For example, a coinbase created at height 10,000 can first be spent at
10,100. If spent at 10,200, its resulting outputs can first be spent at
11,200. If the original coinbase is instead first spent at 11,000, it does
not trigger the second maturity period.

A transaction combining an early coinbase with ordinary inputs marks all of
its outputs, including change and value supplied by other inputs. This
conservative rule avoids inventing an input-to-output value allocation.
Untouched outputs in the same wallet or at the same address are unaffected.

The coinbase subsidy, fee calculation, scripts, and 100-block coinbase
maturity are unchanged. Pre-activation payout transactions do not acquire
the marker retroactively. Coinbase outputs created before activation do
qualify if first spent within the age window after activation.

## Validation, mempool, mining, and wallet

The payout marker is derived before inputs are consumed and stored in the
new outputs' `Coin` metadata. `Consensus::CheckTxInputs` enforces maturity
when accepting transactions and when connecting blocks, including a child
spend in the same block. The RPC policy override cannot bypass this check.

The mempool evaluates the next block's height. It derives a pending payout's
marker from its direct coinbase inputs at that height, including temporary
package outputs. This avoids stale metadata when a pending parent's input
passes from age 999 to 1,000. Activation and reorganization cleanup remove
children that have become premature, and mining checks payout maturity
before selecting a transaction.

Spendable balances and coin selection exclude immature payout outputs;
`getbalances` reports these funds in the `immature` balance. An
explicitly selected immature payout input is rejected. `listunspent` reports
the affected output as unspendable, and `gettxout` includes:

- `coinbase_relocked`: whether this ordinary output received the marker;
- `coinbase_relock_height`: earliest spending-block height, for a marked
  confirmed output only.

The flag remains true after maturity until the output is spent. It indicates
which rule governs the output; the height determines whether it is presently
spendable. A mempool payout has no confirmed unlock height yet.

## Persistent state and compatibility

Unmarked `Coin` and undo records retain their existing bytes. Marked records
set bit 32 in the height/coinbase metadata VARINT, which is decoded as a
`uint64_t` by this implementation. Legacy readers decode a `uint32_t` and
reject an overflow rather than silently discarding the marker. Unknown
metadata bits, or simultaneous coinbase and payout markers, are rejected.

Undo records, interrupted-flush replay, and coin statistics reconstruction
retain or rederive the marker. UTXO commitments preserve historical unmarked
encodings and include a disjoint escape for marked outputs. Existing
assumeutxo commitments therefore remain unchanged before activation.
Snapshot metadata remains version 2; a snapshot containing marked coins
requires the extended Coin reader. Older software rejects its coin data.

Use a fresh regtest data directory when changing activation height.
Rebuilding chainstate alone is not a supported migration procedure because
existing undo data and indexes were produced under the previous rules.
Old software does not enforce the new validation rules and cannot read
marked coin records. A public
deployment requires an agreed activation mechanism, ecosystem review, and
an explicit upgrade/recovery procedure; this draft does not select a public
activation height or modify a running node.

## Tests

`feature_coinbase_relock.py` exercises the original maturity boundary,
activation with a populated mempool, the 999/1,000 trigger boundary, the
fresh payout's 999/1,000 boundary, mixed inputs, package and external block
rejection, no second-generation propagation, reorgs, restart, chainstate
reindex, and full reindex. The wallet test checks receiving-wallet balances,
coin selection, and spending at maturity.

Unit tests check metadata round trips, legacy encoding
compatibility, rejection by the old width-limited decoder, undo,
clear/reset, persistent coin storage, and UTXO commitment separation.
Updated fuzz sources were syntax-checked; a fuzz campaign was not run.
