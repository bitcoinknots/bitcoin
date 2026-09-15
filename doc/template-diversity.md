# Template diversity

`gettemplatediversity` estimates how many independent block-template builders
produced recent blocks. It exists because the property that matters for
censorship resistance is not who owns hashrate, but how many independent
parties choose which transactions go into blocks. A large farm building its
own templates is one voice. Ten thousand small miners all mining one pool's
template are also one voice.

This is local and advisory. It has no effect on validation, relay, or mining.

## Why not measure farm size?

Proof of work carries no identity. One operator can present as any number of
small miners with different addresses, IPs, tags, and templates, and nothing on
chain or on the wire distinguishes them. Any per-entity cap is defeated by
splitting, which is nearly free. So this tool does not try.

## What it measures

**Structure.** Each block is grouped by how its coinbase and header were built:

- coinbase transaction version, locktime convention, input sequence
- scriptSig push layout after the BIP34 height (binary push lengths; text pushes
  are recorded only as "text", never by content or length)
- witness commitment placement and whether a coinbase witness is present
- payout output types (runs of the same type collapse, so a pool splitting
  payouts across a varying number of recipients keeps one key) and a coarse
  payout-count bucket
- header version top bits, signalled version bits, and whether version rolling
  is in use

Coinbase tags are reported per structure but never used for grouping, since
anyone can write any tag. A structure count is a **lower bound on distinct
template-building software and configurations**, not a count of entities:
unrelated miners running identical software share a structure.

**Selection.** For blocks this node sees connect while synced, it compares the
block with its own mempool: how many transactions that had waited at least 60
seconds, and paid more (alone and with ancestors) than the block's median
included feerate, were left out. A structure whose live samples skip heavily
in at least a quarter but under three quarters of cases is marked
`selection_divergent`, a hint that more than one template builder shares it.
This data exists only for blocks seen live; it is kept in memory for the last
2016 blocks and resets on restart.

## Why it is harder to game than the alternatives

A coinbase tag, an RPC credential, or any on-chain marker costs nothing to
copy, so any rule built on one is defeated by the party it targets. Here, to
look like many independent template makers, a pool has to actually produce
templates that differ in structure and, over time, in transaction selection.
Varying structure alone is cheap, so structure counts can be inflated; varying
selection means actually choosing transactions differently, which is the
decentralization being measured.

## Limitations

- Structure can be deliberately varied, which inflates `distinct_structures`.
  Treat it as a lower bound only when nobody is trying to inflate it.
- Many unrelated miners share popular software, so real diversity can be higher
  than reported.
- Skipped-transaction counts assume this node's mempool resembles what miners
  saw. Propagation delays, differing policy (Knots rejects transactions other
  implementations accept), and full blocks all add noise. The 60-second age
  cutoff and the median-feerate threshold reduce, but do not remove, that noise.
- Callbacks run asynchronously, so a transaction removed from the mempool
  between the block connecting and the callback running is not counted.
- Datacarrier and feerate fields need undo data, so pruned blocks omit them, and
  blocks whose data is pruned entirely are counted in `unavailable_blocks`.
- The analysis reads up to 2016 blocks from disk per call.

## Use by Proof of Datum

The node keeps a rolling count of the structures of the last 2016 connected
blocks, leaving out blocks submitted through its own RPC. Proof of Datum
compares each mining connection's submitted blocks with it; see
`doc/proof-of-datum.md`.

## Usage

    bitcoin-cli gettemplatediversity              # last 144 blocks, summary
    bitcoin-cli gettemplatediversity 2016 true    # last 2016 blocks, with per-block detail
