# Miner revenue: subsidy versus fees

`getminerrevenue [nblocks]` reports how miners were paid over the most recent
blocks (default 144, at most 2016): how much of the reward came from the block
subsidy, how much from transaction fees, and how much reward miners left
unclaimed.

It exists to ground one question in data: how close a chain is to being secured
by fees alone. It does not change issuance, the subsidy schedule, or anything
else about block validity.

## Output

- `total_subsidy`, `total_fees`, `total_claimed`, `unclaimed`: satoshis over the
  window. `unclaimed` is `total_subsidy + total_fees - total_claimed`.
- `fee_share_pct`: fees as a percentage of subsidy plus fees over the window.
- `per_block_fee_share_pct`: minimum, median and maximum of each block's own fee
  share. A high window average can hide a few blocks with very large fees.
- `blocks_fees_exceed_subsidy`: how many blocks earned more from fees than from
  the subsidy.

Percentages are truncated to two decimal places.

## How it is computed

For each block, the subsidy comes from the consensus schedule
(`GetBlockSubsidy`). Fees are the sum of each non-coinbase transaction's inputs,
read from undo data, minus its outputs, the same method `getblockstats` uses for
`totalfee`. `total_claimed` is the sum of the coinbase outputs.

## Limitations

- Fees need undo data, so the RPC fails if any block in the window is pruned.
- It describes revenue, not security. How much hashrate a given revenue buys
  depends on hardware and energy costs this node cannot see.
- A fee share measured over 2016 blocks says little about fee revenue in a
  period with different demand.
