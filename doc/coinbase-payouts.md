# Coinbase payouts

`getcoinbasepayouts [nblocks]` reports how the most recent blocks (default 144,
at most 2016) paid out their coinbase. It is measurement only. It does not
affect block validity, relay, mining, or which payout scripts are acceptable.

## Output

- `by_output_count`: coinbase value grouped by the number of non-zero-value
  coinbase outputs (`0-1`, `2-9`, `10-49`, `50+`). Pools that pay hashers
  directly in the coinbase show up in the larger groups. Pools that take the
  reward to one script and pay hashers in a later transaction show up in `0-1`.
- `primary_scripts`: blocks grouped by their primary payout script, meaning the
  script of the largest-value coinbase output. Each entry has its block count
  and share, total coinbase value, mean output count, the address where the
  script has one, and the most common coinbase tag.
- `effective_primary_scripts`: the inverse Simpson index over those block
  shares. For example, ten equally common scripts give 10, and one script
  producing every block gives 1.

Percentages are truncated to two decimal places. The `effective_primary_scripts`
and `mean_outputs` values are rounded.

## What this does not tell you

- **A payout script is not an identity.** An operator can use a new script per
  block, which inflates `effective_primary_scripts`. Several operators can pay
  the same script. A coinbase can pay any script, whoever mined the block.
- **Tags are claims.** `top_tag` is whatever text the block's creator wrote in
  the coinbase.
- **Coinbase shape is not who ends up holding the coins.** A single-output
  coinbase followed by a payout transaction a block after maturity reaches
  hashers about as quickly as a many-output coinbase does.

For grouping blocks by how their template was built, rather than by where the
coinbase pays, see `gettemplatediversity`.
