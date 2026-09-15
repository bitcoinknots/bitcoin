# Coinbase Curfew

A consensus change that is disabled on every network. A coinbase output created
at or after `curfew_height` may only be spent in a block whose parent's
median-time-past is at least `curfew_seconds` after the median-time-past of the
block that created it. Ordinary 100-block coinbase maturity still applies as
well.

## What changed from the first version, and why

| First version | This version | Why |
|---|---|---|
| Lock measured in blocks (`curfew_depth`, default 25,200) | Lock measured in median-time-past seconds (`curfew_seconds`) | A block count does not deliver the calendar time it is described in. Review measured this chain's recent spacing at 168.8 s per block (blocks 971171-971370), which makes 25,200 blocks about 49 days, not the roughly six months the first version stated. |
| A default of 25,200 blocks | No default; zero disables the rule | A default lock length should not be chosen implicitly in a code change |
| Applied to every coinbase spent after `curfew_height`, including coinbases already mature | Applies only to coinbases created at or after `curfew_height` | Changing the rules for coins that had already become spendable is retroactive. Review of similar proposals also favoured attaching the lock to the creating height. |
| Checked on mempool entry and block connection | Also re-checked when a reorg updates the mempool | A reorg can lower the tip's median-time-past back under a curfew |

## Checks

`IsCoinbaseCurfewLocked(coin, spend_parent, consensus)` is true when the coin
is a coinbase created at or after `curfew_height`, `curfew_seconds` is non-zero,
and `spend_parent`'s median-time-past is below the creating block's
median-time-past plus `curfew_seconds`. It is used:

- in mempool acceptance, with the current tip as `spend_parent`
  (`bad-txns-coinbase-curfew`)
- in `ConnectBlock`, with the block's parent (`bad-txns-coinbase-curfew`)
- when the mempool is updated after a reorg, evicting spends that became locked

Median-time-past only moves forward along one chain, so a coin that has become
spendable stays spendable unless a reorg replaces the blocks in between.

## Regtest

    bitcoind -regtest -curfewheight=<height> -curfewseconds=<n>

## Limitations

Measuring in time fixes the duration. It does not address the main concern
review raised:

- **The lock falls on hashers.** Review measured that pools with real volume pay
  their hashers on-chain within a few blocks of maturity: either in the coinbase
  itself, or in a payout transaction about one block later. An extended lock
  therefore delays hashers' pay at every pool. Only pools with enough capital
  can cover the gap, which favours the largest.
- **It does nothing to a miner who does not need the cash.**
- **Overlapping proposals.** #402, #403, #404, #409 and #410 explore extended
  coinbase maturity in more depth, including time-denominated durations (#403)
  and tranche assignment. This PR should be judged against them.
- **No activation.** No height or duration is set for mainnet, testnet,
  testnet4 or signet.

## Testing

`test/functional/feature_coinbase_curfew.py` mines at 10-minute spacing up to
activation, then at 1-minute spacing. It checks:
- a coinbase created before activation spends after ordinary maturity
- a coinbase created at activation is still rejected after ordinary maturity, both from the mempool and inside a block
- that coinbase stays rejected at every tip whose median-time-past is short of the target
- it is accepted and mined once the target is reached
