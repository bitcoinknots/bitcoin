Rolling coinbase maturity
-------------------------

On mainnet, coinbase rewards mined at height 979919 or later whose mining
block's parent median time past (MTP) is below the existing RDTS expiry,
1819756800 (1 September 2027, 00:00 UTC), require 25920 blocks of maturity.
This is approximately 180 days at the target block interval, not a wall-clock
waiting period. Each reward matures independently. The first covered reward
can be spent at height 1005839. The new rule does not expire at height 979920.

Covered rewards retain the full 25920-block requirement after RDTS expires.
Rewards mined with parent MTP at or above expiry require 100 blocks instead.
The existing rule for rewards mined from height 973440 remains enforced
through spending height 979919, with its original release at 979920.
Rewards mined before height 979919 are not subject to the new 180-day rule;
after the original release they require 100-block consensus maturity. All
coinbase outputs, including transaction fees, follow these rules.
The expiry boundary is determined on the branch being validated, including
during reorganizations; candidate block timestamps do not determine coverage.

Relay and wallet maturity also return to 100 blocks for rewards mined after
expiry. Pre-activation rewards retain the existing 6480-block relay/wallet
policy; only covered rewards mined from 979919 use the new 25920-block depth.
The wallet retains its existing one-confirmation safety margin for available
credit.

For the rolling phase, `getdeploymentinfo` reports `coinbase_expiry_time`
rather than `height_end`. Before that phase activates, it describes the
historical rule with its original activation, release height and 6480-block
maturity. The active flag refers to the block after the queried block.
The deployment remains active, and `getblocktemplate` continues to advertise
`long_coinbase_maturity`, after expiry because old rewards remain subject to
the rule. Testnet4's existing height-based schedule and other networks are
unchanged. Regtest can opt into rolling maturity with
`-testcoinbasematuritylong=start:enforce:release` and
`-testcoinbasematuritylongexpiry=time`; the rolling depth is `release - start`.
If RDTS is also configured, its expiry must agree.

An upgrade uses a new `rolling_coinbase_maturity_180d_v2` validation marker and
rechecks the new rule from height 979919, including when the tip is past expiry.
The existing `long_coinbase_maturity` marker continues to cover the historical
rule. Nodes without that historical marker still need to validate that history.
Legacy maturity markers cannot certify this stronger rule. Pruned nodes that
lack the block or undo data needed to rewind must reindex and redownload the
missing history. Experimental rules that previously marked now-valid blocks
invalid require a reindex; cached invalidity is not cleared by this framework.
Regtest schedules must not be changed on an existing chainstate without reindexing.

The expectation is a continuation of the 180-day rolling window, with the
option to increase or decrease the window depending on the health of the
network. Such a continuation or adjustment requires a subsequent consensus
change; this implementation does not automatically extend coverage beyond
RDTS expiry.
