RDTS continues; rolling 40320-block coinbase maturity
----------------------------------------------------

On mainnet, RDTS (BIP110) no longer expires: `RdtsExpiryTime` was
1819756800 (2027-09-01 00:00 UTC) and is now `INT64_MAX`. Its rules (the
800000-weight block limit, 34-byte output scripts, the OP_RETURN data limit
and the input rules it gates) stay in force at every height from the BLAKE2b
fork. Keeping rules in force is strictly more restrictive than letting them
lapse, so this is a soft fork.

The rolling coinbase maturity continues with RDTS, as #467 made it, at 40320
blocks (~280 days, about the length of a human pregnancy) instead of 6480
(~45 days). Rewards mined from height 973440 each mature 40320 blocks after
the block that mined them; there is no hold until a date and no release. The
rule matches #419's valid-block set before height 979920 (no covered reward
can reach 6480 confirmations sooner) and only restricts it from 979920
onward, where #419 returns covered rewards to 100 and #467 keeps 6480 until
2027-09-01. Testnet4 keeps its original height-based window; other public
networks and default regtest are unchanged.

The existing revalidation marker extends beyond #419's height window, bounded
by parent MTP. A #419 node upgrading after 979920 rewinds to 979919, even
when its tip is already past expiry, to recheck pre-expiry history and cached
descendants. Without a marker, revalidation begins at enforcement minus one.
Pruned nodes missing required history refuse startup before disconnecting
blocks and must reindex. Nodes that ran different experimental rules sharing
the marker must also reindex. Assumeutxo background validation must complete
pre-snapshot coverage.

Mempool admission, reorg filtering, wallet credit, coin selection and GUI
maturity retain #419 behavior: every coinbase needs the configured long
depth for policy and wallet availability, including after consensus expiry.
Policy therefore remains stricter than consensus after expiry. Wallet credit
retains its one-confirmation margin. RPC category help describes applicable
maturity; deployment reporting shows the configured long depth, parent-MTP
expiry and next-block active state. GBT stops advertising the rule at expiry.

Configured regtest accepts `-testcoinbasematuritylong=start:enforce:release[:maturity]`
and `-testcoinbasematuritylongexpiry=time`. The expiry defaults to the configured
RDTS expiry, or INT64_MAX if none, and must match `-rdtsexpiry` when both are set.
