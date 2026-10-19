Rolling coinbase maturity until RDTS expiry
------------------------------------------

On mainnet, rewards mined from height 973440 require a rolling 6480-block
maturity while the spending block's parent median time past is below
`RdtsExpiryTime` (2027-09-01 00:00 UTC). Every reward matures individually;
there is no hold until expiry. At expiry, consensus maturity returns to
100 for all rewards, including rewards mined immediately before expiry.
Until expiry, the rule matches #419 before height 979920 and only restricts
#419's valid-block set from 979920 onward. Testnet4 keeps its original
height-based window; other public networks and default regtest are unchanged.

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
