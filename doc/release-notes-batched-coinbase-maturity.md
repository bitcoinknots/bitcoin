### Batched extended coinbase maturity (temporary softfork)

Coinbase outputs created while this deployment is active use a longer
maturity that is attached to the creating block, not to the spend:

- 1/6 of window blocks (`(height - start) % 6 == 0`): 2016 confirmations
- 2/6 of window blocks (`% 6` in {1,2}): 4032 confirmations
- 1/2 of window blocks (`% 6` in {3,4,5}): 8064 confirmations

The assignment is by block height, so coinbase transaction size does
not change. There is no extra output and no DATUM/script change.

The window is the same shape as RDTS: first block whose parent MTP
reaches the start time, through the last block whose parent MTP is still
below the RDTS expiry. After expiry, **new** coinbases go back to the
ordinary 100-block maturity. Coinbases created *inside* the window keep
their 2016/8064/26280 lock until they actually mature — expiry does not
unlock them early.

Only outputs created inside the window are affected. A coinbase output
created before activation keeps the 100-block rule throughout, so
activating the deployment cannot lock an output that was already
spendable. The 100-block rule continues to apply to every coinbase
output at all times as a floor.

The start time is not yet scheduled on mainnet or testnet4 in this
release (see `src/kernel/chainparams.cpp`); the deployment does nothing
until it is.

Miners: block rewards mined inside the window cannot be spent until
their assigned tranche matures (or, for coins created after expiry, 100
blocks). Pools that pay their miners directly from coinbase outputs pass
this delay through to those miners. A non-upgraded miner that spends its
own reward at 100 confirmations produces a block that upgraded nodes
reject, if that reward was created in the window.

Wallet: rewards subject to the rule are reported as immature (in
`getbalances` `immature`, `listtransactions` category `immature` and the
GUI) until they can be spent, and are not selected for spending before
then, so the wallet never creates a transaction the network would reject.

`getdeploymentinfo` reports the deployment as `extended_coinbase_maturity`,
a `flagday` entry with `start_time`, `expiry_time` (the RDTS expiry;
after this, *new* coinbases use 100), `active` (for the next block's
*creation* rule) and, once the queried chain's median-time-past has
reached the start time, `height`, the activation height on that chain.
It is omitted on chains where the deployment is not scheduled.
`getblocktemplate` lists `extended_coinbase_maturity` in `rules` while
new coinbases are still being created under the rule; no client-side
support is required.

On regtest the deployment is scheduled with `-extendedcoinbasematurity=<time>`,
which requires `-rdtsexpiry` and must precede it.
