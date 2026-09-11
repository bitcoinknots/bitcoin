### Extended coinbase maturity (temporary softfork)

Coinbase outputs created while this deployment is active can only be spent
once buried under 6480 blocks (45 days of ten-minute blocks),
instead of the usual 100. The rule applies to every block from the first one
whose parent's median-time-past reaches the deployment's start time, and
expires together with RDTS: from the first block whose parent's
median-time-past reaches the RDTS expiry (2027-09-01 00:00 UTC on mainnet)
every coinbase output is again spendable after 100 confirmations, including
those created during the window that had not yet reached 6480.

Only outputs created inside the window are affected. A coinbase output created
before activation keeps the 100-block rule throughout, so activating the
deployment cannot lock an output that was already spendable. The 100-block
rule continues to apply to every coinbase output at all times.

The start time is not yet scheduled on mainnet or testnet4 in this release
(see `src/kernel/chainparams.cpp`); the deployment does nothing until it is.

Miners: block rewards mined inside the window cannot be spent for 6480 blocks
(or until the RDTS expiry, whichever comes first). Pools that pay their miners
directly from coinbase outputs pass this delay through to those miners. A
non-upgraded miner that spends its own reward at 100 confirmations produces a
block that upgraded nodes reject.

Wallet: rewards subject to the rule are reported as immature (in
`getbalances` `immature`, `listtransactions` category `immature` and the
GUI) until they can be spent, and are not selected for spending before then,
so the wallet never creates a transaction the network would reject.

`getdeploymentinfo` reports the deployment as `extended_coinbase_maturity`, a
`flagday` entry with `start_time`, `expiry_time` (the RDTS expiry), `active`
(for the next block) and, once the queried chain's median-time-past has reached
the start time, `height`, the activation height on that chain. It is omitted
on chains where the deployment is not scheduled. `getblocktemplate` lists
`extended_coinbase_maturity` in `rules` while the deployment is active; no
client-side support is required.

On regtest the deployment is scheduled with `-extendedcoinbasematurity=<time>`,
which requires `-rdtsexpiry` and must precede it.
