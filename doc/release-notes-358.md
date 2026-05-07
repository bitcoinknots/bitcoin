### BIP110/RDTS activation change (hardfork)

RDTS no longer activates via versionbits signalling. As part of the hardfork,
RDTS rules are enforced for every block from the BLAKE2b hardfork height
until the parent block's median-time-past reaches 2027-09-01 00:00 UTC,
replacing the prior versionbits schedule, which the chain stall prevented from
ever reaching activation at height 965664. The expiry preserves the previous
schedule's approximately one year of enforcement. It is a fixed date: should
the hardfork happen later than planned, the enforcement window shortens
accordingly.

While the RDTS deployment is active, blocks are additionally limited to
800,000 weight units, roughly 290 to 330 kB of transactions per block on the
current transaction mix. The limit lifts at expiry together with the other
RDTS rules, and `getblocktemplate` reports the reduced limit in
`weightlimit` while it applies. A `-blockreservedweight` above the reduced
limit leaves no room for transactions while it applies; the node warns about
this at startup.

There is no mandatory-signalling window any longer: the proof-of-work change
itself separates this chain from the one continuing under SHA256d, since a
SHA256d block at or above the hardfork height is invalid.

A data directory inherited from a client that was not enforcing the hardfork
can contain such blocks, and normal startup does not re-validate inherited
history. They are corrected automatically at the next startup: the offending
blocks are marked invalid, which truncates that chain to the last block
before the hardfork, and the node then downloads and follows the BLAKE2b
chain from its peers. The rewind disconnects every inherited block from the
hardfork height up, so upgrading long after the hardfork can take some
minutes at startup, during which the node reports "Correcting inherited
chain state". If the block data needed for that rewind has been pruned
(a pruned node keeps at least the most recent 288 blocks, so one upgrading
more than a couple of days after the hardfork will usually have pruned them),
the node refuses to start and offers a rebuild instead, which for a pruned
node means re-downloading the chain. Only this header-derivable rule
is corrected automatically; violations that require block data to detect,
such as the weight limit above, are caught by a chainstate rebuild
(`-reindex-chainstate`) or a full `-reindex`. The invalidated
SHA256d chain is not counted by the "we do not appear to fully agree with our
peers" warning: it is expected to outweigh the BLAKE2b chain and is invalid
by design.

Nodes must be configured with the correct `-blake2b_headline` value, published
at the hardfork. A node started with the wrong value will reject the first
BLAKE2b block until the value is corrected.

There is no forced migration of funds: inputs spending coins created before
the fork remain valid under pre-RDTS script rules (grandfathering). Note such
spends are not relayed by policy and require direct miner submission: the
mempool applies the RDTS rules to every transaction regardless of the age of
the coins it spends, so this node neither relays nor mines them itself, and a
miner has to include them from another source.

`getdeploymentinfo` now reports RDTS as a `flagday` deployment with its
hardfork height and median-time-past expiry, and `getblocktemplate` lists
`reduced_data` in `rules` while the deployment is active. The `reduced_data`
entry's `type` changes from `bip9` to `flagday`, it no longer carries a `bip9`
object, and it is omitted on chains where the deployment is not scheduled, so
scripts reading `deployments.reduced_data.bip9.status` need updating. The
regtest `-vbparams=reduced_data:...` option is gone with the versionbits
deployment.

Test networks: the versionbits RDTS deployment that shipped in Knots 29.3 and
29.4 did lock in and activate on testnet3 (heights 4963392 to 5015807, May to
July 2026). That historical window is not carried over; this release validates
testnet3 as Bitcoin Core does, without it, and no longer treats the bit-4
signalling of that era as an unknown deployment. A testnet3 node that rejected
a block during that window under an earlier Knots release, and is therefore
still on a shorter branch, needs a `-reindex` to rejoin the chain. Testnet4 and
signet saw no such activation.
