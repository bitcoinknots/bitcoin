### BIP110/RDTS activation change (hardfork)

RDTS no longer activates via versionbits signalling. As part of the hardfork,
RDTS rules are enforced for every block from the BLAKE2b activation height
until the parent block's median-time-past reaches 2027-09-01 00:00 UTC,
replacing the prior versionbits schedule, which the chain stall prevented from
ever reaching activation at height 965664. The expiry preserves the previous
schedule's approximately one year of enforcement.

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
minutes at startup. If the block data needed for that rewind has been pruned
(a pruned node keeps at least the most recent 288 blocks, so one upgrading
more than a couple of days after the hardfork will usually have pruned them),
the node refuses to start and offers a rebuild instead, which for a pruned
node means re-downloading the chain. Only this header-derivable rule
is corrected automatically; violations that require block data to detect
remain a `-reindex` matter. The invalidated SHA256d chain is not counted by
the "we do not appear to fully agree with our peers" warning: it is expected
to outweigh the BLAKE2b chain and is invalid by design.

Nodes must be configured with the correct `blake2b_headline` value, published
at the hardfork. A node started with the wrong value will reject the first
BLAKE2b block until the value is corrected.

There is no forced migration of funds: inputs spending coins created before
the fork remain valid under pre-RDTS script rules (grandfathering). Note such
spends are not relayed by policy and require direct miner submission.

`getdeploymentinfo` now reports RDTS as a `flagday` deployment with its
activation height and median-time-past expiry, and `getblocktemplate` lists
`reduced_data` in `rules` while the deployment is active.
