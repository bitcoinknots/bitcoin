### Extra-work (temporary softfork)

While this deployment is active, a block must meet its header target divided by
an *extra-work factor*: `hash <= target / factor`. The factor is 1 while the
recent hashrate stays within its own trend and rises, up to 8, when it departs
upward from it. It is computed from the parent block's chain only, so the
target the next block must meet is known at the tip: the effective work of the
last 72 blocks divided by their elapsed median-time-past (the fast estimate,
about half a day), over the same measure for the last 4320 blocks (the slow
estimate, about a month), divided by a band of 5/4. Effective work is the work
a block's effective target required, so hashrate that is being held to the
target spacing by the rule is still measured at its true size.

The rule can only require more work than the header does, never less, so every
block that satisfies it is valid for a node that does not enforce it. The
header `nBits` and the difficulty retarget are unchanged: hashrate that grows
with the chain keeps flowing into the header difficulty as before, while a
short-lived burst is absorbed by the factor before it distorts it, and there is
nothing to unwind when the burst leaves.

The rule applies to every block from the first one whose parent's
median-time-past reaches the deployment's start time, and expires together
with RDTS: from the first block whose parent's median-time-past reaches the
RDTS expiry (2027-09-01 00:00 UTC on mainnet), the header target is again the
only proof-of-work requirement.

The start time is not yet scheduled on mainnet or testnet4 in this release
(see `src/kernel/chainparams.cpp`); the deployment does nothing until it is.

Miners: while the rule is active, `getblocktemplate` lists `!extra_work` in
`rules`, its `target` is the effective target (lower than `bits` encodes), and
`extra_work_factor` reports the factor. Pool software must compare hashes
against `target`, not against a target derived from `bits`, and must declare
support for the `extra_work` rule to receive templates; a template consumer
that does not is refused a template instead of building blocks upgraded nodes
reject with `bad-extra-work`. A non-upgraded miner that produces blocks meeting
only the header target while the factor is above 1 produces blocks upgraded
nodes reject.

`getdeploymentinfo` reports the deployment as `extra_work`, a `flagday` entry
with `start_time`, `expiry_time` (the RDTS expiry), `active` (for the next
block) and `factor` (the next block's). It is omitted on chains where the
deployment is not scheduled.

On regtest the deployment is scheduled with `-extrawork=<time>`, which
requires `-rdtsexpiry` and must precede it.
