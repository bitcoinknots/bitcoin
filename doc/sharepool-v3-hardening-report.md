# Hash-only v3 hardening — 12 September 2026

Version 3 binds the owner's signature to the complete snapshot and exact job,
derives share targets from contextual native difficulty, and pays by exact
verified work. Jobs refused by policy or native validation no longer admit offered evidence. New relay turns
and expiry handling improve fairness on existing Bitcoin connections.

This is a fresh-regtest protocol revision. The previous v2 wire format is not
compatible. It remains a draft and does not enable public networks.

## Review disposition

| Concern | Current result |
| --- | --- |
| Easy production share difficulty | Deterministic target scaling and work-weighted payout arithmetic implemented and tested, including compact target boundaries. The 1024 scaling factor still needs operational calibration, especially for small pools. |
| Signatures only attested policy | Fixed: the signature covers the full normalized job, including witness bytes, plus every snapshot field. Physical search fields and the circular commitment are handled explicitly. |
| Rejected jobs retained offered evidence | Fixed for gate authorization: temporary native overlay, staged evidence and one final journal transaction. Explicit snapshot publication is separate. |
| Resource fairness and validation latency | FIFO turns, backpressure-independent expiry and bounded inventory replay implemented. Peer order was already randomized. Full native validation still needs latency isolation and measurements. |
| External job construction | Still open: `getblocktemplate` advertises v3 requirements but a native complete job builder is not implemented. |
| Test gaps | Added native exact-template/witness/context checks, signed invalid-origin transaction cases, full level-four chain verification, scheduler cases, atomic gate rejection and varied-difficulty payouts. Broad production load and independent recovery coverage remain open. |

The earlier claim that native tests only compared encodings was too broad:
existing tests already exercised actual payouts, rejected blocks and competing
native branches. The earlier deterministic peer-order premise was also wrong:
the message loop already shuffles peers. Random order alone did not guarantee
fair service, which is why explicit ready-connection turns were added.

## Verification

- 45 focused C++ tests passed across the hash snapshot, relay, legacy settlement,
  signer and activation suites. Of these, 18 test hash-only consensus and six
  test relay helpers.
- 39 Python tests passed: 26 gate cases and 13 codec/signing/accounting cases.
  Gate cases use RPC doubles; they do not substitute for native validation.
- The 13 existing legacy native rule cases also passed.
- Native rule checks passed for redirected payouts, wrong exact rewards,
  unavailable versus malformed data and subsequent valid block acceptance.
- Native origin/attestation checks passed for GBT version/target metadata,
  non-admitting overlays, changed transactions and witnesses,
  context changes, missing inputs, double spending and script failure. These
  include correctly signed invalid origins so rejection reaches the native
  transaction validator. A valid spend pays the intended coinbase destination.
- Native relay checks passed for inventory updates/replay suppression, four-slot
  scheduling, a waiting fifth peer, disconnect cleanup and malformed inventory.
- Lifecycle tests passed over v1 and encrypted v2 transport: pending-data restart,
  automatic P2P recovery, late work, reindex, competing-branch reorganization and
  `verifychain(4, 0)` on all three nodes.

The [100-miner v3 pipeline](../contrib/sharepool/results/hash-only-v3-100-miners.json)
passed in 605.8 seconds using five native nodes, 100 local gates and fresh
native signing identities. Height 103 paid 100 outputs exactly 5,000,014,950 satoshis
including fees; height 104 paid the late proof and previous winner 2,500,000,000
satoshis each. Already solved commitments stayed unchanged. All temporary owner
keys were removed and nodes stopped.

[Verification metadata](../contrib/sharepool/results/hash-only-v3-verification.json)
records the actual executable and final source hashes. The long run imported its
Python modules before the final compact-target, scalar-bound and copied-signature
guards were added. The final 39 Python cases cover those guards separately; native
consensus already enforced the exact signature. The native functional runs used
the same v3 node executable. This distinction avoids presenting separate runs as
an identical final-source deployment.
No physical miner, GPU, public testnet or mainnet was used in these runs.

## Remaining blockers

The native job builder remains unimplemented.

Native UTXO/script validation can still hold `cs_main`, and pending-block retry
still occupies the network message thread. Moving it to the existing validation
callback scheduler can deadlock; a proper worker lifecycle and measured budgets
are needed. Mandatory coverage of unworked issued jobs can build dependency
chains that reach the depth limit after repeated refreshes. A 16 MiB snapshot
also cannot contain 100 near-4-MB templates: the 100-miner fixture uses small
transaction bodies and is not a production-capacity measurement. Deduplicated
data transfer and snapshot layout need further design. Durable retention,
streaming archive recovery, the signer file's missing explicit checksum and
availability assumptions also remain deployment concerns. The successful tests
do not establish production readiness.
