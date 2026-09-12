# Hash-only v2 test results — 12 September 2026

The hash-only regtest profile successfully settled 100 miners' submitted proofs
in one block across five native enforcing nodes. All 100 local mining gates
validated complete origin templates and authorized their own settlement job.
There was no gate bypass or change to an already solved commitment.

The header commits a flat hash of the complete off-block snapshot. Settlement
proof records are absent from coinbase; its monetary outputs still pay miners
directly. This report does not establish mainnet readiness.

## Measured native pipeline

The [100-miner report](../contrib/sharepool/results/hash-only-100-miners.json)
records fresh native signing identities, distinct funded transaction templates,
real low-difficulty native proofs, P2P snapshot replication, durable gate
admission and exact payouts. This used 100 logical miners, five disposable
regtest nodes and eight CPU hashing threads. It used no GPU, physical miner or
public network. The run took 672.8 seconds including the test wrapper.

| Settlement | Proofs | Direct payout outputs | Reward including verified fees |
| --- | ---: | ---: | ---: |
| Height 103 | 100 | 100 | 5,000,014,950 satoshis |
| Height 104 | 2 | 2 | 5,000,000,000 satoshis |

Late work arrived after the first winning header was frozen. All gates required
a refresh before dispatching further work; the existing solved block remained
unchanged and valid. The next block paid the late proof and the previous winner
2,500,000,000 satoshis each. The last winning proof remains durably pending for
a future eligible settlement. All test keys were removed and nodes stopped.

This is the successful replacement for the version 1 32-proof bottleneck. A
separate baseline run confirmed that all 100 informed v1 gates refused to omit
68 acknowledged proofs. That baseline later failed in its control harness's
winning-origin registration, so it is not reported as a completed pipeline.

## Other verification

- [34 focused native cases](../contrib/sharepool/results/hash-only-native.json)
  cover the new codec/verifier and existing profile, signer and activation
  behavior. They include 100 proofs, exact reward arithmetic, parent state,
  repeat-payment rejection, dependency budgets and known empty commitments.
- [Native payout checks](../contrib/sharepool/results/hash-only-native-rules.json)
  reject redirected payout scripts and incorrect amounts even after recomputing
  the snapshot hash. An unavailable preimage remains pending; delivery of a
  matching but malformed preimage establishes rejection. A valid settlement
  subsequently succeeds.
- Three native nodes pass pending-block restart and automatic P2P recovery,
  late-share settlement, offline chainstate reindex, competing valid branches,
  and reindex after reorganization. Runs assert the actual connection framing
  for both [v1 transport](../contrib/sharepool/results/hash-only-lifecycle.json)
  and [encrypted v2 transport](../contrib/sharepool/results/hash-only-lifecycle-v2-transport.json).
- [25 Python codec/gate cases](../contrib/sharepool/results/hash-only-python.json)
  pass with native RPC doubles. These separately cover the final scalar metadata
  length checks added after the native 100-miner process had started.
- [13 existing native rule cases](../contrib/sharepool/results/hash-only-legacy-regression.json)
  pass against a v2-capable build while using the unchanged v1 profile.

The first reindex run exposed recursive script-queue ownership. Nested origin
validation now executes the same script checks synchronously and does not use
assumevalid. The unchanged lifecycle tests passed after that fix. The final
known-empty-preimage case passed in both native unit and functional checks.

Reports retain the actual binary and source hashes where recorded. The long
100-miner run used an earlier build; subsequent queue and empty-preimage fixes
have separate verification. This is not a claim that every test ran against one
identical final executable. This verification was completed before publication.

## Remaining deployment limits

The [format and gate guide](sharepool-hash-only.md) describes finite snapshot,
dependency and storage budgets. Repeated dependent job refreshes can reach the
depth or byte budget. Version 2 still needs an independently verified streaming
archive export/import workflow and a sustainable retention policy. Hashes cannot
guarantee data availability or establish that undisclosed work never existed.

Independent storage-recovery review remains incomplete. The completed functional
restart/reindex checks above are separate evidence. These tests did not change
the Goldshell configuration or activate settlement rules on mainnet or a public
test network.
