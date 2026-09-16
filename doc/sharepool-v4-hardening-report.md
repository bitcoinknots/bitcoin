# Hash-only v4 hardening — 12 September 2026

Version 4 constructs complete jobs with the native mempool and fee calculator,
shares full transaction bodies across overlapping templates, moves pending-block
retry to a dedicated worker, and adds durable gate archives and bounded batch
selection. The block still contains one flat hash of the complete snapshot in
`m_mm_rhs`; templates and shares travel over existing Bitcoin connections.

This is a fresh-regtest revision with incompatible wire and local database
formats. It does not enable mainnet or public testnet. In particular, the
requested regular-pool payout variance and indefinite carry are not implemented
by the current three-height proof-age rule.

## Changes and evidence

| Area | Result |
| --- | --- |
| Job construction | Native preparation selects transactions, reserves coinbase space, derives state and exact subsidy plus fees, and returns an exact signing statement. Finalization verifies the signed job. Gate authorization and the final dispatch check remain required. |
| Overlapping templates | A canonical Wtxid table stores each complete transaction once, with ordered references for every template. Witness variants remain distinct. Native storage also shares transaction bodies and recovers from tested content corruption. |
| Validation work | A bounded worker retries pending blocks, executes prepared script checks outside `cs_main`, rechecks changed chain context and reuses validated origins. Dense dependency graphs no longer repeat validation by recursion depth. Initial P2P processing and some historical paths still hold global locks. |
| Durable receipts | Gate archives rotate and restore with integrity checks. Batches select a deterministic fitting prefix; deferred receipts remain stored. Only confirmed canonical settlement marks payment. Expired unpaid work is reported explicitly. |
| Key files | A checksummed native key/policy record detects corruption. Legacy migration requires the expected policy and public key and does not overwrite an existing destination. |

## Final native verification

The focused native suite passed **59 cases**: 22 hash consensus, five storage,
six relay, five retry worker, seven signer, four activation and ten legacy
settlement cases. The rest of the Bitcoin unit suite was outside this run's
filter. The [native result](../contrib/sharepool/results/hash-only-v4-native-tests.xml)
records every selected case and assertion.

Ten native functional runs passed on the same node executable:

- Exact payout and invalid-settlement rules; full origin transaction, signature
  and witness validation; relay behavior.
- Lifecycle recovery over both v1 and encrypted v2 transport, including missing
  data, restart, reindex, competing forks and level-four chain verification.
- Native job construction with real mempool fees, external signatures, rejected
  altered jobs, and stale-tip finalization.
- Worker script load, RPC/P2P responsiveness, pending-data restart and a competing
  chain arriving during validation.
- HTTP body limits for the explicit regtest profile, with ordinary limits
  preserved; the 13 existing legacy rule cases.
- The complete 100-miner pipeline described below.

[Functional logs](../contrib/sharepool/results/hash-only-v4-functional-tests.txt)
include the commands and actual success records.

The [worker measurement](../contrib/sharepool/results/hash-only-v4-worker.json)
used 64 origins with 100 inputs each and 199 SHA256 operations per input. It
completed 6,400 script checks outside `cs_main` in a 2.110-second pipeline, with
a 0.112-second P2P ping and a maximum 0.002443-second response among 126 sampled
RPCs while active. A separate concurrent-tip stage recorded a context retry and
accepted and extended the competing branch. These are one-host loopback
measurements, not latency guarantees or WAN capacity results.

## 100-miner pipeline

The [run](../contrib/sharepool/results/hash-only-v4-100-miners.json) passed in
515.055 seconds using 100 logical mining gates, five native nodes and eight CPU
proof-search threads. Every miner had a distinct signed initial template and
payout script. All 100 gates validated and durably acknowledged the initial
proofs. Native job construction was used for every first and second settlement
candidate; no gate was bypassed.

Height 103 paid all 100 miners exactly 5,000,014,950 satoshis in total, including
14,950 satoshis of actual transaction fees. Height 104 paid a late proof and the
previous winning proof 2,500,000,000 satoshis each. The previous block's solved
commitment remained unchanged, and the new winner remained durably pending for
later eligible settlement. Existing P2P connections survived the exchanges.
Temporary owner keys were removed and the nodes stopped.

The 100-miner integration uses small, native-valid transactions. Separate wire
and storage fixtures reconstruct 100 overlapping 3.85 MB templates without
duplicating their common transaction body; those fixtures do not establish
native validity of 100 near-limit blocks. Dedicated storage tests verify that
same-txid/different-witness transactions survive restart and that substituted
witness bytes are quarantined and repaired without altering the other variant.

## Python and analytical verification

The final gate and codec run passed 64 tests: 26 gate, 13 archive, ten batch and
builder adapter, and 15 codec cases. A separate run with the native signer
binary explicitly configured passed all 22 signer tests without skips. Seven
capacity-model checks and nine payout-comparison checks passed, for 102 Python
tests in total. The comparison added for the regular-pool variance requirement
has its own reproducible analytical results and tests;
see [difficulty and payout comparison](sharepool-difficulty-capacity.md).

RPC doubles in Python tests exercise gate policy, atomic admission and recovery;
they do not replace the native integration runs. Analytical Poisson and
allocation calculations are models, not observed production mining or payout
measurements.

[Verification metadata](../contrib/sharepool/results/hash-only-v4-verification.json)
records the executable and source hashes. The node and signer remained
unchanged throughout the final functional runs. Only the unit-test executable
was subsequently rebuilt to add witness persistence coverage and correct a
fixture name. No ASIC, GPU, public testnet or mainnet was used.

## Remaining production requirements

The [gap register](sharepool-production-gaps.md) is part of this report. The
remaining work includes a separately authenticated admitted-work history and
payout window, native historical storage and recovery at sustained scale,
production share-rate selection, worst-case WAN/disk/validation measurements,
and data-availability and activation rules. Preserving an acknowledged receipt
on disk does not extend its consensus payment eligibility. Test success must
not be presented as regular-pool variance equivalence or production readiness.
